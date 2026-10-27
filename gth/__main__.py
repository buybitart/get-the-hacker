"""GTH command line interface."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path
from .gps import GPSProvider
from .console import Console
from .positioning import estimate_position, estimate_movement
from .runtime import Session, EvidenceLimit, load_config, read_jsonl, rebuild_reports
from .web import start_server

ROOT = Path(__file__).resolve().parent.parent

def default_output():
    android = Path('/sdcard').exists() or 'com.termux' in os.environ.get('PREFIX','') or 'ANDROID_ROOT' in os.environ
    return Path('/sdcard/Download/GTH') if android else ROOT/'reports'



def positive(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError('Use a positive whole number.')
    return number


def show_alert(alert, console=None):
    (console or Console()).event(alert)


def read_sensor(gps, session):
    try:
        fix = gps.get_fix()
        if not isinstance(fix, dict):
            raise ValueError('GPS reply is not valid.')
        return fix
    except Exception as error:
        # GPS is optional. Packet evidence must continue without a fix.
        if not session.record.get('gps_read_error'):
            session.error('gps_read', error)
            session.update(gps_read_error=True)
        return {'status':'unavailable','reason':'No sensor GPS fix.','provider':None,
                'lat':None,'lon':None,'timestamp':None,'accuracy_m':None}


def device_check(interface=None):
    data = {'python':sys.version.split()[0], 'scapy':bool(importlib.util.find_spec('scapy')), 'iw':shutil.which('iw'), 'interface':interface, 'monitor_mode':False, 'radio_verified':False, 'gps_verified':False}
    if interface and data['iw']:
        try:
            proc = subprocess.run(['iw','dev',interface,'info'],capture_output=True,text=True,timeout=3)
            data['monitor_mode'] = proc.returncode == 0 and 'type monitor' in proc.stdout
            data['interface_info'] = proc.stdout.strip() if proc.returncode == 0 else 'Interface check failed.'
        except (OSError,subprocess.TimeoutExpired):
            data['interface_info'] = 'Interface check failed.'
    data['ready_for_capture'] = data['scapy'] and data['monitor_mode']
    return data


def source_info(path,kind):
    path = Path(path)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream,'sha256').hexdigest()
    return {'type':kind,'path':str(path.resolve()),'sha256':digest,'bytes':path.stat().st_size}


def offline(args):
    from .packets import read_pcap, parse_packet, capture_observation
    mode = 'demo' if args.command == 'demo' else 'replay'
    if mode == 'demo':
        from .demo import events as demo_events, policy as demo_policy
        path=None
        config=load_config(args.config) if args.config else demo_policy()
        source={'type':'synthetic','synthetic':True,'description':'Offline Demo. No radio frames are sent.'}
    else:
        path=Path(args.input)
        config=load_config(args.config)
        source=source_info(path,'pcap' if path.suffix.lower() in ('.pcap','.pcapng','.cap') else 'jsonl')
    is_pcap = path is not None and path.suffix.lower() in ('.pcap','.pcapng','.cap')
    session = Session(args.output,mode,config,source,args.max_bytes)
    status, error, code = 'complete',None,0
    ui = Console(defer=True)
    ui.attach(session)
    ui.emit('MODE', 'Synthetic demo' if mode == 'demo' else 'Replay file')
    try:
        if is_pcap:
            for packet in read_pcap(path):
                if session.record['counters']['packets'] >= args.max_packets:
                    status='limited'; break
                session.count('packets')
                try:
                    event = parse_packet(packet)
                except (ValueError,TypeError,IndexError,AttributeError,OverflowError) as exc:
                    session.count('invalid')
                    session.capture_observation(capture_observation(packet, error=exc))
                    continue
                session.capture_observation(capture_observation(packet, event=event))
                if event is None:
                    session.count('ignored'); continue
                for alert in session.accept(event):
                    show_alert(alert, ui)
        else:
            for event in (demo_events() if mode == 'demo' else read_jsonl(path)):
                if session.record['counters']['packets'] >= args.max_packets:
                    status='limited'; break
                session.count('packets')
                for alert in session.accept(event):
                    show_alert(alert, ui)
        if session.record['counters']['events'] == 0:
            status='no_evidence'; code=1
        gaps = session.record['counters']['invalid'] or any(session.engine.stats[k] for k in ('invalid_events','out_of_order','event_evictions'))
        if gaps and status == 'complete':
            status='partial'; code=1
        if status == 'limited':
            code=1
    except KeyboardInterrupt:
        status='interrupted'; code=130
        session.account_pending_packet('interrupted')
    except EvidenceLimit as exc:
        status,error,code='limited',str(exc),1
        session.account_pending_packet('storage_limit')
        session.error('storage_limit',exc)
    except Exception as exc:
        status='error'; error=str(exc); code=1
        session.account_pending_packet('processing_error')
        session.error('replay_read', exc)
    finally:
        try:
            if session.record['storage']['status']!='limit':
                session.telemetry()
        except EvidenceLimit as exc:
            session.error('storage_limit',exc)
            status,error,code='limited',error or str(exc),1
        except (OSError, RuntimeError) as exc:
            session.error('telemetry_write', exc)
            status, error, code = 'error', error or str(exc), 1
        ui.update(session.public_snapshot(),report='SAVING')
        session.finish(status,error)
    ui.emit('REPORT', str(session.directory.resolve()))
    ui.update(session.public_snapshot(),final=True,report='SAVED')
    return code


def monitor(args):
    check = device_check(args.interface)
    ui = Console(defer=True)
    if not check['ready_for_capture']:
        ui.emit('ERROR', 'Live mode needs Scapy and Monitor Mode.', '31')
        if getattr(args, 'automatic', False):
            from .auto import diagnostic
            return diagnostic(args, args.preparation, 'CAPTURE NOT AVAILABLE',
                              'Live mode needs Scapy and Monitor Mode.')
        ui.update({'mode':'unavailable','status':'unavailable'},final=True,report='NOT STARTED')
        return 1
    from scapy.sendrecv import AsyncSniffer
    from .packets import parse_packet, initialize_capture_layers, capture_observation
    session = Session(args.output, 'live', load_config(args.config),
                      {'type':'monitor','interface':args.interface,'check':check}, args.max_bytes)
    ui.attach(session)
    session.update(result='MONITOR MODE', capture_available=False)
    if getattr(args, 'automatic', False):
        session.update(radio_selection=copy.deepcopy(args.preparation.state))
    events = queue.Queue(maxsize=4096)
    received=queue_peak=overflow_drops=drained_after_stop=0
    def receive(packet):
        nonlocal received,queue_peak,overflow_drops
        received+=1
        try:
            events.put_nowait(packet)
            queue_peak=max(queue_peak,events.qsize())
        except queue.Full:
            # The capture callback must not wait for report or storage locks.
            overflow_drops+=1
    def queue_state(stop=False):
        backlog=events.qsize()
        session.update(queue={'received':received,'peak':queue_peak,'capacity':4096,
                              'pending':0 if stop else backlog,'overflow_drops':overflow_drops,
                              'stop_drops':backlog if stop else 0,'drained_after_stop':drained_after_stop})
        with session.lock:
            session.record['counters']['queue_drops']=overflow_drops+(backlog if stop else 0)

    def process_packet(packet):
        nonlocal stage, known_networks
        session.count('packets')
        stage = 'packet_parse'
        try:
            event = parse_packet(packet)
        except (ValueError,TypeError,IndexError,AttributeError,OverflowError) as exc:
            session.count('invalid')
            metadata=capture_observation(packet,error=exc)
            try:
                metadata['timestamp']=float(packet.time)
            except (AttributeError,TypeError,ValueError,OverflowError):
                pass
            session.capture_observation(metadata)
            return
        metadata=capture_observation(packet,event=event)
        try:
            metadata['timestamp']=float(event['timestamp'] if event is not None else packet.time)
        except (AttributeError,KeyError,TypeError,ValueError,OverflowError):
            pass
        stage='capture_observation'
        session.capture_observation(metadata)
        if event is None:
            session.count('ignored')
            return
        event['sensor_gps'] = session.record['sensor_gps']
        stage = 'evidence_write'
        for alert in session.accept(event):
            show_alert(alert, ui)
        if event.get('bssid') in session.networks and event['bssid'] not in known_networks:
            known_networks.add(event['bssid'])
            ui.network(session.networks[event['bssid']])
            if len(known_networks) > 1024:
                known_networks = set(session.networks)

    sniffer = server = None
    start, heartbeat, telemetry_at = time.monotonic(), 0, 0
    status, error, code, stage = 'complete', None, 0, 'decoder_init'
    known_networks = set()
    console_saved = False
    capture_seen_running = False
    try:
        decoder = initialize_capture_layers()
        if isinstance(decoder, dict):
            session.update(decoder=decoder)
            session.log('Decoder ready.', decoder=decoder)
        stage = 'gps_init'
        gps = GPSProvider(args.gps)
        stage = 'capture_init'
        sniffer = AsyncSniffer(iface=args.interface, prn=receive, store=False)
        if args.web:
            stage = 'web_start'
            try:
                server = start_server(session.public_snapshot, args.port, evidence_directory=session.directory, network_provider=session.network_page)
            except OSError:
                if not getattr(args, 'automatic', False):
                    raise
                server = start_server(session.public_snapshot, 0, evidence_directory=session.directory, network_provider=session.network_page)
        if server:
            ui.emit('WEB', f'Mobile view: http://127.0.0.1:{server.server_port}')
        ui.emit('MODE', f'Monitor | {args.interface}')
        selected = session.record.get('radio_selection',{}).get('current_state',{})
        if selected.get('frequency_mhz'):
            ui.emit('RADIO', str(selected['frequency_mhz'])+' MHz | Fixed channel')
        ui.emit('WIDS', 'Capture starts | Ctrl+C stops')
        stage = 'capture_start'
        sniffer.start()
        capture_started=time.monotonic()
        session.update(capture_active=True, capture_available=True)
        while args.duration == 0 or time.monotonic()-start < args.duration:
            stage = 'capture_read'
            if getattr(sniffer, 'exception', None):
                raise sniffer.exception
            if sniffer.running:
                capture_seen_running=True
            else:
                worker=getattr(sniffer,'thread',None)
                if capture_seen_running or (worker is not None and not worker.is_alive()) or time.monotonic()-capture_started>=5:
                    session.update(capture_worker_stop={'timestamp':time.time(),'thread_alive':bool(worker and worker.is_alive()),'pending':events.qsize(),'received':received})
                    raise RuntimeError('Capture worker stopped. Check the adapter.')
            if session.record['counters']['packets'] >= args.max_packets:
                status, code = 'limited', 1
                break
            if time.monotonic() >= heartbeat:
                checkpoint_due = False
                stage = 'gps_read'
                fix = read_sensor(gps, session)
                session.sensor(fix)
                ui.gps(fix)
                if args.ranges:
                    stage = 'range_read'
                    try:
                        ranges = load_json_file(args.ranges)
                        position = estimate_position(ranges)
                        position['measurements'] = ranges
                    except (OSError, ValueError, TypeError):
                        position = {'status':'unsupported','reason':'Range file is not valid.'}
                    session.position(position)
                if time.monotonic() >= telemetry_at:
                    stage = 'telemetry_write'
                    queue_state()
                    row = session.telemetry()
                    ui.emit('RX', f"Packets {row['packets']} | Frames {row['events']} | Skip {row['ignored']}")
                    ui.state('WIDS', 'Frames delayed' if row['health']=='capture_backlog' else 'No fresh frames' if row['health']=='no_fresh_frames' else 'NO WIDS DATA' if row['health'] == 'no_wids_data' else
                             'Frames seen' if row['health'] == 'active' else 'Wait frames',
                             '31' if row['health'] in ('no_wids_data','no_fresh_frames','capture_backlog') else None)
                    telemetry_at = time.monotonic()+5
                    checkpoint_due = True
                ui.update(session.public_snapshot())
                if ui.last_error is not None and not console_saved:
                    session.error('console_write', ui.last_error)
                    session.update(console_available=False)
                    console_saved = True
                if checkpoint_due:
                    stage = 'checkpoint'
                    session.checkpoint(background_report=True)
                heartbeat = time.monotonic()+1
            stage = 'capture_read'
            try:
                packet = events.get(timeout=0.1)
            except queue.Empty:
                continue
            process_packet(packet)
    except KeyboardInterrupt:
        status, code = 'interrupted', 130
        session.account_pending_packet('interrupted')
    except EvidenceLimit as exc:
        status,error,code='limited',str(exc),1
        session.account_pending_packet('storage_limit')
        session.error('storage_limit',exc)
    except Exception as exc:
        status, error, code = 'error', str(exc), 1
        session.account_pending_packet('processing_error')
        session.error(stage, exc)
    finally:
        if sniffer is not None and sniffer.running:
            try:
                sniffer.stop()
            except Exception as exc:
                session.error('capture_stop', exc)
                status, error, code = 'error', error or 'Capture did not stop cleanly.', 1
        # The radio has stopped. Keep already received frames within the same limits.
        if sniffer is None or not sniffer.running:
            while not events.empty() and session.record['counters']['packets'] < args.max_packets and session.record['storage']['status']!='limit':
                try:
                    process_packet(events.get_nowait())
                    drained_after_stop+=1
                except KeyboardInterrupt:
                    session.account_pending_packet('drain_interrupted')
                    break
                except Exception as exc:
                    session.account_pending_packet('drain_error')
                    session.error('queue_drain',exc)
                    status,error,code='limited' if isinstance(exc,EvidenceLimit) else 'error',error or str(exc),1
                    break
        queue_state(stop=True)
        if (session.record['counters']['queue_drops'] or session.record['counters']['invalid'] or session.engine.stats['invalid_events'] or session.engine.stats['out_of_order'] or session.engine.stats['event_evictions']) and status == 'complete':
            status, code = 'partial', 1
        if not session.record['counters']['events'] and status == 'complete':
            status, code = 'no_evidence', 1
        try:
            ui.update(session.public_snapshot(),report='SAVING')
            if ui.last_error is not None and not console_saved:
                session.error('console_write', ui.last_error)
                session.update(console_available=False)
            if getattr(args, 'automatic', False):
                from .auto import restore_radio
                if restore_radio(args.preparation, session):
                    status, error, code = 'error', error or 'Radio restore failed.', 1
            try:
                if session.record['storage']['status']!='limit':
                    session.telemetry()
            except EvidenceLimit as exc:
                session.error('storage_limit',exc)
                status,error,code='limited',error or str(exc),1
            except (OSError, RuntimeError) as exc:
                session.error('telemetry_write', exc)
                status, error, code = 'error', error or str(exc), 1
            ui.update(session.public_snapshot(),report='SAVING')
            session.finish(status,error)
        finally:
            if server:
                server.shutdown()
                server.server_close()
    ui.emit('REPORT', str(session.directory.resolve()))
    ui.update(session.public_snapshot(),final=True,report='SAVED')
    return code


def load_json_file(path):
    p = Path(path)
    if p.stat().st_size > 4*1024*1024:
        raise ValueError('JSON file is too large.')
    return json.loads(p.read_text(encoding='utf-8'))


def load_report_file(path):
    p=Path(path)
    if p.stat().st_size>64*1024*1024:
        raise ValueError('Report is too large. Limit: 64 MiB.')
    with p.open('r',encoding='utf-8') as stream:
        record=json.load(stream,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Report has a non-finite value.')))
    if not isinstance(record,dict):
        raise ValueError('Report must be an object.')
    for key in ('counters','engine','source','config','review','capture_diagnostics','queue'):
        if record.get(key) is not None and not isinstance(record[key],dict):
            raise ValueError('Report field must be an object: '+key)
    for key in ('alerts','capture_timeline','errors','alert_witnesses'):
        if record.get(key) is not None:
            rows=record[key]
            if not isinstance(rows,list) or len(rows)>100000 or any(not isinstance(row,dict) for row in rows):
                raise ValueError('Report rows are not valid: '+key)
    return record


def main():
    if len(sys.argv) == 1:
        from .auto import run_auto
        def stop(signum, frame):
            raise KeyboardInterrupt
        old_term = signal.signal(signal.SIGTERM, stop)
        try:
            return run_auto()
        except KeyboardInterrupt:
            return 130
        except (OSError, ValueError, RuntimeError) as error:
            Console(sys.stderr).emit('Error',str(error),'31')
            return 1
        finally:
            signal.signal(signal.SIGTERM, old_term)
    parser = argparse.ArgumentParser(prog='gth.sh',description='Get the hacker - passive WIDS. Record evidence. Check each alert.')
    sub = parser.add_subparsers(dest='command',required=True)
    for name,help_text in [('demo','Run a synthetic demo.'),('replay','Read PCAP, PCAPNG, or JSONL.'),('monitor','Watch a Monitor Mode interface.')]:
        p = sub.add_parser(name,help=help_text)
        p.add_argument('--config',help='Trusted AP policy JSON.')
        p.add_argument('--output',default=str(default_output()),help='Report parent folder.')
        p.add_argument('--max-packets',type=positive,default=1000000)
        p.add_argument('--max-bytes',type=positive,default=268435456)
        if name == 'replay':
            p.add_argument('input',help='Input capture file.')
        if name == 'monitor':
            p.add_argument('--interface',required=True,help='Monitor Mode interface name.')
            p.add_argument('--duration',type=int,default=60,help='Seconds. Use 0 until Ctrl+C.')
            p.add_argument('--gps',choices=['none','gpsd','termux'],default='none')
            p.add_argument('--ranges',help='Fresh calibrated range JSON file.')
            p.add_argument('--web',action='store_true',help='Start the local mobile view.')
            p.add_argument('--port',type=positive,default=8765)
    p = sub.add_parser('check',help='Check capture needs. Send no frames.')
    p.add_argument('--interface')
    p = sub.add_parser('report',help='Build HTML, PDF, and JSON from a session.')
    p.add_argument('session')
    p = sub.add_parser('view',help='Open a saved session in the local mobile view.')
    p.add_argument('session'); p.add_argument('--port',type=positive,default=8765)
    p = sub.add_parser('locate',help='Check calibrated source range data.')
    p.add_argument('input'); p.add_argument('--output',help='Result JSON path. Default: the standard output folder.')
    p = sub.add_parser('movement',help='Check movement from supported source fixes.')
    p.add_argument('input'); p.add_argument('--output',help='Result JSON path. Default: the standard output folder.')
    args = parser.parse_args()
    if hasattr(args,'duration') and args.duration < 0:
        parser.error('Duration must be zero or greater.')
    if hasattr(args,'port') and args.port > 65535:
        parser.error('Port must be below 65536.')
    try:
        if args.command in ('demo','replay'):
            return offline(args)
        if args.command == 'monitor':
            return monitor(args)
        if args.command == 'check':
            check=device_check(args.interface); print(json.dumps(check,indent=2)); return 0 if check['ready_for_capture'] else 1
        if args.command == 'report':
            rebuild_reports(args.session); print('Reports saved.'); return 0
        if args.command in ('locate','movement'):
            measurements = load_json_file(args.input)
            result = (estimate_position if args.command == 'locate' else estimate_movement)(measurements)
            result['input_evidence'] = measurements
            result['input_file'] = source_info(args.input,'range_data' if args.command == 'locate' else 'position_data')
            from .reports import atomic_write
            output = Path(args.output) if args.output else default_output()/(args.command+'-'+time.strftime('%Y%m%d-%H%M%S',time.gmtime())+'-'+uuid.uuid4().hex[:8]+'.json')
            output.parent.mkdir(parents=True,exist_ok=True)
            atomic_write(output,json.dumps(result,indent=2,allow_nan=False))
            print('Result file: '+str(output.resolve()))
            print(json.dumps(result,indent=2)); return 0 if result['status'] in ('estimated','movement_supported') else 1
        if args.command == 'view':
            record = load_report_file(Path(args.session)/'report.json')
            record['data_source']='saved_session'
            from .proof import verify_session
            record.setdefault('review',{})['proof_check']=verify_session(Path(args.session))
            server=start_server(lambda:record,args.port,evidence_directory=Path(args.session))
            print(f'Mobile view: http://127.0.0.1:{server.server_port}',flush=True)
            try:
                while True:
                    time.sleep(0.5)
            except KeyboardInterrupt:
                server.shutdown(); server.server_close()
            return 0
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print('Error: '+str(exc),file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
