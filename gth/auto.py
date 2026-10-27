"""Start GTH with local radio facts. No flags are needed."""
import copy
import json
import shutil
import socket
import sys
import time
from types import SimpleNamespace

from .gps import GPSProvider
from .console import Console
from .radio import inspect_interface, prepare_capture
from .runtime import Session, load_config
from .engine import Engine
from .web import start_server


def gps_mode():
    if shutil.which('termux-location'):
        return 'termux'
    try:
        with socket.create_connection(('127.0.0.1', 2947), timeout=0.2):
            return 'gpsd'
    except OSError:
        return 'none'


def restore_radio(preparation, session):
    errors = preparation.restore()
    preparation.restore_reported = True
    session.update(radio_restore={'errors': errors,
                                 'pending': preparation.state['changed']})
    if errors:
        session.log('Radio restore failed. Check the adapter.',errors=errors)
    return errors


def diagnostic(args, preparation, result='NO WIFI INTERFACE', reason=None):
    session = Session(args.output, 'diagnostic', load_config(args.config),
                      {'type': 'radio_check'})
    session.update(result=result, capture_available=False, network_status=None,
                   radio_selection=copy.deepcopy(preparation.state))
    message = reason or preparation.state['reason']
    try:
        session.log(result, reason=message)
        restore_radio(preparation, session)
    finally:
        session.finish('unavailable', message)
    ui=Console(defer=True)
    ui.attach(session)
    ui.emit('REPORT',str(session.directory.resolve()))
    ui.update(session.public_snapshot(),final=True,report='SAVED')
    return 1


def managed(args, preparation):
    from .__main__ import read_sensor
    ui = Console(defer=True)
    session = Session(args.output, 'managed', load_config(args.config),
                      {'type': 'managed_link', 'interface': args.interface})
    ui.attach(session)
    session.update(result='WIDS NOT AVAILABLE', capture_available=False,
                   radio_selection=copy.deepcopy(preparation.state))
    status, error, code, server = 'complete', None, 0, None
    started = time.monotonic()
    telemetry_at = 0
    console_saved = False
    stage = 'gps_init'
    try:
        gps = GPSProvider(args.gps)
        if args.web:
            stage = 'web_start'
            try:
                server = start_server(session.public_snapshot, args.port, evidence_directory=session.directory, network_provider=session.network_page)
            except OSError:
                server = start_server(session.public_snapshot, 0, evidence_directory=session.directory, network_provider=session.network_page)
            ui.emit('WEB', f'Mobile view: http://127.0.0.1:{server.server_port}')
        ui.emit('MODE', 'Managed | '+args.interface)
        ui.emit('WIDS', 'WIDS NOT AVAILABLE | Link only')
        while args.duration == 0 or time.monotonic() - started < args.duration:
            stage = 'link_read'
            network = inspect_interface(args.interface)
            network.update(coverage='managed_link_only', timestamp=time.time())
            stage = 'gps_read'
            fix = read_sensor(gps, session)
            session.sensor(fix)
            session.update(network_status=network)
            key = {k:v for k,v in network.items() if k != 'timestamp'}
            if key != ui.states.get('link_record'):
                ui.states['link_record'] = key
                session.log('Link status. No frame capture.', network_status=network, sensor_gps=fix)
                ui.network(network)
            ui.gps(fix)
            stage = 'telemetry_write'
            if time.monotonic() >= telemetry_at:
                session.telemetry()
                telemetry_at = time.monotonic()+5
            if ui.last_error is not None and not console_saved:
                session.error('console_write',ui.last_error)
                session.update(console_available=False)
                console_saved = True
            stage = 'checkpoint'
            session.checkpoint()
            ui.update(session.public_snapshot())
            time.sleep(min(1.0, max(0.0, args.duration-(time.monotonic()-started)))
                       if args.duration else 1.0)
    except KeyboardInterrupt:
        status, code = 'interrupted', 130
    except Exception as exc:
        status, error, code = 'error', str(exc), 1
        session.error(stage,exc)
    finally:
        try:
            if restore_radio(preparation, session):
                status, error, code = 'error', 'Radio restore failed.', 1
            ui.update(session.public_snapshot(),report='SAVING')
            session.finish(status, error)
        finally:
            if server:
                server.shutdown()
                server.server_close()
    ui.emit('REPORT',str(session.directory.resolve()))
    ui.update(session.public_snapshot(),final=True,report='SAVED')
    return code


def run_auto(output=None, duration=0, web=True, port=8765):
    from . import __main__ as cli
    args = SimpleNamespace(output=str(output or cli.default_output()),
                           config=str(cli.ROOT / 'config/default.json'),
                           duration=duration, web=web, port=port,
                           max_packets=1000000, max_bytes=268435456,
                           ranges=None, automatic=True)
    # Validate policy before touching the adapter.
    Engine(load_config(args.config))
    preparation = prepare_capture()
    try:
        args.interface = preparation.state['interface']
        args.preparation = preparation
        args.gps = gps_mode() if preparation.state['mode'] != 'unavailable' else 'none'
        if preparation.state['mode'] == 'monitor':
            return cli.monitor(args)
        if preparation.state['mode'] == 'managed':
            return managed(args, preparation)
        result = 'CAPTURE NOT AVAILABLE' if args.interface is not None else 'NO WIFI INTERFACE'
        return diagnostic(args, preparation, result)
    finally:
        # Covers import, storage, and startup errors before a session can open.
        if preparation.state['changed'] and not getattr(preparation, 'restore_reported', False):
            errors = preparation.restore()
            if errors:
                Console(sys.stderr).emit('Radio restore','FAILED','31')
