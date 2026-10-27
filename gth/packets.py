"""Read 802.11 evidence. This module never sends a frame."""
import math
import hashlib
import struct


def initialize_capture_layers():
    """Load link decoders before a capture socket or PCAP reader is opened."""
    from scapy.layers import dot11, eap, l2
    from scapy.config import conf
    import scapy

    # Linux L2Socket stores its decoder at socket creation. A later import does
    # not change that socket. Check both Linux ARPHRD and PCAP DLT entries.
    expected = {
        1: l2.Ether, 105: dot11.Dot11, 127: dot11.RadioTap,
        801: dot11.Dot11, 803: dot11.RadioTap,
    }
    for code, layer in expected.items():
        if conf.l2types.num2layer.get(code) is not layer:
            raise RuntimeError('Wi-Fi decoder is not ready.')
    return {
        'status': 'ready',
        'scapy_version': scapy.__version__,
        'link_decoders': {str(code): layer.__name__ for code, layer in expected.items()},
        'eap_decoder': eap.EAPOL.__name__,
    }


def capture_observation(packet, event=None, error=None):
    """Return bounded capture metadata. Do not change the packet decoder."""
    out = {
        'reason': 'invalid_packet',
        'packet_class': type(packet).__name__[:80],
        'layers': [],
        'length': None,
        'dot11_type': None,
        'dot11_subtype': None,
        'rssi': None,
        'channel': None,
        'frequency_mhz': None,
    }
    try:
        out['length'] = len(packet)
    except Exception:
        pass
    try:
        current, seen = packet, set()
        for _ in range(16):
            if current is None or id(current) in seen:
                break
            seen.add(id(current))
            name = type(current).__name__[:80]
            if name == 'NoPayload':
                break
            out['layers'].append(name)
            current = getattr(current, 'payload', None)
    except Exception:
        pass
    try:
        from scapy.layers.dot11 import Dot11, RadioTap
        dot = packet.getlayer(Dot11)
        rt = packet.getlayer(RadioTap)
        if dot is not None:
            out['dot11_type'] = int(dot.type)
            out['dot11_subtype'] = int(dot.subtype)
        if rt is not None:
            signal = getattr(rt, 'dBm_AntSignal', None)
            freq = getattr(rt, 'ChannelFrequency', None)
            if signal is not None and -127 <= int(signal) <= 0:
                out['rssi'] = int(signal)
            if freq is not None and 1 <= int(freq) <= 100000:
                out['frequency_mhz'] = int(freq)
                out['channel'] = frequency_channel(int(freq))
        if error is not None:
            out['reason'] = 'invalid_packet'
        elif event is not None:
            out['reason'] = 'accepted'
        elif dot is None:
            out['reason'] = 'unsupported_link'
        elif int(dot.type) not in (0, 2):
            out['reason'] = 'unsupported_frame_type'
        elif not dot.addr2:
            out['reason'] = 'invalid_packet'
        elif int(dot.type) == 2:
            out['reason'] = 'encrypted_data' if int(dot.FCfield) & 64 else 'other_data'
        else:
            out['reason'] = 'unsupported_management'
    except Exception:
        # Test doubles and malformed packet objects must not stop capture.
        out['reason'] = 'accepted' if event is not None and error is None else 'invalid_packet'
    if error is not None:
        out['error_type'] = type(error).__name__[:80]
    if out['reason'].startswith('unsupported_'):
        try:
            out['prefix_hex'] = bytes(packet)[:64].hex()
        except Exception:
            pass
    return out


def frequency_channel(freq):
    if freq == 2484:
        return 14
    if 2412 <= freq <= 2472 and (freq - 2407) % 5 == 0:
        return (freq - 2407) // 5
    if 5005 <= freq < 5925 and freq % 5 == 0:
        return (freq - 5000) // 5
    if freq == 5935:
        return 2
    if 5955 <= freq <= 7115 and (freq - 5950) % 5 == 0:
        return (freq - 5950) // 5
    return None


def rsn_fields(raw):
    """Read complete RSN fields. Keep unsupported values out of policy rules."""
    out = dict(rsn_valid=False, rsn_error=None, pmf_capable=None, pmf_required=None,
               rsn_group_cipher=None, rsn_pairwise_ciphers=[], rsn_akms=[],
               rsn_pmkid_count=None, rsn_group_management_cipher=None)
    offset = 0

    def take(size):
        nonlocal offset
        if offset + size > len(raw):
            raise ValueError('Short RSN field.')
        value = raw[offset:offset+size]; offset += size
        return value

    def count():
        return int.from_bytes(take(2), 'little')

    def suite(allowed):
        value = take(4)
        if value[:3] != b'\x00\x0f\xac' or value[3] not in allowed:
            raise ValueError('Unsupported RSN suite.')
        return value.hex()

    try:
        if count() != 1:
            raise ValueError('Unsupported RSN version.')
        # Fields after Version may be absent. Complete missing fields use
        # RSN defaults. A partial field is never a default.
        out['rsn_group_cipher'] = suite({1, 2, 4, 5, 7, 8, 9, 10}) if offset < len(raw) else '000fac04'
        out['rsn_pairwise_ciphers'] = ['000fac04']
        if offset < len(raw):
            size = count()
            if size < 1:
                raise ValueError('Empty RSN cipher list.')
            out['rsn_pairwise_ciphers'] = [suite({0, 1, 2, 4, 5, 8, 9, 10}) for _ in range(size)]
        out['rsn_akms'] = ['000fac01']
        if offset < len(raw):
            size = count()
            if size < 1:
                raise ValueError('Empty RSN AKM list.')
            out['rsn_akms'] = [suite({1, 2, 3, 4, 5, 6, 8, 9, 11, 12, 13, 18}) for _ in range(size)]
        caps = count() if offset < len(raw) else 0
        capable, required = bool(caps & 128), bool(caps & 64)
        if required and not capable:
            raise ValueError('PMF flags conflict.')
        out['rsn_pmkid_count'] = count() if offset < len(raw) else 0
        take(16*out['rsn_pmkid_count'])
        if offset < len(raw):
            out['rsn_group_management_cipher'] = suite({6, 11, 12, 13})
        if offset != len(raw):
            raise ValueError('Extra RSN data.')
        out.update(rsn_valid=True, pmf_capable=capable, pmf_required=required)
    except ValueError as error:
        out['rsn_error'] = str(error)
    return out


def security_details(ies, privacy):
    out = dict(security='unknown', pmf_capable=None, pmf_required=None,
               rsn_valid=None, rsn_error=None)
    rsns = [v for k, v in ies if k == 48]
    if len(rsns) > 1:
        out.update(rsn_valid=False, rsn_error='Duplicate RSN fields.')
        return out
    if rsns:
        out.update(rsn_fields(rsns[0]))
        if out['rsn_valid']:
            suites = {int(value[-2:], 16) for value in out['rsn_akms']}
            # Transition mode still permits WPA2; it is not WPA3-only.
            out['security'] = 'wpa3' if suites <= {8, 9, 12, 13} else 'wpa2'
            # OWE is not WPA2. Keep its AKM but do not rank it as WPA2.
            if 18 in suites:
                out['security'] = 'unknown'
        return out
    for k, val in ies:
        if k == 221 and val.startswith(b'\x00\x50\xf2\x01'):
            try:
                if len(val) < 14 or val[4:6] != b'\x01\x00':
                    return out
                count = int.from_bytes(val[10:12], 'little')
                off = 12 + 4*count
                if count < 1 or off+2 > len(val):
                    return out
                auth_count = int.from_bytes(val[off:off+2], 'little')
                if auth_count < 1 or off+2+4*auth_count > len(val):
                    return out
                out['security'] = 'wpa'
                return out
            except (IndexError, ValueError):
                return out
    out['security'] = 'wep' if privacy else 'open'
    return out


def security_from_ies(ies, privacy):
    details = security_details(ies, privacy)
    return details['security'], details['pmf_required']


def wps_fields(raw):
    """Read an unfragmented WFA WSC message. Do not inspect encrypted values."""
    if len(raw) < 14 or raw[4] != 254 or raw[5:8] != b'\x00\x37\x2a' or raw[8:12] != b'\x00\x00\x00\x01':
        return None
    if raw[13] != 0:  # Fragmented WSC needs reassembly; do not guess.
        return None
    if raw[12] not in (4, 3):
        return None
    off, attrs = 14, {}
    while off < len(raw):
        if off + 4 > len(raw):
            raise ValueError('Short WPS field.')
        key, size = struct.unpack_from('!HH', raw, off)
        off += 4
        if off + size > len(raw) or key in attrs:
            raise ValueError('Bad WPS field length or duplicate field.')
        attrs[key] = raw[off:off+size]
        off += size
    msg = attrs.get(0x1022, b'')
    if len(msg) != 1:
        return None
    out = {'message_type': msg[0]}
    if 0x1009 in attrs and len(attrs[0x1009]) == 2:
        out['config_error'] = int.from_bytes(attrs[0x1009], 'big')
    for key in (0x101a, 0x1039):
        if len(attrs.get(key, b'')) == 16:
            out['session_id'] = attrs[key].hex()
            break
    return out


def parse_packet(packet):
    from scapy.layers.dot11 import Dot11, Dot11FCS, RadioTap, Dot11Beacon, Dot11ProbeResp, Dot11Elt, Dot11Deauth, Dot11Disas, Dot11Auth, Dot11AssoResp, Dot11ReassoResp
    from scapy.layers.eap import EAPOL, EAPOL_KEY, EAP
    if not packet.haslayer(Dot11):
        return None
    d = packet[Dot11]
    if d.type not in (0, 2) or not d.addr2:
        return None
    ts = float(packet.time)
    if not math.isfinite(ts) or ts < 0:
        raise ValueError('Bad packet time.')
    flags = int(d.FCfield)
    ds = flags & 3
    bssid = d.addr3 if d.type == 0 or ds == 0 else d.addr1 if ds == 1 else d.addr2 if ds == 2 else None
    if bssid == 'ff:ff:ff:ff:ff:ff':
        bssid = None
    event = dict(timestamp=ts, kind='other', source=d.addr2.lower(), destination=(d.addr1 or '').lower(), bssid=bssid.lower() if bssid else None, sequence=int(d.SC) >> 4, fragment=int(d.SC) & 15, retry=bool(flags & 8), protected=bool(flags & 64), bad_fcs=False, rssi=None, channel=None)
    if packet.haslayer(RadioTap):
        rt = packet[RadioTap]
        if getattr(rt, 'dBm_AntSignal', None) is not None:
            rssi = int(rt.dBm_AntSignal)
            event['rssi'] = rssi if -127 <= rssi <= 0 else None
        if getattr(rt, 'ChannelFrequency', None) is not None:
            event['frequency_mhz'] = int(rt.ChannelFrequency)
            event['channel'] = frequency_channel(event['frequency_mhz'])
        event['bad_fcs'] = bool(int(getattr(rt, 'Flags', 0) or 0) & 0x40)
    frame_bytes = bytearray(bytes(d))
    if isinstance(d, Dot11FCS):
        # FCS includes the Retry bit. Remove FCS before normalizing Retry.
        # This hash is a dedup key. It is not a hash of the raw radio frame.
        frame_bytes = frame_bytes[:-4]
    if len(frame_bytes) > 1:
        frame_bytes[1] &= ~8
    event['frame_hash'] = hashlib.sha256(frame_bytes).hexdigest()
    subtype = int(d.subtype)
    if d.type == 0:
        event['kind'] = {8:'beacon', 4:'probe_request', 5:'probe_response', 12:'deauth', 10:'disassoc', 11:'auth', 0:'assoc_request', 2:'assoc_request', 1:'assoc_response', 3:'reassoc_response'}.get(subtype, 'other')
        if event['kind'] in ('beacon', 'probe_request', 'probe_response', 'assoc_request'):
            # Scapy may turn a short RSN into Raw or rebuild missing bytes.
            # Read the original body so malformed RSN cannot become WEP/Open.
            body = d.payload
            raw_body = getattr(body, 'original', b'') or bytes(body)
            offset = {8: 12, 5: 12, 4: 0, 0: 4, 2: 10}[subtype]
            if len(raw_body) < offset:
                raise ValueError('Short 802.11 management body.')
            ies = []
            while offset < len(raw_body):
                if offset + 2 > len(raw_body):
                    raise ValueError('Short 802.11 information element.')
                tag, size = raw_body[offset:offset+2]
                offset += 2
                if offset + size > len(raw_body):
                    raise ValueError('Short 802.11 information element.')
                ies.append((tag, raw_body[offset:offset+size]))
                offset += size
                if len(ies) > 128:
                    raise ValueError('Too many 802.11 information elements.')
            names = [v for k, v in ies if k == 0]
            if names:
                if len(names) != 1 or len(names[0]) > 32:
                    raise ValueError('Bad SSID field.')
                event['ssid'] = names[0].decode('utf-8', errors='replace')
                event['ssid_hex'] = names[0].hex()
            for k, val in ies:
                if k == 3 and len(val) == 1:
                    event['advertised_channel'] = val[0]
                    if event['channel'] is None:
                        event['channel'] = val[0]
            cap = packet[Dot11Beacon].cap if packet.haslayer(Dot11Beacon) else packet[Dot11ProbeResp].cap if packet.haslayer(Dot11ProbeResp) else None
            if cap is not None:
                event.update(security_details(ies, bool(int(cap) & 0x10)))
                body = packet[Dot11Beacon] if packet.haslayer(Dot11Beacon) else packet[Dot11ProbeResp]
                event['beacon_tsf_us'] = int(body.timestamp)
                event['beacon_interval_tu'] = int(body.beacon_interval)
        if packet.haslayer(Dot11Deauth) and not event['protected']:
            event['reason'] = int(packet[Dot11Deauth].reason)
        if packet.haslayer(Dot11Disas) and not event['protected']:
            event['reason'] = int(packet[Dot11Disas].reason)
        if event['kind'] in ('assoc_response','reassoc_response') and not event['protected']:
            layer=packet.getlayer(Dot11AssoResp) if subtype==1 else packet.getlayer(Dot11ReassoResp)
            if layer is None or len(bytes(layer))<6:
                raise ValueError('Short Association response.')
            event.update(status=int(layer.status),association_id=int(layer.AID)&0x3fff)
        if packet.haslayer(Dot11Auth) and not event['protected']:
            event.update(auth_algorithm=int(packet[Dot11Auth].algo), auth_sequence=int(packet[Dot11Auth].seqnum), status=int(packet[Dot11Auth].status))
    if not event['protected'] and packet.haslayer(EAPOL_KEY) and packet.haslayer(EAPOL):
        key, eapol = packet[EAPOL_KEY], packet[EAPOL]
        raw = bytes(eapol)
        if len(raw) < 99 or int(eapol.type) != 3:
            raise ValueError('Short EAPOL Key frame.')
        declared = int.from_bytes(raw[2:4], 'big')
        data_len = int.from_bytes(raw[97:99], 'big')
        if declared < 95 or declared + 4 > len(raw) or 99 + data_len > declared + 4:
            raise ValueError('Bad EAPOL Key length.')
        event['kind'] = 'eapol_key'
        event.update(replay_counter=int(key.key_replay_counter), nonce=bytes(key.key_nonce).hex(), key_message=None)
        if int(key.key_type) == 1 and not int(key.request) and not int(key.error):
            ack, mic, install, secure = [bool(int(getattr(key, x))) for x in ('key_ack','has_key_mic','install','secure')]
            event['key_message'] = 1 if ack and not mic and not install else 3 if ack and mic and install else 4 if not ack and mic and secure else 2 if not ack and mic and not secure else None
        event['pmkid_present'] = False
        if not int(key.encrypted_key_data):
            data, off = bytes(key.key_data), 0
            while off+2 <= len(data):
                tag, size = data[off:off+2]; off += 2
                if off+size > len(data):
                    break
                val = data[off:off+size]; off += size
                if tag == 221 and size == 20 and val[:4] == b'\x00\x0f\xac\x04':
                    event['pmkid_present'] = True
    elif not event['protected'] and packet.haslayer(EAP):
        eap = packet[EAP]
        raw = bytes(eap)
        if len(raw) < 4:
            raise ValueError('Short EAP frame.')
        size = int.from_bytes(raw[2:4], 'big')
        if size > len(raw) or size < 4:
            raise ValueError('Bad EAP length.')
        event.update(kind='eap', eap_code=int(eap.code), eap_id=int(eap.id), eap_type=int(raw[4]) if size >= 5 and int(eap.code) in (1,2) else None)
        fields = wps_fields(raw[:size]) if event['eap_type'] == 254 else None
        if fields:
            event.update(fields, kind='wps')
    return event if event['kind'] != 'other' else None


def read_pcap(path):
    # Register Radiotap/802.11 and EAPOL link types before opening the reader.
    initialize_capture_layers()
    from scapy.utils import PcapReader
    with PcapReader(str(path)) as reader:
        for packet in reader:
            yield packet
