"""Passive WIDS rules. Report frame facts. Do not claim human identity."""

from collections import OrderedDict, deque
import copy
import math
import re


DEFAULTS = {
    "deauth_count": 20, "deauth_window": 10.0, "deauth_sequence_min": 5,
    "probe_count": 30, "probe_ssids": 10, "probe_window": 30.0,
    "beacon_count": 3, "beacon_window": 30.0,
    "karma_ssids": 5, "karma_clients": 2, "karma_window": 60.0,
    "karma_response_delay": 2.0,
    "handshake_count": 8, "handshake_window": 60.0,
    "auth_fail_count": 8, "auth_fail_window": 60.0,
    "assoc_fail_count": 8, "assoc_fail_window": 60.0,
    "wps_fail_count": 8, "wps_fail_window": 60.0,
    "cooldown": 30.0, "dedup_window": 2.0,
    "max_keys": 1024, "max_events_per_key": 128,
    "max_total_events": 20000, "max_dedup": 16384, "max_cooldowns": 4096,
}
KINDS = frozenset({"beacon", "probe_request", "probe_response", "deauth",
                   "disassoc", "auth", "assoc_request", "assoc_response", "reassoc_response", "eap", "eapol_key", "wps"})
SECURITY = {"open": 0, "wep": 1, "wpa": 2, "wpa2": 3, "wpa3": 4}
MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z")
BROADCAST = "ff:ff:ff:ff:ff:ff"
COMMON_LIMITS = [
    "A MAC address is a transmitter claim. It can be spoofed or changed.",
    "Capture loss and channel coverage can hide frames.",
    "Sensor GPS is not source GPS. Source location is unknown.",
]
RULE_KINDS = {
    'deauth_burst': {'deauth', 'disassoc'}, 'active_recon': {'probe_request'},
    'possible_evil_twin': {'beacon'}, 'ap_policy_change': {'beacon'},
    'possible_karma': {'probe_request', 'probe_response'},
    'handshake_attempt_burst': {'eapol_key'}, 'auth_failure_burst': {'auth'},
    'assoc_failure_burst': {'assoc_response', 'reassoc_response'},
    'wps_failure_burst': {'wps'},
}


def _ssid_identity(record):
    """Use exact SSID bytes. Legacy UTF-8 text keeps its old meaning."""
    text, encoded = record.get('ssid'), record.get('ssid_hex')
    if encoded is not None:
        if not isinstance(encoded, str) or len(encoded) > 64 or len(encoded) % 2 or not re.fullmatch(r'[0-9a-fA-F]*', encoded):
            raise ValueError('SSID bytes are not valid.')
        raw = bytes.fromhex(encoded)
        if text is not None and raw.decode('utf-8', errors='replace') != text:
            raise ValueError('SSID text and bytes do not match.')
        return encoded.lower()
    if text is None:
        return None
    if not isinstance(text, str):
        raise ValueError('SSID text is not valid.')
    raw = text.encode('utf-8')
    if len(raw) > 32:
        raise ValueError('SSID is longer than 32 bytes.')
    return raw.hex()


from .values import finite as _number, timestamp as _timestamp


def _mac(value, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, str) or not MAC.fullmatch(value.lower()):
        raise ValueError("MAC address is not valid.")
    return value.lower()


class Engine:
    """Process time-ordered normalized events in one thread.

    Configuration: {"trusted_aps": [...], "detection": {policy: value}}.
    Other top-level fields belong to the application and are ignored.
    No rule sends a radio frame or starts a process.
    """

    def __init__(self, config=None):
        if config is None:
            config = {}
        if not isinstance(config, dict):
            raise ValueError("Config must be an object.")
        policy = config.get("detection", {})
        if not isinstance(policy, dict):
            raise ValueError("Detection config must be an object.")
        unknown = set(policy) - set(DEFAULTS)
        if unknown:
            raise ValueError("Unknown detection setting: " + str(sorted(unknown, key=str)[0]))
        self.policy = dict(DEFAULTS)
        self.policy.update(policy)
        for key, value in self.policy.items():
            if not _number(value):
                raise ValueError("Detection setting must be a finite number: " + key)
            if isinstance(DEFAULTS[key], int):
                if not isinstance(value, int) or not 1 <= value <= 100000:
                    raise ValueError("Detection count must be an integer from 1 to 100000: " + key)
            elif not (0 <= value <= 3600 if key in {"cooldown", "dedup_window"} else 0 < value <= 3600):
                raise ValueError("Detection time is outside the safe range: " + key)
        p = self.policy
        threshold_keys = [k for k in p if k.endswith("_count") or k in {"probe_ssids", "karma_ssids", "karma_clients", "deauth_sequence_min"}]
        if any(p[k] > p["max_events_per_key"] for k in threshold_keys):
            raise ValueError("Event limit is smaller than a detection threshold.")
        if p["max_total_events"] < p["max_events_per_key"]:
            raise ValueError("Total event limit is smaller than the per-key limit.")
        if p["deauth_sequence_min"] > p["deauth_count"] or p["probe_ssids"] > p["probe_count"]:
            raise ValueError("Unique-value threshold is larger than the frame count.")
        if p["karma_response_delay"] > p["probe_window"]:
            raise ValueError("KARMA response delay is larger than the Probe Request window.")

        baselines = config.get("trusted_aps", [])
        if not isinstance(baselines, list) or len(baselines) > 4096:
            raise ValueError("Trusted APs must be a list with at most 4096 entries.")
        self.baselines = {}
        self._ap_policies = {}
        self.trusted_pairs = set()
        for ap in baselines:
            if not isinstance(ap, dict):
                raise ValueError("Each trusted AP must be an object.")
            ssid = ap.get("ssid")
            if not isinstance(ssid, str) or not 1 <= len(ssid) <= 128:
                raise ValueError("Trusted SSID must be a nonempty text value.")
            bssid = _mac(ap.get("bssid"))
            if int(bssid[:2], 16) & 1:
                raise ValueError("Trusted BSSID must be a unicast MAC address.")
            security = ap.get("security")
            if not isinstance(security, str) or security not in SECURITY:
                raise ValueError("Trusted AP security must be open, wep, wpa, wpa2, or wpa3.")
            if "pmf_required" in ap and not isinstance(ap["pmf_required"], bool):
                raise ValueError("PMF required must be true or false.")
            identity = _ssid_identity(ap)
            old = self.baselines.get(identity, [])
            if any(row["bssid"] == bssid and row["security"] != security for row in old):
                raise ValueError("Trusted AP has conflicting security values.")
            row = {"ssid": ssid, "bssid": bssid, "security": security}
            if 'ssid_hex' in ap:
                row['ssid_hex'] = identity
            if 'pmf_required' in ap:
                row['pmf_required'] = ap['pmf_required']
            if any(row['bssid'] == bssid and row != prior for prior in old if prior['bssid'] == bssid):
                raise ValueError('Trusted AP has conflicting policy values.')
            if row not in old:
                old.append(row)
            self.baselines[identity] = old
            policies=self._ap_policies.setdefault(bssid,[])
            if row not in policies:policies.append(row)
            self.trusted_pairs.add((identity, bssid))

        self.stats = {key: 0 for key in (
            "events_received", "events_accepted", "invalid_events", "bad_fcs",
            "out_of_order", "retries_ignored", "state_evictions", "event_evictions",
            "dedup_evictions", "cooldown_evictions", "alerts", "recon_observations",
            "rule_events", "policy_observations", "cooldown_suppressed", "expired_events")}
        self.coverage = {'first_timestamp': None, 'last_timestamp': None, 'kinds': {},
                         'rules': {rule: {'enabled': bool(self.trusted_pairs) if rule in {'possible_evil_twin', 'ap_policy_change'} else True,
                                          'eligible_events': 0, 'first_timestamp': None, 'last_timestamp': None,
                                          'missing_fields': {}} for rule in RULE_KINDS}}
        self.rule_inputs = {}
        self._streams = OrderedDict()
        self._dedup = OrderedDict()
        self._cooldowns = OrderedDict()
        self._stored = 0
        self._last_time = None
        self._serial = 0
        self._ttl = max(p[k] for k in p if k.endswith("_window"))

    def baseline_for(self, event):
        """Return the policy for exact SSID bytes. Display text is not an ID."""
        try:
            return self.baselines.get(_ssid_identity(event), [])
        except ValueError:
            return []

    def ap_policy_for(self, event):
        """List allowed settings for one claimed BSSID."""
        return self._ap_policies.get(event.get('bssid'),[])

    def _normalize(self, event):
        if not isinstance(event, dict):
            raise ValueError("Event must be an object.")
        ts = event.get("timestamp")
        if not _timestamp(ts) or event.get("kind") not in KINDS:
            raise ValueError("Event time or kind is not valid.")
        e = {"timestamp": float(ts), "kind": event["kind"],
             "source": _mac(event.get("source")),
             "destination": _mac(event.get("destination"), True),
             "bssid": _mac(event.get("bssid"), True)}
        if int(e["source"][:2], 16) & 1:
            raise ValueError("Source must be a unicast MAC address.")
        if e["bssid"] == BROADCAST:
            e["bssid"] = None
        if e["bssid"] is not None and int(e["bssid"][:2], 16) & 1:
            raise ValueError("BSSID must be a unicast MAC address.")
        for key in ("retry", "protected", "bad_fcs"):
            if key in event and not isinstance(event[key], bool):
                raise ValueError("Frame flag must be true or false.")
            e[key] = event.get(key, False)
        for key, low, high in (("sequence", 0, 4095), ("fragment", 0, 15),
                               ("rssi", -127, 0), ("channel", 1, 255),
                               ("reason", 0, 65535), ("status", 0, 65535),
                               ("eap_code", 1, 4), ("eap_type", 0, 255),
                               ("eap_id", 0, 255), ("key_message", 1, 4),
                               ("replay_counter", 0, 2**64 - 1),
                               ("config_error", 0, 65535)):
            value = event.get(key)
            if value is not None and (not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high):
                raise ValueError("Frame number is not valid: " + key)
            e[key] = value
        for key in ("ssid", "nonce", "key_nonce", "frame_hash", "session_id"):
            value = event.get(key)
            if value is not None and (not isinstance(value, str) or len(value) > 128):
                raise ValueError("Frame text is not valid: " + key)
            e[key] = value
        e['_ssid_key'] = _ssid_identity(event)
        for key in ('pmf_required', 'pmf_capable', 'rsn_valid'):
            value = event.get(key)
            if value is not None and not isinstance(value, bool):
                raise ValueError('RSN flag must be true, false, or null.')
            e[key] = value
        if e["nonce"] is None:
            e["nonce"] = e["key_nonce"]
        if e["nonce"] is not None:
            e["nonce"] = e["nonce"].lower()
        e["security"] = event.get("security", "unknown")
        if e["security"] not in set(SECURITY) | {"unknown"}:
            raise ValueError("Frame security is not valid.")
        wps_type = event.get("wps_message_type", event.get("message_type"))
        if wps_type is not None and (isinstance(wps_type, bool) or not isinstance(wps_type, (int, str))):
            raise ValueError("WPS message type is not valid.")
        if isinstance(wps_type, str) and len(wps_type) > 32:
            raise ValueError("WPS message type is too long.")
        e["wps_message_type"] = wps_type
        gps = event.get("sensor_gps")
        e["sensor_gps"] = None
        if gps is not None:
            if not isinstance(gps, dict):
                raise ValueError("Sensor GPS must be an object or null.")
            # The GPS adapter owns fix checks. Keep scalar report fields only.
            allowed = {"latitude", "longitude", "altitude_m", "accuracy_m", "timestamp",
                       "status", "source", "mode", "lat", "lon", "error_m", "age_s",
                       "provider", "accuracy_kind", "reason", "fix_mode"}
            e["sensor_gps"] = {k: v for k, v in gps.items() if k in allowed and
                (v is None or isinstance(v, bool) or _number(v) or isinstance(v, str) and len(v) <= 128)}
        e["_raw_evidence"] = event
        e["_evidence_event"] = None
        e["_evidence_ref"] = event.get("_evidence_ref")
        return e

    def _expire(self, now):
        while self._streams:
            key, values = next(iter(self._streams.items()))
            if values[-1]["timestamp"] >= now - self._ttl:
                break
            self._streams.pop(key)
            self._stored -= len(values)
            self.stats["expired_events"] += len(values)
        for cache, window in ((self._dedup, self.policy["dedup_window"]),
                              (self._cooldowns, self.policy["cooldown"])):
            while cache and next(iter(cache.values())) < now - window:
                cache.popitem(last=False)

    def _is_retry_copy(self, e):
        if e["sequence"] is None or self.policy["dedup_window"] == 0:
            return False
        fields = ("kind", "source", "destination", "bssid", "sequence", "fragment",
                  "_ssid_key", "security", "pmf_required", "pmf_capable", "protected", "reason", "status", "key_message",
                  "replay_counter", "nonce", "eap_code", "eap_type", "eap_id",
                  "wps_message_type", "config_error", "session_id", "frame_hash")
        signature = tuple(e.get(k) for k in fields)
        previous = self._dedup.get(signature)
        if e["retry"] and previous is not None and e["timestamp"] - previous <= self.policy["dedup_window"]:
            return True
        self._dedup[signature] = e["timestamp"]
        self._dedup.move_to_end(signature)
        while len(self._dedup) > self.policy["max_dedup"]:
            self._dedup.popitem(last=False)
            self.stats["dedup_evictions"] += 1
        return False

    def _drop_oldest_stream(self):
        _, values = self._streams.popitem(last=False)
        self._stored -= len(values)
        self.stats["state_evictions"] += 1
        self.stats["event_evictions"] += len(values)

    def _add(self, key, e, window):
        # Copy raw Evidence only when a rule stores this frame.
        # Stateless observations do not need a second full event copy.
        if e.get('_evidence_event') is None:
            raw=e.pop('_raw_evidence')
            e['_evidence_event']=copy.deepcopy({k:v for k,v in raw.items() if k!='_evidence_ref'})
            e['_evidence_ref']=copy.deepcopy(e['_evidence_ref'])
        values = self._streams.get(key)
        if values is None:
            while len(self._streams) >= self.policy["max_keys"]:
                self._drop_oldest_stream()
            values = deque()
            self._streams[key] = values
        while values and values[0]["timestamp"] < e["timestamp"] - window:
            values.popleft()
            self._stored -= 1
            self.stats["expired_events"] += 1
        if len(values) >= self.policy["max_events_per_key"]:
            values.popleft()
            self._stored -= 1
            self.stats["event_evictions"] += 1
        values.append(e)
        self._stored += 1
        self._streams.move_to_end(key)
        while self._stored > self.policy["max_total_events"]:
            self._drop_oldest_stream()
        rule={'deauth':'deauth_burst','probe':'active_recon','twin':'possible_evil_twin','ap_policy':'ap_policy_change',
              'karma':'possible_karma','auth_fail':'auth_failure_burst','assoc_fail':'assoc_failure_burst',
              'handshake':'handshake_attempt_burst','wps_fail':'wps_failure_burst'}.get(key[0])
        if rule:
            previous=self.rule_inputs.get(rule,{})
            self.rule_inputs[rule]={'candidate_frames':len(values),'peak_candidate_frames':max(len(values),previous.get('peak_candidate_frames',0)),
                'window_s':window,'observed_at':e['timestamp'],
                'scope':'One stored source and AP group. Peak uses the saved session.'}
        return values

    def _emit(self, e, rule_id, method, evidence, limits, source=None, frames=()):
        source = source or e["source"]
        key = (rule_id, source, e["bssid"])
        previous = self._cooldowns.get(key)
        if previous is not None and e["timestamp"] - previous < self.policy["cooldown"]:
            self.stats["cooldown_suppressed"] += 1
            return []
        self._cooldowns[key] = e["timestamp"]
        self._cooldowns.move_to_end(key)
        while len(self._cooldowns) > self.policy["max_cooldowns"]:
            self._cooldowns.popitem(last=False)
            self.stats["cooldown_evictions"] += 1
        self._serial += 1
        self.stats["alerts"] += 1
        event_type = ('recon_observation' if rule_id == 'active_recon' else
                      'policy_observation' if rule_id == 'ap_policy_change' else 'wireless_evidence')
        self.stats[{'recon_observation': 'recon_observations', 'policy_observation': 'policy_observations',
                    'wireless_evidence': 'rule_events'}[event_type]] += 1
        # RSSI belongs to the actual frame sender, not an inferred client.
        rssi = e["rssi"] if source == e["source"] else None
        evidence = dict(evidence, frame_transmitter=e["source"],
                        frame_rssi_dbm=e["rssi"], sequence=e["sequence"],
                        source_claim="frame transmitter" if source == e["source"] else "frame receiver")
        return [{"id": f"GTH-{self._serial:06d}", "rule_id": rule_id,
                 "attack_method": method, "result": "EVENT DETECTED",
                 "event_type": event_type,
                 "timestamp": e["timestamp"], "source": source,
                 "bssid": e["bssid"], "ssid": e["ssid"], "rssi": rssi,
                 "channel": e["channel"], "evidence": evidence,
                 "sensor_gps": e["sensor_gps"], "source_location": None,
                 "limitations": COMMON_LIMITS + limits,
                 "_proof_frames": [{"event":row["_evidence_event"], "reference":row["_evidence_ref"]} for row in frames]}]

    def process(self, event):
        """Return new findings. Invalid events are counted and skipped."""
        self.stats["events_received"] += 1
        try:
            e = self._normalize(event)
        except (ValueError, TypeError, OverflowError):
            self.stats["invalid_events"] += 1
            return []
        if e["bad_fcs"]:
            self.stats["bad_fcs"] += 1
            return []
        if self._last_time is not None and e["timestamp"] < self._last_time:
            self.stats["out_of_order"] += 1
            return []
        self._last_time = e["timestamp"]
        self._expire(e["timestamp"])
        if self._is_retry_copy(e):
            self.stats["retries_ignored"] += 1
            return []
        self.stats["events_accepted"] += 1
        self._cover(e)
        kind, p = e["kind"], self.policy
        if kind in {"deauth", "disassoc"} and e["bssid"]:
            values = self._add(("deauth", e["source"], e["bssid"]), e, p["deauth_window"])
            sequences = {row["sequence"] for row in values if row["sequence"] is not None}
            duration = values[-1]["timestamp"] - values[0]["timestamp"]
            time_bins = {math.floor(row["timestamp"] * 4) for row in values}
            # Several injection tools reuse sequence zero. A sustained pattern is
            # useful Evidence, but capture copies can mimic it.
            self.rule_inputs['deauth_burst'].update(distinct_sequences=len(sequences),time_bins=len(time_bins))
            varied_sequence = len(sequences) >= p["deauth_sequence_min"]
            sustained_sequence = bool(sequences) and duration >= 1.0 and len(time_bins) >= 4
            if len(values) >= p["deauth_count"] and (varied_sequence or sustained_sequence):
                protected = sum(row["protected"] for row in values)
                deauth_frames = sum(row["kind"] == "deauth" for row in values)
                disassoc_frames = len(values) - deauth_frames
                method = ("DEAUTH/DISASSOC BURST DETECTED" if deauth_frames and disassoc_frames
                          else "DEAUTH BURST DETECTED" if deauth_frames
                          else "DISASSOC BURST DETECTED")
                return self._emit(e, "deauth_burst", method,
                    {"frame_count": len(values), "distinct_sequences": len(sequences),
                     "deauth_frames": deauth_frames, "disassoc_frames": disassoc_frames,
                     "window_seconds": p["deauth_window"], "protected_frames": protected,
                     "duration_seconds": duration, "distinct_250ms_bins": len(time_bins),
                     "sequence_pattern": "varied" if varied_sequence else "sustained reuse",
                     "unprotected_frames": len(values) - protected,
                     "reasons": sorted({row["reason"] for row in values if row["reason"] is not None})},
                    ["An AP reset can cause a burst. This rule does not prove an attack.",
                     "A protected flag does not prove a valid PMF MIC.",
                     "Capture copies without Retry flags can mimic sustained sequence reuse."], frames=values)
        elif kind == "probe_request":
            values = self._add(("probe", e["source"], None), e, p["probe_window"])
            ssids = {row['_ssid_key'] for row in values if row['_ssid_key']}
            self.rule_inputs['active_recon']['distinct_ssids']=len(ssids)
            if len(values) >= p["probe_count"] and len(ssids) >= p["probe_ssids"]:
                return self._emit(e, "active_recon", "DIRECTED PROBE BURST DETECTED",
                    {"frame_count": len(values), "distinct_ssids": len(ssids),
                     "window_seconds": p["probe_window"], "ssid_sample": sorted({row['ssid'] for row in values if row['ssid']})[:10],
                     "ssid_hex_sample": sorted(ssids)[:10]},
                    ["Probe Requests are normal for many devices. This is not an attack finding.",
                     "A silent passive scanner cannot be found from Probe Requests."], frames=values)
        elif kind == "beacon" and e['_ssid_key'] and e["bssid"]:
            baseline = self.baselines.get(e['_ssid_key'], [])
            rank = SECURITY.get(e["security"])
            if e['rsn_valid'] is False:
                return []
            ap_policy=self.ap_policy_for(e)
            if ap_policy:
                return self._ap_policy(e, ap_policy)
            if baseline and rank is not None:
                expected_rank = min(SECURITY[row["security"]] for row in baseline)
                if rank < expected_rank:
                    values = self._add(("twin", e["source"], e["bssid"], e['_ssid_key'], e["security"]), e, p["beacon_window"])
                    sequences = {row["sequence"] for row in values if row["sequence"] is not None}
                    if len(values) >= p["beacon_count"] and len(sequences) >= min(p["beacon_count"], 3):
                        return self._emit(e, "possible_evil_twin", "AP SECURITY MISMATCH",
                            {"beacon_count": len(values), "window_seconds": p["beacon_window"],
                             "observed_security": e["security"], "trusted_aps": baseline,
                             "baseline_source": "explicit user config"},
                            ["A planned guest AP or AP change can match this rule.",
                             "A same-BSSID clone is outside this rule."], frames=values)
        elif kind == "probe_response" and e["ssid"] and e["bssid"] and e["destination"]:
            requests = self._streams.get(("probe", e["destination"], None), ())
            matched = next((row for row in reversed(requests) if row['_ssid_key'] == e['_ssid_key'] and
                          row["destination"] in {None, BROADCAST, e["source"]} and
                          0 <= e["timestamp"] - row["timestamp"] <= p["karma_response_delay"]
                          ), None)
            if matched is not None:
                e["_matched_probe"] = matched
                values = self._add(("karma", e["source"], e["bssid"]), e, p["karma_window"])
                ssids = {row['_ssid_key'] for row in values}
                clients = {row["destination"] for row in values}
                self.rule_inputs['possible_karma'].update(distinct_ssids=len(ssids),distinct_clients=len(clients))
                if len(ssids) >= p["karma_ssids"] and len(clients) >= p["karma_clients"]:
                    return self._emit(e, "possible_karma", "MULTI-SSID RESPONSES DETECTED",
                        {"matched_responses": len(values), "distinct_ssids": len(ssids),
                         "distinct_clients": len(clients), "window_seconds": p["karma_window"],
                         "ssid_sample": sorted({row['ssid'] for row in values})[:10],
                         "ssid_hex_sample": sorted(ssids)[:10]},
                        ["Multi-SSID AP behavior can match this rule. This is not proof of KARMA."],
                        frames=sorted({id(row):row for response in values for row in (response["_matched_probe"],response)}.values(), key=lambda row:row["timestamp"]))
        elif kind == "eapol_key" and e["bssid"]:
            return self._handshake(e)
        elif kind == "auth" and e["status"] not in {None, 0} and e["source"] == e["bssid"] and e["destination"] not in {None, BROADCAST}:
            values = self._add(("auth_fail", e["destination"], e["bssid"]), e, p["auth_fail_window"])
            if len(values) >= p["auth_fail_count"]:
                return self._emit(e, "auth_failure_burst", "AUTH FAILURE BURST DETECTED",
                    {"failure_count": len(values), "window_seconds": p["auth_fail_window"],
                     "reported_by": e["source"], "status_codes": sorted({r["status"] for r in values})},
                    ["Bad device settings can cause failures. This does not prove brute force.",
                     "The client is a receiver claim in the AP frame. Client RSSI is unknown."],
                    source=e["destination"], frames=values)
        elif kind in {"assoc_response", "reassoc_response"} and e["status"] not in {None, 0} and e["source"] == e["bssid"] and e["destination"] not in {None, BROADCAST}:
            values = self._add(("assoc_fail", e["destination"], e["bssid"]), e, p["assoc_fail_window"])
            if len(values) >= p["assoc_fail_count"]:
                return self._emit(e, "assoc_failure_burst", "ASSOCIATION REJECT BURST DETECTED",
                    {"failure_count": len(values), "window_seconds": p["assoc_fail_window"],
                     "reported_by": e["source"], "status_codes": sorted({r["status"] for r in values}),
                     "response_types": sorted({r["kind"] for r in values})},
                    ["AP limits or client settings can cause rejects. This does not prove an attack.",
                     "The AP frame names the receiver. Client RSSI is unknown."],
                    source=e["destination"], frames=values)
        elif kind == "wps" and e["bssid"]:
            return self._wps(e)
        return []

    def _ap_policy(self, e, baseline):
        same_name=[row for row in baseline if _ssid_identity(row)==e['_ssid_key']]
        candidates=same_name or baseline
        expected=candidates[0]
        changed = {}
        if not same_name:
            changed['ssid']={'expected':[row['ssid'] for row in candidates],'observed':e['ssid'], 'observed_hex':e['_ssid_key']}
        if e['security'] in SECURITY and not any(e['security']==row['security'] for row in candidates):
            changed['security'] = {'expected': expected['security'], 'observed': e['security']}
        pmf=[row['pmf_required'] for row in candidates if 'pmf_required' in row]
        if len(pmf)==len(candidates) and e['pmf_required'] is not None and e['pmf_required'] not in pmf:
            changed['pmf_required'] = {'expected': pmf[0], 'observed': e['pmf_required']}
        if not changed:
            return []
        signature = tuple((key, row.get('observed_hex',row['observed'])) for key, row in sorted(changed.items()))
        values = self._add(('ap_policy', e['source'], e['bssid'], e['_ssid_key'], signature), e, self.policy['beacon_window'])
        sequences = {row['sequence'] for row in values if row['sequence'] is not None}
        if len(values) < self.policy['beacon_count'] or len(sequences) < min(self.policy['beacon_count'], 3):
            return []
        return self._emit(e, 'ap_policy_change', 'AP POLICY CHANGE',
                          {'beacon_count': len(values), 'distinct_sequences': len(sequences),
                           'window_seconds': self.policy['beacon_window'], 'changes': changed,
                           'trusted_ap': expected, 'baseline_source': 'explicit user config'},
                          ['An AP config change can match this rule. This is a policy observation.',
                           'A BSSID can be spoofed. These frames do not prove a clone or an attack.'], frames=values)

    def _cover(self, e):
        """Count accepted input and rule prerequisites. This is not accuracy."""
        coverage, kind, stamp = self.coverage, e['kind'], e['timestamp']
        if coverage['first_timestamp'] is None:
            coverage['first_timestamp'] = stamp
        coverage['last_timestamp'] = stamp
        coverage['kinds'][kind] = coverage['kinds'].get(kind, 0) + 1
        for rule, kinds in RULE_KINDS.items():
            if kind not in kinds:
                continue
            row, missing = coverage['rules'][rule], []
            if rule not in {'active_recon', 'possible_karma'} and not e['bssid']:
                missing.append('bssid')
            if rule in {'active_recon', 'possible_karma', 'possible_evil_twin', 'ap_policy_change'} and not e['_ssid_key']:
                missing.append('ssid')
            if rule in {'possible_evil_twin', 'ap_policy_change'}:
                baseline = self.baselines.get(e['_ssid_key'], [])
                if rule == 'ap_policy_change':
                    baseline = self.ap_policy_for(e)
                if not baseline:
                    missing.append('baseline')
                if e['security'] == 'unknown':
                    missing.append('security')
                if e['rsn_valid'] is False:
                    missing.append('valid_rsn')
                if rule == 'ap_policy_change' and any('pmf_required' in ap for ap in baseline) and e['pmf_required'] is None:
                    # PMF can be unknown while a security comparison is possible.
                    fields = row['missing_fields']
                    fields['pmf_required'] = fields.get('pmf_required', 0) + 1
            if rule == 'deauth_burst' and e['sequence'] is None:
                missing.append('sequence')
            if rule == 'possible_karma' and kind == 'probe_response':
                if not e['bssid']:
                    missing.append('bssid')
                if e['destination'] in {None, BROADCAST}:
                    missing.append('client')
            if rule in {'auth_failure_burst', 'assoc_failure_burst'}:
                if e['status'] is None:
                    missing.append('status')
                if e['source'] != e['bssid'] or e['destination'] in {None, BROADCAST}:
                    missing.append('ap_response')
            if rule == 'handshake_attempt_burst':
                if e['key_message'] is None:
                    missing.append('key_message')
                if e['replay_counter'] is None:
                    missing.append('replay_counter')
                if e['key_message'] == 2 and (not e['nonce'] or not re.fullmatch('[0-9a-f]{64}', e['nonce']) or int(e['nonce'], 16) == 0):
                    missing.append('nonce')
                if not ((e['key_message'] in {1, 3} and e['source'] == e['bssid'] and e['destination'] not in {None, BROADCAST}) or
                        (e['key_message'] in {2, 4} and e['destination'] == e['bssid'] and e['source'] != e['bssid'])):
                    missing.append('handshake_direction')
            if rule == 'wps_failure_burst':
                if e['wps_message_type'] is None:
                    missing.append('wps_message_type')
                if e['config_error'] is None:
                    missing.append('config_error')
                if e['session_id'] is None and (e['sequence'] is None or e['eap_id'] is None):
                    missing.append('session_key')
            for reason in missing:
                row['missing_fields'][reason] = row['missing_fields'].get(reason, 0) + 1
            if row['enabled'] and not missing:
                row['eligible_events'] += 1
                if row['first_timestamp'] is None:
                    row['first_timestamp'] = stamp
                row['last_timestamp'] = stamp

    def _handshake(self, e):
        message, ap = e["key_message"], e["bssid"]
        if message in {1, 3} and e["source"] == ap:
            client = e["destination"]
        elif message in {2, 4} and e["destination"] == ap and e["source"] != ap:
            client = e["source"]
        else:
            return []
        if client in {None, BROADCAST} or e["replay_counter"] is None:
            return []
        if message == 2 and (not e["nonce"] or not re.fullmatch(r"[0-9a-fA-F]{64}", e["nonce"]) or int(e["nonce"], 16) == 0):
            return []
        p = self.policy
        values = self._add(("handshake", client, ap), e, p["handshake_window"])
        if message != 2:
            return []
        attempts = {row["nonce"] for row in values if row["key_message"] == 2}
        self.rule_inputs['handshake_attempt_burst']['distinct_attempts']=len(attempts)
        if len(attempts) < p["handshake_count"]:
            return []
        # A linked M2 -> M3 -> M4 is conservative evidence of a completed exchange.
        # M3 alone or an unrelated replay counter must not suppress this rule.
        completed = False
        last_m2 = {}
        m3 = set()
        for row in values:
            counter = row["replay_counter"]
            if row["key_message"] == 2:
                last_m2[counter] = row["timestamp"]
            elif row["key_message"] == 3 and counter - 1 in last_m2:
                m3.add(counter)
            elif row["key_message"] == 4 and counter in m3:
                completed = True
        if completed:
            return []
        return self._emit(e, "handshake_attempt_burst", "EAPOL RETRY PATTERN DETECTED",
            {"distinct_attempts": len(attempts), "window_seconds": p["handshake_window"],
             "completed_exchange_seen": False, "count_basis": "distinct nonzero M2 nonce; replay counter links the exchange"},
            ["Missing M3 or M4 can be capture loss. This does not prove password brute force.",
             "PMKID presence and missing M2 alone do not start this rule."], frames=values)

    def _wps(self, e):
        if e["wps_message_type"] not in {14, "WSC_NACK", "NACK"} or e["config_error"] in {None, 0}:
            return []
        ap = e["bssid"]
        client = e["destination"] if e["source"] == ap else e["source"]
        if client in {None, BROADCAST}:
            return []
        if e["session_id"] is None and (e["sequence"] is None or e["eap_id"] is None):
            return []
        p = self.policy
        values = self._add(("wps_fail", client, ap), e, p["wps_fail_window"])
        failures = {row["session_id"] or (row["eap_id"], row["sequence"]) for row in values}
        self.rule_inputs['wps_failure_burst']['distinct_failures']=len(failures)
        if len(failures) >= p["wps_fail_count"]:
            return self._emit(e, "wps_failure_burst", "WPS FAILURE BURST DETECTED",
                {"distinct_failure_results": len(failures), "window_seconds": p["wps_fail_window"],
                 "config_errors": sorted({row["config_error"] for row in values}),
                 "count_basis": "session ID or EAP ID and sequence"},
                ["Normal WPS setup faults can cause failures. This does not prove PIN brute force.",
                 "Without a session ID, the rule counts failure frames, not complete sessions."],
                source=client, frames=values)
        return []

    def snapshot(self):
        return {"stats": dict(self.stats), "state": {"keys": len(self._streams),
                "stored_events": self._stored, "dedup_keys": len(self._dedup),
                "cooldown_keys": len(self._cooldowns), "last_timestamp": self._last_time},
                "policy": dict(self.policy), "rule_inputs":copy.deepcopy(self.rule_inputs), "coverage": copy.deepcopy(self.coverage), "trusted_ap_count": len(self.trusted_pairs),
                "source_location": "Unknown. This engine has no source position measurements.",
                "unsupported": ["Silent passive scanning", "Offline password cracking",
                                "Person identity", "Source GPS from one RSSI value"]}
