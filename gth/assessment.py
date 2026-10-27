"""Plain evidence meaning. Raw records and proof files stay unchanged."""
import math
import re


RULES = {
    'deauth_burst': ('Deauth burst', 'Many Deauth or Disassoc frames matched the rule.',
                     'A reset or an attack can cause this pattern.',
                     'Frames do not prove the sender or intent.', 'Check AP logs for a reset at this time.'),
    'ap_policy_change': ('AP policy change', 'Saved AP settings differ from received beacons.', 'The AP name, security, or PMF setting changed.', 'A setting change alone does not prove an attack.', 'Check the AP settings with the owner.'),
    'active_recon': ('Recon observed', 'Probe requests matched the Recon rule.',
                     'A client searched for many network names.',
                     'Client search can be normal. A probe is not an attack.', 'Compare the times with known client activity.'),
    'possible_evil_twin': ('AP change', 'An AP matched the saved baseline-change rule.',
                           'The saved network name used a new BSSID and weaker security.',
                           'A changed AP can be valid. This does not prove an Evil Twin.', 'Check the BSSID and security with the AP owner.'),
    'possible_karma': ('Probe replies', 'Probe requests and replies matched the rule.',
                      'One AP replied to several requested network names.',
                      'Saved replies do not prove a rogue AP or a person.', 'Check the AP service and its network names.'),
    'auth_failure_burst': ('Auth rejects', 'AP rejection frames matched the rule.',
                           'Several authentication requests failed.',
                           'Access policy or setup errors can cause rejects.', 'Check the AP authentication log.'),
    'assoc_failure_burst': ('Join rejects', 'AP association rejection frames matched the rule.',
                            'Several client join requests failed.',
                            'AP capacity or policy can cause rejects.', 'Check the AP client and capacity logs.'),
    'handshake_attempt_burst': ('Handshake attempts', 'EAPOL attempts matched the rule.',
                                'Several key exchanges had no linked full exchange in this capture.',
                                'Missing frames do not prove a password attack.', 'Check packet loss and AP authentication logs.'),
    'wps_failure_burst': ('WPS rejects', 'WPS error replies matched the rule.',
                          'Several WPS requests returned an error.',
                          'A setup error can cause WPS failures.', 'Check WPS setup and AP logs.'),
}


from .values import count as measured, mapping as _dict


def _mac(value):
    return value.lower() if isinstance(value, str) and re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', value) else None


def _observation(alert):
    return _recon(alert) or alert.get("event_type")=="policy_observation" or alert.get("rule_id")=="ap_policy_change"


def _recon(alert):
    return alert.get('rule_id') == 'active_recon' or alert.get('event_type') == 'recon_observation'


def event_meaning(alert, proof_check=None):
    rule = alert.get('rule_id')
    title, fact, meaning, limit, action = RULES.get(rule, (
        'Saved event', 'An event record was saved.', 'Read the rule and its evidence.',
        'No plain rule meaning is defined for this event.', 'Check the saved rule and proof.'))
    proof = _dict(alert.get('proof'))
    proof_state = proof.get('status') if proof.get('status') in ('complete', 'partial', 'error', 'pending') else 'missing'
    if proof_state in ('complete', 'partial') and proof.get('verified') is not True:
        proof_state = 'unchecked'
    check = _dict(proof_check)
    matches = [row for row in check.get('results', []) if isinstance(row, dict)
               and alert.get('id') and row.get('id') == alert.get('id')] if isinstance(check.get('results'), list) else []
    note = 'This is saved proof status. Run the proof check to verify the files.'
    if any(row.get('status') == 'FAIL' for row in matches):
        proof_state = 'failed'
        note = 'The independent file check failed for this event. Read the check errors.'
    elif check.get('status') == 'FAIL' and not any(row.get('status') == 'PASS' for row in matches):
        proof_state = 'unchecked'
        note = 'The session proof check failed. This event has no passing file check.'
    elif any(row.get('status') == 'PASS' for row in matches):
        note = 'The file check passed for this event. It does not prove a person or intent.'
    return {'id': alert.get('id'), 'rule_id': rule, 'title': title, 'fact': fact,
            'meaning': meaning, 'limit': limit, 'action': action, 'proof_state': proof_state,
            'proof_note': note}


def assess(record):
    """Build one presentation result from recorded facts. Never infer identity."""
    record = _dict(record)
    witnesses=record.get('alert_witnesses')
    if isinstance(witnesses,list) and witnesses:
        record=dict(record)
        recent=[a for a in record.get('alerts',[]) if isinstance(a,dict)]
        ids={a.get('id') for a in recent}
        record['alerts']=[a for a in witnesses[:9] if isinstance(a,dict) and a.get('id') not in ids]+recent
    counters = _dict(record.get('counters'))
    stats = _dict(_dict(record.get('engine')).get('stats'))
    diag = _dict(record.get('capture_diagnostics'))
    review = _dict(record.get('review'))
    proof_check = _dict(review.get('proof_check'))
    replay_stats = _dict(_dict(_dict(review.get('derived')).get('replay')).get('stats'))
    uses_replay = not _dict(record.get('engine')) and bool(replay_stats)
    if uses_replay:
        stats = replay_stats
    accepted = measured(stats.get('events_accepted'))
    packets, decoded = measured(counters.get('packets')), measured(counters.get('events'))
    drops = measured(counters.get('queue_drops'))
    alerts = [a for a in record.get('alerts', []) if isinstance(a, dict)] if isinstance(record.get('alerts', []), list) else []
    events = [event_meaning(a, proof_check) for a in alerts]
    rule_count = max(sum(not _observation(a) for a in alerts), measured(stats.get('rule_events')) or 0)
    recon_count = max(sum(_recon(a) for a in alerts), measured(stats.get('recon_observations')) or 0)
    reasons, actions = [], []
    if uses_replay:
        reasons.append('Result uses saved-event replay.')
    unavailable = record.get('mode') in ('managed', 'diagnostic', 'unavailable')
    failed = record.get('status') == 'error' or bool(record.get('error')) or record.get('result') == 'CAPTURE ERROR'
    storage_limit = _dict(record.get('storage')).get('status') == 'limit' or record.get('result') == 'EVIDENCE LIMIT'
    if unavailable:
        capture_state = 'unavailable'
        capture_title = ('WIDS NOT AVAILABLE' if record.get('mode') == 'managed' else
                         'CAPTURE NOT AVAILABLE' if record.get('result') == 'CAPTURE NOT AVAILABLE' else 'NO WIFI INTERFACE')
        reasons.append('No radio frames were measured for WIDS in this mode.')
        actions.append('Use a supported adapter in Monitor Mode.')
    elif storage_limit:
        capture_state, capture_title = 'partial', 'EVIDENCE LIMIT'
        reasons.append('The evidence size limit was reached. Capture stopped at this limit.'
                       if record.get('ended_at') is not None else
                       'The evidence size limit was reached. No final end time was saved.')
        actions.append('Keep these files. Start a new session to save more input.')
    elif failed:
        capture_state, capture_title = 'partial', 'CAPTURE ERROR'
        reasons.append(str(record.get('error') or 'Capture ended with an error.'))
        actions.append('Check the capture error and adapter state.')
    elif diag.get('health') == 'no_fresh_frames':
        capture_state, capture_title = 'partial', 'NO FRESH FRAMES'
        reasons.append('No fresh radio frames arrived at the last check.')
        actions.append('Check the radio and the capture log.')
    elif diag.get('health') == 'no_wids_data' or (accepted == 0 and decoded) or (decoded == 0 and packets):
        capture_state, capture_title = 'partial', 'NO WIDS DATA'
        reasons.append('No valid input passed WIDS checks at the last check.')
        actions.append('Check Monitor Mode and frame decode errors.')
    elif packets == 0 and decoded == 0:
        capture_state, capture_title = 'partial', 'NO PACKETS'
        reasons.append('No packet was saved.')
        actions.append('Check the adapter, channel, and capture log.')
    elif accepted is None or accepted == 0 or decoded is None:
        capture_state, capture_title = 'unknown', 'NOT ENOUGH DATA'
        reasons.append('The saved data has no positive accepted-input count.')
        actions.append('Check the saved input and WIDS counters.')
    else:
        capture_state, capture_title = 'available', 'OBSERVED WIRELESS EVENTS'
    lag = diag.get('capture_lag_s')
    lag = lag if isinstance(lag, (int, float)) and not isinstance(lag, bool) and math.isfinite(lag) and lag >= 0 else None
    history = _dict(_dict(review.get('derived')).get('capture_lag_s'))
    historical_max, historical_last = history.get('max'), history.get('last')
    historical_max = historical_max if measured(historical_max) is not None else None
    historical_last = historical_last if measured(historical_last) is not None else None
    delayed = diag.get('health') == 'capture_backlog' or (lag is not None and lag >= 15)
    past_delayed = historical_max is not None and historical_max >= 15
    if delayed or past_delayed:
        if capture_state == 'available':
            capture_state = 'partial'
            capture_title = 'FRAMES DELAYED'
        if delayed:
            reasons.append('Frames were delayed at the last check.' +
                           (' Capture lag: ' + format(lag, '.6g') + ' s.' if lag is not None else ''))
        if past_delayed:
            reasons.append('Saved timeline lag: max ' + format(historical_max, '.6g') + ' s; last ' +
                           (format(historical_last, '.6g') + ' s.' if historical_last is not None else 'not recorded.'))
        actions.append('Check capture load. Delayed frames can delay alerts.')
    if drops:
        if capture_state == 'available':
            capture_state = 'partial'
        reasons.append(str(drops) + ' frames were lost in the capture queue.')
        actions.append('Check capture load and queue loss before a longer run.')
    unwritten = measured(counters.get('unwritten'))
    if unwritten:
        if capture_state == 'available':
            capture_state = 'partial'
        reasons.append(str(unwritten) + ' received packets were not saved as event or skip records.')
    if not storage_limit and (record.get('report_state') in ('recovered', 'interrupted', 'stopped', 'cancelled') or record.get('status') in ('partial', 'limited', 'interrupted')):
        if capture_state == 'available':
            capture_state = 'partial'
        reasons.append('This is a saved partial session. The end of capture is not fully checked.')
    if proof_check.get('status') == 'FAIL':
        reasons.append('Proof check failed. Some saved evidence could not be verified.')
        actions.append('Read the proof check errors. Use the original files to check the evidence.')
    if unavailable:
        state, title, meaning = 'unavailable', 'WIDS unavailable', 'This mode did not measure radio frames for WIDS.'
    elif rule_count:
        state, title, meaning = 'rule_event', 'Rule event saved', 'Saved frames matched a WIDS rule. Read the event and proof.'
    elif recon_count:
        state, title, meaning = 'unusual_activity', 'Recon observed', 'Probe frames matched the Recon rule. Client search can be normal.'
    elif accepted and decoded and isinstance(record.get('alerts'), list):
        state, title, meaning = 'no_rule_signs', 'No rule signs', 'No saved event matched the rules in this capture.'
    else:
        state, title, meaning = 'insufficient_data', 'Not enough data', 'This input does not support a useful rule conclusion.'
    total_saved = measured(counters.get('alerts'))
    if proof_check.get('status') == 'FAIL' and state == 'no_rule_signs':
        state, title, meaning = 'insufficient_data', 'Evidence check failed', 'The saved file check failed. Read the check errors before using this result.'
    if not rule_count and not recon_count and total_saved:
        state, title, meaning = 'insufficient_data', 'Event details missing', 'The alert count is positive, but no event type is available.'
        reasons.append('Saved alert count: ' + str(total_saved) + '. Event details are missing.')
    if rule_count + recon_count > len(alerts):
        reasons.append('Only ' + str(len(alerts)) + ' of ' + str(rule_count + recon_count) + ' saved event details are in this view.')
    linked = {}
    for alert in alerts:
        mac = _mac(alert.get('bssid'))
        if mac:
            linked.setdefault(mac, []).append(alert)
    networks = record.get('networks') or []
    if isinstance(networks, dict):
        networks = list(networks.values())
    network_rows = []
    for network in networks if isinstance(networks, list) else []:
        if not isinstance(network, dict):
            continue
        related = linked.get(_mac(network.get('bssid')), [])
        event_state = ('not_checked' if unavailable or not accepted else 'no_linked_event')
        if related and not unavailable:
            event_state = 'rule_event' if any(not _observation(a) for a in related) else 'policy_observed' if any(a.get('rule_id')=='ap_policy_change' for a in related) else 'recon_observed'
        baseline = network.get('baseline_status')
        baseline = {'not_configured': 'missing', 'conflict': 'mismatch'}.get(baseline, baseline)
        if baseline not in ('match', 'mismatch', 'missing', 'unknown'):
            baseline = 'unknown'
        network_rows.append({'bssid': network.get('bssid'), 'ssid': network.get('ssid'),
                             'baseline_state': baseline, 'event_state': event_state,
                             'event_count': len(related), 'event_ids': [a.get('id') for a in related if a.get('id')]})
    if any(n['baseline_state'] == 'missing' for n in network_rows):
        actions.append('Add a baseline for APs you own and can check.')
    actions.extend(e['action'] for e in events)
    if not actions:
        actions.append('Keep this report. Check AP logs if users report a problem.')
    limits = ['Zero alerts do not prove a safe network.',
              'Source MAC is not a person ID. A rule match does not prove intent.',
              'Only received frames on measured channels were checked.',
              'A baseline match does not prove a safe AP.',
              'Sensor GPS is not source GPS. RSSI alone does not give a location.']
    result = {'schema_version': 1, 'evidence_state': state, 'title': title, 'meaning': meaning,
            'capture_state': capture_state, 'capture_title': capture_title,
            'reasons': reasons, 'actions': list(dict.fromkeys(actions)),
            'networks': network_rows, 'events': events, 'rule_count': rule_count,
            'recon_count': recon_count, 'limits': limits,
            'proof_check_state': proof_check.get('status') if proof_check.get('status') in ('PASS', 'FAIL') else 'UNVERIFIED'}

    from .security import security_assessment
    result.update(security_assessment(record, result))
    return result
