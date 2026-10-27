"""One scoped WIDS conclusion. Missing measurements stay unknown."""
import math
import re
from .engine import DEFAULTS

RULE_CHECKS = {
 'deauth_burst':('Deauth / Disassoc','deauth_window','attack_indicator'),
 'active_recon':('Probe Recon','probe_window','recon_observation'),
 'possible_evil_twin':('Evil Twin signs','beacon_window','attack_indicator'),
 'possible_karma':('KARMA signs','karma_window','attack_indicator'),
 'auth_failure_burst':('Auth rejects','auth_fail_window','attack_indicator'),
 'assoc_failure_burst':('Assoc rejects','assoc_fail_window','attack_indicator'),
 'handshake_attempt_burst':('EAPOL attempts','handshake_window','attack_indicator'),
 'wps_failure_burst':('WPS rejects','wps_fail_window','attack_indicator'),
 'ap_policy_change':('AP policy change','beacon_window','policy_observation'),
}


def number(value):
    return value if finite(value) and value>=0 else None


from .values import mapping, finite


def conditions(policy):
    p=dict(DEFAULTS);p.update({k:v for k,v in mapping(policy).items() if k in p and number(v) is not None})
    return {
      'deauth_burst':f"{p['deauth_count']} Deauth/Disassoc frames in {p['deauth_window']:g} s. {p['deauth_sequence_min']} sequences or 4 time bins.",
      'active_recon':f"{p['probe_count']} Probe Requests and {p['probe_ssids']} named SSIDs in {p['probe_window']:g} s. Recon only.",
      'possible_evil_twin':f"{p['beacon_count']} beacons in {p['beacon_window']:g} s. saved SSID, new BSSID, weaker security.",
      'possible_karma':f"{p['karma_ssids']} matching SSIDs and {p['karma_clients']} clients in {p['karma_window']:g} s. reply delay <= {p['karma_response_delay']:g} s.",
      'auth_failure_burst':f"{p['auth_fail_count']} authentication rejects in {p['auth_fail_window']:g} s.",
      'assoc_failure_burst':f"{p['assoc_fail_count']} association rejects in {p['assoc_fail_window']:g} s.",
      'handshake_attempt_burst':f"{p['handshake_count']} distinct M2 nonces in {p['handshake_window']:g} s. no linked M2/M3/M4 exchange.",
      'wps_failure_burst':f"{p['wps_fail_count']} WPS NACK errors in {p['wps_fail_window']:g} s.",
      'ap_policy_change':f"{p['beacon_count']} distinct beacon sequences in {p['beacon_window']:g} s. saved AP name, security, or PMF policy differs. Policy observation only.",
    }


def security_assessment(record, human):
    counters=mapping(record.get('counters'));engine=mapping(record.get('engine'));stats=mapping(engine.get('stats'))
    review=mapping(record.get('review'));derived=mapping(review.get('derived'));replay=mapping(derived.get('replay'))
    coverage=mapping(engine.get('coverage'));replayed=False
    if not coverage and mapping(replay.get('coverage')):
        coverage=replay['coverage'];replayed=True
    config=mapping(record.get('config'));policy=dict(DEFAULTS)
    policy.update({k:v for k,v in mapping(config.get('detection')).items() if k in policy and number(v) is not None})
    policy.update({k:v for k,v in mapping(engine.get('policy')).items() if k in policy and number(v) is not None})
    descriptions=conditions(policy)
    first,last=number(coverage.get('first_timestamp')),number(coverage.get('last_timestamp'))
    span=last-first if first is not None and last is not None and last>=first else None
    source=mapping(record.get('source'));check=mapping(source.get('check'))
    radio=mapping(mapping(record.get('radio_selection')).get('current_state'))
    channel=radio.get('channel')
    if number(channel) is None:
        match=re.search(r'\bchannel\s+(\d+)\b',str(check.get('interface_info','')))
        channel=int(match[1]) if match else None
    channels=coverage.get('channels',[])
    if channel is None and isinstance(channels,list) and channels:
        channel=channels[0] if all(number(v) is not None and v>0 for v in channels) else None
    mode=record.get('mode');monitor=(mode in ('demo','replay') or mode=='live' and check.get('monitor_mode') is True)
    if mode in ('demo','replay') and channel is None:
        channel=next((n.get('channel') for n in record.get('networks',[]) if isinstance(n,dict) and number(n.get('channel'))),None)
    failures=[]
    if not monitor:failures.append('Monitor Mode or saved radio input is not verified.')
    if channel is None:failures.append('The observed channel is not recorded.')
    if human.get('capture_state')!='available':failures.append('Capture data is incomplete or unavailable.')
    if record.get('status') not in ('running','complete'):failures.append('The session has no complete capture result.')
    if number(counters.get('queue_drops')) is None:failures.append('Capture queue loss is unknown.')
    for key in ('queue_drops','invalid','unwritten'):
        if number(counters.get(key)):failures.append(key+' count is positive.')
    for key in ('invalid_events','bad_fcs','out_of_order','event_evictions','state_evictions'):
        if number(stats.get(key)):failures.append(key+' count is positive.')
    if mapping(record.get('packet_accounting')).get('balanced') is False:failures.append('Packet counts do not balance.')
    if review.get('parse_errors'):failures.append('Saved input has read errors.')
    proof_check=mapping(review.get('proof_check'))
    if proof_check.get('status')=='FAIL':failures.append('Saved evidence failed its file check.')
    for error in record.get('errors',[]) or []:
        if isinstance(error,dict) and error.get('stage') not in ('gps_read','gps_init','console_write','radio_restore'):
            failures.append('Processing errors were recorded.');break
    raw_alerts=record.get('alerts');alerts=[a for a in raw_alerts if isinstance(a,dict)] if isinstance(raw_alerts,list) else []
    index=mapping(record.get('rule_event_counts'))
    index_ok=record.get('rule_event_counts_version')==1 and set(index).issubset(RULE_CHECKS)
    for key,row in index.items():
        if not isinstance(row,dict) or any(type(row.get(k)) is not int or row[k]<0 for k in ('total','verified')) or row['verified']>row['total']:
            index_ok=False;break
    if index_ok:
        index_ok=sum(row['total'] for row in index.values())==counters.get('alerts')
        index_ok=index_ok and all(sum(a.get('rule_id')==key for a in alerts)<=index.get(key,{}).get('total',0) and sum(a.get('rule_id')==key and mapping(a.get('proof')).get('status')=='complete' and mapping(a.get('proof')).get('verified') is True for a in alerts)<=index.get(key,{}).get('verified',0) for key in RULE_CHECKS)
    if (not isinstance(raw_alerts,list) or (number(counters.get('alerts')) or 0)>len(alerts)) and not index_ok:
        failures.append('Event details are incomplete.')
    if any(a.get('rule_id') not in RULE_CHECKS for a in alerts):failures.append('A saved rule is not supported by this assessment.')
    trusted=config.get('trusted_aps') or []
    quality=('UNAVAILABLE' if not monitor or human.get('capture_state')=='unavailable' else
             'UNKNOWN' if not coverage else 'PARTIAL' if failures else 'SUFFICIENT')
    means={e.get('id'):e for e in human.get('events',[])}
    rows=[];all_refs=[];attack_count=0;unverified_attack=False
    for rule,(name,window_key,kind) in RULE_CHECKS.items():
        available=mapping(mapping(coverage.get('rules')).get(rule))
        eligible=number(available.get('eligible_events'))
        matching=[a for a in alerts if a.get('rule_id')==rule]
        verified=[];refs=[]
        for alert in matching:
            proof=mapping(alert.get('proof'));meaning=mapping(means.get(alert.get('id')))
            valid=proof.get('status')=='complete' and proof.get('verified') is True and meaning.get('proof_state')=='complete'
            # The runtime verifies its own durable proof. A failed file audit overrides it.
            if proof_check.get('status')=='FAIL':
                valid=valid and any(isinstance(r,dict) and r.get('id')==alert.get('id') and r.get('status')=='PASS' for r in proof_check.get('results',[]))
            if valid:
                verified.append(alert)
                ref={'event_id':alert.get('id'),'rule_id':rule,'proof':proof}
                refs.append(ref);all_refs.append(ref)
        match_count=index.get(rule,{}).get('total',0) if index_ok else len(matching)
        verified_count=(index.get(rule,{}).get('verified',0) if index_ok and verified and proof_check.get('status')!='FAIL' else len(verified))
        window=policy[window_key]
        reasons=[]
        if available.get('enabled') is not True:reasons.append('Rule input coverage was not recorded or this rule was not active.')
        if rule in ('possible_evil_twin','ap_policy_change') and not trusted:reasons.append('No trusted AP policy was set.')
        if eligible is None or eligible==0:reasons.append('No usable input for this rule was recorded.')
        if span is None or span<window:reasons.append('The recorded frame span is shorter than this rule window.')
        if any(number(v) for v in mapping(available.get('missing_fields')).values()):reasons.append('Some required frame fields are missing.')
        if (matching and len(verified)<len(matching)) or (index_ok and match_count>index.get(rule,{}).get('verified',0)):reasons.append('Event proof is missing, partial, or failed.')
        if kind=='attack_indicator' and verified:
            result='DETECTED';reason='Saved evidence matched this attack indicator rule.';attack_count+=verified_count
        elif not failures and not reasons:
            result='NOT_DETECTED';reason='No attack indicator matched this rule in the checked frames.'
        else:
            result='NOT_ASSESSED';reason=' '.join(dict.fromkeys(reasons+failures)) or 'Security check not completed.'
        if kind!='attack_indicator' and match_count:
            reason=('Recon was observed. Client search is not an attack.' if kind=='recon_observation' else 'AP policy changed. This alone does not prove an attack.')+' '+reason
        if kind=='attack_indicator' and match_count and not verified:unverified_attack=True
        rows.append({'rule_id':rule,'name':name,'result':result,'assessment_kind':kind,
                     'eligible_events':eligible,'window_s':window,'condition':descriptions[rule],
                     'observed':('Eligible frames: '+str(eligible)+'. ' if eligible is not None else 'Eligible frames: N/A. ')+f'Rule matches: {match_count}.',
                     'match_count':match_count,'verified_count':verified_count,'match_scope':'session_index' if index_ok else 'available_details','evidence_refs':refs,'reason':reason})
    if monitor and attack_count:
        activity='DETECTED';reason='Attack indicators detected.'
    elif not failures and not unverified_attack and any(r['result']=='NOT_DETECTED' and r['assessment_kind']=='attack_indicator' for r in rows):
        activity='NOT_DETECTED';reason='No attack indicators detected in the checked rules and frames.'
    else:
        activity='NOT_ASSESSED';reason='Security check not completed.'
    received=number(mapping(record.get('queue')).get('received'))
    if received is None and mode in ('demo','replay'):received=number(counters.get('packets'))
    return {'assessment_version':'2.0','hacker_activity':activity,'capture_quality':quality,
      'frames_received':received,'frames_analyzed':number(stats.get('events_accepted')),
      'frames_dropped':number(counters.get('queue_drops')),'networks_observed':(record['networks_seen'] if type(record.get('networks_seen')) is int and record['networks_seen']>=len(human.get('networks',[])) and mapping(record.get('network_history')).get('status')=='available' else len(human.get('networks',[]))),
      'attack_indicators':attack_count,'rules_checked':[r['rule_id'] for r in rows if r['result']!='NOT_ASSESSED'],
      'rules_not_checked':[r['rule_id'] for r in rows if r['result']=='NOT_ASSESSED'],
      'rule_results':rows,'evidence_refs':all_refs,'capture_limitations':list(dict.fromkeys(failures)),
      'assessment_reason':reason,'observation_span_s':span,'observed_channel':channel,
      'coverage_scope':('Current rules on saved frames. Original loss and errors still apply.' if replayed else 'Only received frames on the recorded channel and active rules are assessed.')}
