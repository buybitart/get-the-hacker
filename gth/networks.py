"""Build one AP observation row. Live capture and replay use this code."""

def observation_row(previous,event,engine):
    key=event['bssid']
    row = dict(previous or {'bssid':key,'first_seen':event['timestamp'],'frames':0})
    row.update({k:event[k] for k in ('ssid','ssid_hex','channel','advertised_channel','frequency_mhz','rssi','security','pmf_required','pmf_capable','rsn_valid','rsn_error','rsn_group_cipher','rsn_pairwise_ciphers','rsn_akms','rsn_pmkid_count','rsn_group_management_cipher','beacon_tsf_us','beacon_interval_tu') if k in event})
    row.update(last_seen=event['timestamp'], frames=row['frames']+1)
    mismatch=event.get('advertised_channel') is not None and event.get('channel') is not None and event['advertised_channel']!=event['channel']
    row['channel_mismatch_frames']=row.get('channel_mismatch_frames',0)+int(mismatch)
    baseline=engine.baseline_for(event)
    row['baseline_fields']=['ssid','bssid','security']
    same_ap=[ap for ap in baseline if ap['bssid']==key]
    row['baseline_status']=('missing' if not (baseline or engine.ap_policy_for(event)) else 'match' if any(ap['bssid']==key and ap['security']==event.get('security') for ap in baseline) else 'mismatch')
    pmf=[ap['pmf_required'] for ap in same_ap if 'pmf_required' in ap]
    if pmf:
        row['baseline_fields'].append('pmf_required')
        if row['baseline_status']=='match':
            row['baseline_status']=('unknown' if event.get('pmf_required') is None else
                                    'match' if event['pmf_required'] in pmf else 'mismatch')
    return row


def rebuild_history(events,config):
    """Recover AP rows from saved input. Original snapshots stay separate."""
    from .engine import Engine
    engine=Engine(config);observed={}
    for event in events:
        before=dict(engine.stats);engine.process(event)
        rejected=any(engine.stats.get(k,0)>before.get(k,0) for k in ('invalid_events','bad_fcs','out_of_order'))
        if not rejected and isinstance(event,dict) and event.get('kind') in ('beacon','probe_response') and event.get('bssid'):
            key=event['bssid'];observed[key]=observation_row(observed.get(key),event,engine)
    return list(observed.values())
