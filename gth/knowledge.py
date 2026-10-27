"""Public rule advice. This module does not classify traffic."""
import json
from functools import lru_cache
from pathlib import Path

@lru_cache(maxsize=1)
def methods():
    path = Path(__file__).resolve().parent.parent / 'config/advice.json'
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return {row['rule_id']: row for row in data.get('methods', []) if isinstance(row, dict) and isinstance(row.get('rule_id'), str)}

def source_note(rule_id):
    return methods().get(rule_id, {})

def advice_rows(assessment):
    """Advice follows saved rule matches. No match gives no automatic advice."""
    rows = []
    for result in assessment.get('rule_results', []):
        if not isinstance(result, dict) or not isinstance(result.get('match_count'), (int,float)) or result['match_count'] <= 0:
            continue
        note = source_note(result.get('rule_id'))
        if note.get('advice'):
            rows.append({'rule_id':result['rule_id'], 'advice':note['advice'], 'sources':note['sources'],
                         'basis':note['description'], 'limit':note['limit']})
    return rows
