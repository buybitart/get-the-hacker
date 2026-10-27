#!/usr/bin/env python3
"""Check saved GTH Evidence. The shared checker is in gth.proof."""
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from gth.proof import verify_session, SCOPE, safe_file, check_alert, read_rows, index_events, object_value


def main(argv=None):
    args=sys.argv[1:] if argv is None else argv
    result=verify_session(args[0]) if len(args)==1 else {'status':'FAIL','checked':0,'passed':0,'failed':0,'scope':SCOPE,'errors':['Use: python3 tools/verify_proofs.py SESSION']}
    print(json.dumps(result,indent=2,ensure_ascii=True,allow_nan=False))
    return 0 if result['status']=='PASS' else 1


if __name__=='__main__':raise SystemExit(main())
