#!/usr/bin/env python3
"""One-shot staging worker: trusted broker supplies fixed input/output paths."""
import argparse,json,os
from pathlib import Path
from omisa_parser.core import ParseError,parse_document

def error(rid,code,stage):return {'schema':'omisa.document/1','type':'error','request_id':rid,'status':'error','code':code,'retryable':code in {'timeout','busy'},'stage':stage}

def main():
    p=argparse.ArgumentParser(allow_abbrev=False)
    p.add_argument('--input',required=True);p.add_argument('--output',required=True);p.add_argument('--request-id',required=True);p.add_argument('--options-json',default='{}')
    a=p.parse_args()
    if not __import__('re').fullmatch('[a-f0-9]{32}',a.request_id): rows=[error('0'*32,'invalid_request','broker')]
    else:
        try:rows=parse_document(Path(a.input),a.request_id,json.loads(a.options_json))
        except ParseError as e:
            try:
                import logging
                logging.getLogger("omisa_parser.worker").exception("worker ParseError code=%s stage=%s", e.code, e.stage)
            except Exception:
                pass
            rows=[error(a.request_id,e.code,e.stage)]
        except Exception as exc:
            try:
                import logging
                logging.getLogger("omisa_parser.worker").exception("worker parse failed")
            except Exception:
                pass
            rows=[error(a.request_id,'parser_failed','extract')]
    out=Path(a.output)
    # The broker supplies a private, absent path. Refuse links/stale names and
    # stream records rather than constructing the complete JSONL in memory.
    fd=os.open(out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb',buffering=0) as stream:
        for row in rows:
            stream.write((json.dumps(row,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode())

if __name__=='__main__':main()
