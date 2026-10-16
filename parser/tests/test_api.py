import json
from pathlib import Path
from omisa_parser.api import parse_authorized_file

FIX=Path(__file__).resolve().parents[1]/'fixtures'

def test_broker_api_accepts_valid_request_and_fixed_paths(tmp_path):
    req={'artifact_ref':'art_v1_'+'A'*22,'options':{'ocr':'off','include':['text'],'max_records':20}}
    result=parse_authorized_file(req,FIX/'sample.txt',tmp_path/'out.jsonl',request_id='f'*32)
    assert result.ok

def test_broker_api_rejects_path_url_and_bad_range_without_worker(tmp_path):
    req={'artifact_ref':'art_v1_'+'A'*22,'path':'/etc/passwd'}
    result=parse_authorized_file(req,FIX/'sample.txt',tmp_path/'out',request_id='f'*32)
    assert result.code=='invalid_request' and not (tmp_path/'out').exists()
    req={'artifact_ref':'art_v1_'+'A'*22,'options':{'range':{'unit':'page','start':1,'end':100}}}
    result=parse_authorized_file(req,FIX/'sample.txt',tmp_path/'out',request_id='f'*32)
    assert result.code=='invalid_request'
