from pathlib import Path
from jsonschema import Draft202012Validator
import json
from .broker import RunResult,run_worker
_SCHEMA=json.loads((Path(__file__).with_name('schemas')/'document-parse-request-v1.schema.json').read_text())
_VALIDATOR=Draft202012Validator(_SCHEMA)

def parse_authorized_file(request:dict,input_path:Path,output_path:Path,*,request_id:str,timeout:float=30)->RunResult:
    """Broker-facing staging API after caller authorization/provenance checks.

    The public request has no path. input_path/output_path are trusted internal
    broker arguments and are passed as argv without a shell.
    """
    errors=list(_VALIDATOR.iter_errors(request))
    rng=request.get('options',{}).get('range') if isinstance(request,dict) else None
    if errors or (rng and (rng['end']<rng['start'] or rng['end']-rng['start']+1>50)):
        return RunResult(False,'invalid_request')
    return run_worker(input_path,output_path,request_id=request_id,timeout=timeout,extra_args=['--options-json',json.dumps(request.get('options',{}),separators=(',',':'))])
