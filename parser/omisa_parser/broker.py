from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence
from jsonschema import Draft202012Validator
from .processes import run_in_process_group

_SCHEMA_PATH=Path(__file__).with_name("schemas")/'document-jsonl-record-v1.schema.json'
_VALIDATOR=Draft202012Validator(json.loads(_SCHEMA_PATH.read_text()))

@dataclass
class RunResult:
    ok:bool; code:str; stderr:bytes=b''

def _validate_output(path:Path, request_id:str, cap:int)->tuple[bool,str]:
    total=0; count=0; terminal=False; document=False; ids=set(); units=set(); orders={}
    try:
        with path.open('rb',buffering=0) as raw:
            while True:
                line=raw.readline(256*1024+2)
                if not line:break
                total+=len(line); count+=1
                if total>cap or len(line)>256*1024+1:return False,'output_limit'
                if not line.endswith(b'\n') or terminal:return False,'parser_failed'
                try: row=json.loads(line.decode('utf-8'))
                except (UnicodeDecodeError,json.JSONDecodeError):return False,'parser_failed'
                if not isinstance(row,dict) or list(_VALIDATOR.iter_errors(row)):return False,'parser_failed'
                typ=row['type']
                if typ=='document':
                    if count!=1 or document or row['request_id']!=request_id:return False,'parser_failed'
                    document=True
                elif typ in {'end','error'}:
                    if row['request_id']!=request_id or (typ=='end' and not document):return False,'parser_failed'
                    if typ=='end' and row['counts']['records_emitted']!=count:return False,'parser_failed'
                    terminal=True; code=row.get('code','ok')
                else:
                    if not document:return False,'parser_failed'
                    ident=row.get('id')
                    if ident in ids:return False,'parser_failed'
                    ids.add(ident)
                    if typ=='unit':
                        parent=row.get('parent_id')
                        if parent is not None and parent not in units:return False,'parser_failed'
                        units.add(ident)
                    else:
                        uid=row.get('unit_id')
                        if uid not in units:return False,'parser_failed'
                        order=row.get('order')
                        if order<=orders.get(uid,0):return False,'parser_failed'
                        orders[uid]=order
        if not terminal:return False,'parser_failed'
        return code=='ok',code
    except (OSError,KeyError,TypeError):return False,'parser_failed'

def run_worker(input_path:Path, output_path:Path, *, request_id:str, timeout:float=30, stdout_cap:int=8*1024*1024, stderr_cap:int=64*1024, worker:Path|None=None, extra_args:Sequence[str]=())->RunResult:
    """Run one worker with an exclusive private output and stream-validate it."""
    root=Path(__file__).resolve().parents[1]
    bundled_python=root/'.venv/bin/python'
    python=bundled_python if bundled_python.is_file() else Path(sys.executable)
    worker=worker or root/'worker.py'
    output_path=Path(output_path)
    if output_path.exists() or output_path.is_symlink():
        try: output_path.unlink()
        except OSError: pass
        return RunResult(False,'parser_failed')
    with tempfile.TemporaryDirectory(prefix='omisa-parse-') as cwd:
        private=Path(cwd)/'output.jsonl'
        # Reserve the name exclusively, then remove it: workers use exclusive creation.
        fd=os.open(private,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd);private.unlink()
        cmd=[str(python),str(worker),'--input',str(input_path),'--output',str(private),'--request-id',request_id,*extra_args]
        stdout_file=Path(cwd)/'stdout'; stderr_file=Path(cwd)/'stderr'
        try:
            with stdout_file.open('wb') as so, stderr_file.open('wb') as se:
                p=run_in_process_group(cmd,cwd=cwd,env={},stdin=subprocess.DEVNULL,
                                       stdout=so,stderr=se,timeout=timeout,
                                       close_fds=True)
        except subprocess.TimeoutExpired:
            return RunResult(False,'timeout',stderr_file.read_bytes()[:stderr_cap] if stderr_file.exists() else b'')
        err=stderr_file.read_bytes()[:stderr_cap]
        if stdout_file.stat().st_size>stdout_cap:return RunResult(False,'output_limit',err)
        if p.returncode:return RunResult(False,'parser_failed',err)
        ok,code=_validate_output(private,request_id,stdout_cap)
        if code in {'ok'} or (code not in {'parser_failed','output_limit'} and private.exists()):
            try:
                output_path.parent.mkdir(parents=True,exist_ok=True)
                os.replace(private,output_path)
            except OSError:return RunResult(False,'parser_failed',err)
        return RunResult(ok,code,err)
