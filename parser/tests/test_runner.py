import json, os, stat, textwrap, time
from pathlib import Path
from omisa_parser.broker import run_worker

FIX=Path(__file__).resolve().parents[1]/'fixtures'

def test_runner_executes_fixed_worker_and_validates_jsonl(tmp_path):
    out=tmp_path/'out.jsonl'
    result=run_worker(FIX/'sample.txt',out,request_id='b'*32,timeout=5)
    assert result.ok and result.code=='ok'
    rows=[json.loads(x) for x in out.read_text().splitlines()]
    assert rows[-1]['type']=='end'

def test_runner_timeout_is_categorical(tmp_path):
    worker=tmp_path/'worker.py'; worker.write_text('import time; time.sleep(5)')
    result=run_worker(FIX/'sample.txt',tmp_path/'out',request_id='c'*32,timeout=.05,worker=worker)
    assert not result.ok and result.code=='timeout'


def _pid_alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_runner_timeout_kills_and_reaps_worker_process_tree(tmp_path):
    pids = tmp_path / 'pids'
    worker = tmp_path / 'worker.py'
    worker.write_text(textwrap.dedent(f'''
        import os, subprocess, sys, time
        child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
        open({str(pids)!r}, 'w').write(f'{{os.getpid()}} {{child.pid}}')
        time.sleep(60)
    '''))
    result = run_worker(FIX/'sample.txt', tmp_path/'out', request_id='c'*32,
                        timeout=.2, worker=worker)
    assert result.code == 'timeout'
    child, grandchild = map(int, pids.read_text().split())
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline and (_pid_alive(child) or _pid_alive(grandchild)):
        time.sleep(.02)
    assert not _pid_alive(child)
    assert not _pid_alive(grandchild)

def test_runner_caps_stderr(tmp_path):
    worker=tmp_path/'worker.py';worker.write_text('import sys;sys.stderr.write("x"*100000);raise SystemExit(1)')
    result=run_worker(FIX/'sample.txt',tmp_path/'out',request_id='d'*32,timeout=2,worker=worker,stderr_cap=100)
    assert result.code=='parser_failed' and len(result.stderr)<=100

def test_runner_uses_empty_environment_and_temp_cwd(tmp_path):
    worker=tmp_path/'worker.py';worker.write_text(textwrap.dedent('''
      import json,os,sys
      from pathlib import Path
      Path(sys.argv[-1]).write_text(json.dumps({'env':dict(os.environ),'cwd':os.getcwd()}))
    '''))
    probe=tmp_path/'probe'
    os.environ['OMISA_SECRET_CANARY']='never'
    result=run_worker(FIX/'sample.txt',tmp_path/'out',request_id='e'*32,timeout=2,worker=worker,extra_args=[str(probe)])
    data=json.loads(probe.read_text())
    assert 'OMISA_SECRET_CANARY' not in data['env']
    assert data['cwd'] != str(Path.cwd())
