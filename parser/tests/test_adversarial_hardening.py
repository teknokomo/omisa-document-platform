import json, stat, zipfile
from pathlib import Path
import pytest
from omisa_parser.broker import run_worker
from omisa_parser.core import Limits, ParseError, parse_document
RID='9'*32; FIX=Path(__file__).resolve().parents[1]/'fixtures'

def _worker(tmp_path,body):
 p=tmp_path/'evil.py';p.write_text('import json,sys\nfrom pathlib import Path\nout=Path(sys.argv[sys.argv.index("--output")+1])\n'+body);return p

def test_runner_refuses_stale_and_malformed_sequences(tmp_path):
 out=tmp_path/'out';out.write_text('stale');assert run_worker(FIX/'sample.txt',out,request_id=RID).code=='parser_failed';assert not out.exists()
 bodies=["out.write_text(json.dumps({'schema':'omisa.document/1','type':'wat'})+'\\n')","e={'schema':'omisa.document/1','type':'error','request_id':'8'*32,'status':'error','code':'parser_failed','retryable':False,'stage':'output'};out.write_text(json.dumps(e)+'\\n')","e={'schema':'omisa.document/1','type':'error','request_id':'9'*32,'status':'error','code':'parser_failed','retryable':False,'stage':'output'};out.write_text((json.dumps(e)+'\\n')*2)"]
 for body in bodies: assert run_worker(FIX/'sample.txt',tmp_path/'out',request_id=RID,worker=_worker(tmp_path,body)).code=='parser_failed'

def test_output_budget_counts_and_tiny_cap(tmp_path):
 p=tmp_path/'x';p.write_text('x'*10000);rec=parse_document(p,RID,limits=Limits(max_output_bytes=800));assert rec[-1]['counts']['text_chars']==sum(len(x['text']) for x in rec if x['type']=='text');assert rec[-1]['counts']['records_emitted']==len(rec)
 rec=parse_document(p,RID,limits=Limits(max_output_bytes=220));raw=''.join(json.dumps(x,separators=(',',':'))+'\n' for x in rec).encode();assert len(raw)<=220 and rec[0]['code']=='output_limit'

def test_detect_head_and_large_text_reads_bounded(monkeypatch,tmp_path):
 p=tmp_path/'x';p.write_text('x'*(2*1024*1024));seen=[];real=Path.open
 class G:
  def __init__(self,f):self.f=f
  def read(self,n=-1):seen.append(n);assert n!=-1;return self.f.read(n)
  def __enter__(self):return self
  def __exit__(self,*a):return self.f.__exit__(*a)
  def __getattr__(self,n):return getattr(self.f,n)
 def guarded(self,*a,**k):
  f=real(self,*a,**k);return G(f) if self==p else f
 monkeypatch.setattr(Path,'open',guarded);parse_document(p,RID,limits=Limits(max_text_chars=1000,max_input_bytes=3*1024*1024));assert max(seen)<=8192

def test_csv_json_xml_caps(tmp_path):
 p=tmp_path/'x';p.write_text(','.join(['x']*257)+'\n'+','.join(['y']*257)+'\n');
 with pytest.raises(ParseError):parse_document(p,RID)
 p.write_text('['*129+'0'+']'*129)
 with pytest.raises(ParseError):parse_document(p,RID)
 p.write_text('<x>'*65+'</x>'*65)
 with pytest.raises(ParseError):parse_document(p,RID)

def test_zip_symlink_nested_magic_structural_spoof(tmp_path):
 p=tmp_path/'x';ct='<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>'
 with zipfile.ZipFile(p,'w') as z:
  i=zipfile.ZipInfo('word/document.xml');i.create_system=3;i.external_attr=(stat.S_IFLNK|511)<<16;z.writestr(i,'target');z.writestr('[Content_Types].xml',ct)
 with pytest.raises(ParseError):parse_document(p,RID)
 with zipfile.ZipFile(p,'w') as z:z.writestr('[Content_Types].xml','<!-- wordprocessingml.document -->');z.writestr('blob.bin',b'PK\x03\x04junk')
 with pytest.raises(ParseError):parse_document(p,RID)

def test_relationship_odf_pdf_and_options_policy(tmp_path):
 p=tmp_path/'x';ct='<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>';rel='<Relationships>'+''.join(f'<Relationship Id="r{i}" targetmode="External"/>' for i in range(10001))+'</Relationships>'
 with zipfile.ZipFile(p,'w') as z:z.writestr('[Content_Types].xml',ct);z.writestr('word/document.xml','<x/>');z.writestr('x.rels',rel)
 with pytest.raises(ParseError):parse_document(p,RID)
 p.write_bytes(FIX.joinpath('sample.pdf').read_bytes()+b'PK\x03\x04/JavaScript')
 with pytest.raises(ParseError):parse_document(p,RID)
 for opt in ({'ocr':'auto'},{'language_hints':['eng']}):
  records=parse_document(FIX/'sample.txt',RID,opt);assert records[-1]['type']=='end'
 with pytest.raises(ParseError):parse_document(FIX/'sample.txt',RID,{'include':['metadata']})

def test_macro_ooxml_is_detected_and_warned(tmp_path):
 p=tmp_path/'x'; source=FIX/'sample.docx'
 with zipfile.ZipFile(source) as src, zipfile.ZipFile(p,'w') as z:
  for info in src.infolist():
   data=src.read(info)
   if info.filename=='[Content_Types].xml':data=data.replace(b'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml',b'application/vnd.ms-word.document.macroEnabled.main+xml')
   z.writestr(info,data)
  z.writestr('word/vbaProject.bin','macro')
 records=parse_document(p,RID);assert records[0]['document']['detected_format']=='docx';assert any(w['code']=='active_content_present' for w in records[0]['warnings'])
