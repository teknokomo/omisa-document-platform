from __future__ import annotations
import codecs, csv, io, json, math, re, stat, unicodedata, zipfile
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from defusedxml import ElementTree as SafeET

SCHEMA = "omisa.document/1"
BUNDLE = "2026.09.0-stage1"
MEDIA = {
 'txt':'text/plain','md':'text/markdown','csv':'text/csv','json':'application/json','xml':'application/xml','rtf':'application/rtf','pdf':'application/pdf',
 'docx':'application/vnd.openxmlformats-officedocument.wordprocessingml.document','xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet','pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation',
 'odt':'application/vnd.oasis.opendocument.text','ods':'application/vnd.oasis.opendocument.spreadsheet','odp':'application/vnd.oasis.opendocument.presentation',
 'doc':'application/msword','xls':'application/vnd.ms-excel','ppt':'application/vnd.ms-powerpoint','ole':'application/x-ole-storage'}

@dataclass(frozen=True)
class Limits:
    max_input_bytes:int=20*1024*1024; max_output_bytes:int=128*1024; max_records:int=200
    max_units:int=500; max_sheets:int=100; max_slides:int=1000; max_cells:int=250_000
    max_rows_per_sheet:int=10_000; max_columns:int=256; max_text_chars:int=5_000_000
    max_zip_entries:int=10_000; max_zip_uncompressed:int=200*1024*1024; max_zip_member:int=64*1024*1024; max_zip_ratio:int=100
    max_csv_field:int=1024*1024; max_csv_row:int=4*1024*1024
    max_xml_depth:int=64; max_xml_attributes:int=256; max_xml_nodes:int=1_000_000; max_json_depth:int=128
    max_json_bytes:int=1024*1024; max_rtf_bytes:int=1024*1024; max_office_xml_member:int=8*1024*1024
    max_pdf_objects:int=100_000

class ParseError(Exception):
    def __init__(self, code:str, stage:str='preflight'): self.code=code; self.stage=stage; super().__init__(code)

def _clean(value:Any, cap:int=65536)->tuple[str,bool]:
    text=str(value)
    text=''.join('�' if c=='\x00' else (' ' if unicodedata.category(c) in {'Cc','Cf'} and c not in '\n\t' else c) for c in text)
    return text[:cap],len(text)>cap

def _zip_preflight(path:Path, limits:Limits)->tuple[zipfile.ZipFile,set[str]]:
    try: z=zipfile.ZipFile(path)
    except (zipfile.BadZipFile,OSError): raise ParseError('malformed_document')
    infos=z.infolist()
    if len(infos)>limits.max_zip_entries: z.close(); raise ParseError('archive_policy_violation')
    total=0; names=set(); folded=set()
    for i in infos:
        n=unicodedata.normalize('NFC',i.filename); p=PurePosixPath(n)
        if i.flag_bits&1: z.close(); raise ParseError('encrypted_document')
        mode=(i.external_attr>>16)&0xffff
        if mode and stat.S_IFMT(mode) not in {0,stat.S_IFREG,stat.S_IFDIR}: z.close(); raise ParseError('archive_policy_violation')
        if '\\' in n or n.startswith('/') or '..' in p.parts or len(n.encode())>512: z.close(); raise ParseError('archive_policy_violation')
        f=n.casefold()
        if f in folded: z.close(); raise ParseError('archive_policy_violation')
        folded.add(f); names.add(n); total+=i.file_size
        ratio=i.file_size/max(1,i.compress_size)
        if i.file_size>limits.max_zip_member or ratio>limits.max_zip_ratio: z.close(); raise ParseError('archive_policy_violation')
        if n.lower().endswith(('.zip','.tar','.7z','.rar','.docx','.xlsx','.pptx','.odt','.ods','.odp')): z.close(); raise ParseError('archive_policy_violation')
        if i.file_size and not n.endswith('/'):
            try: magic=z.open(i).read(8)
            except Exception: z.close(); raise ParseError('malformed_document')
            if magic.startswith((b'PK\x03\x04',b'Rar!',b'7z\xbc\xaf\x27\x1c')): z.close(); raise ParseError('archive_policy_violation')
    if total>limits.max_zip_uncompressed or total/max(1,sum(i.compress_size for i in infos))>limits.max_zip_ratio: z.close(); raise ParseError('archive_policy_violation')
    return z,names

def _detect(path:Path, limits:Limits)->tuple[str,list[dict]]:
    size=path.stat().st_size
    if not size: raise ParseError('malformed_document')
    if size>limits.max_input_bytes: raise ParseError('input_too_large')
    with path.open('rb') as stream: head=stream.read(8192)
    if head.startswith(b'%PDF-'):
        with path.open('rb') as stream:
            data=stream.read(limits.max_input_bytes+1)
        if len(data)>limits.max_input_bytes: raise ParseError('input_too_large')
        if b'PK\x03\x04' in data: raise ParseError('active_content_policy')
        if not re.search(br'%%EOF\s*$',data): raise ParseError('malformed_document')
        # Active-content policy is semantic, not a raw byte scan. Compressed
        # content streams and subset font names may legitimately contain bytes
        # such as /AA or /JS; only resolved PDF dictionaries decide.
        try:
            import pymupdf as fitz
        except ImportError:
            import fitz
        active=re.compile(r'/(?:AA|JavaScript|JS|OpenAction|Launch|EmbeddedFile)\b')
        try:
            with fitz.open(stream=data,filetype='pdf') as doc:
                if doc.page_count<1: raise ParseError('malformed_document')
                for xref in range(1,doc.xref_length()):
                    try: text=doc.xref_object(xref,compressed=False)
                    except Exception: raise ParseError('malformed_document')
                    if active.search(text): raise ParseError('active_content_policy')
        except ParseError: raise
        except Exception: raise ParseError('malformed_document')
        return 'pdf',[]
    if head.startswith(b'{\\rtf'): return 'rtf',[]
    if head.startswith(bytes.fromhex('D0CF11E0A1B11AE1')):
        # Scan no more than the already-enforced input cap. CFB stream names
        # are UTF-16LE; unknown CFB remains a conservative generic OLE type.
        with path.open('rb') as stream:data=stream.read(limits.max_input_bytes+1)
        if len(data)>limits.max_input_bytes:raise ParseError('input_too_large')
        if 'WordDocument'.encode('utf-16le') in data:return 'doc',[]
        if any(x.encode('utf-16le') in data for x in ('Workbook','Book')):return 'xls',[]
        if 'PowerPoint Document'.encode('utf-16le') in data:return 'ppt',[]
        return 'ole',[]
    if head.startswith(b'PK\x03\x04'):
        z,names=_zip_preflight(path,limits)
        try:
            if any(i.filename.lower().endswith(('.xml','.rels')) and i.file_size>limits.max_office_xml_member for i in z.infolist()): raise ParseError('resource_limit')
            if 'mimetype' in names:
                mt=z.read('mimetype')[:100].decode('ascii','strict')
                fm={'application/vnd.oasis.opendocument.text':'odt','application/vnd.oasis.opendocument.spreadsheet':'ods','application/vnd.oasis.opendocument.presentation':'odp'}.get(mt)
                if fm:return fm,_zip_warnings(z,names)
            if '[Content_Types].xml' not in names: raise ParseError('unsupported_format')
            try: root=SafeET.fromstring(z.read('[Content_Types].xml'))
            except Exception: raise ParseError('malformed_document')
            types=[x.attrib.get('ContentType','') for x in root if x.tag.rsplit('}',1)[-1] in {'Override','Default'}]
            if any('wordprocessingml.document.main+xml' in x or 'wordprocessingml.template.main+xml' in x or 'ms-word.document.macroenabled.main+xml' in x.lower() for x in types):
                if 'word/document.xml' not in names: raise ParseError('malformed_document')
                return 'docx',_zip_warnings(z,names)
            if any('spreadsheetml.sheet.main+xml' in x or 'spreadsheetml.template.main+xml' in x or 'ms-excel.sheet.macroenabled.main+xml' in x.lower() for x in types):
                if 'xl/workbook.xml' not in names: raise ParseError('malformed_document')
                return 'xlsx',_zip_warnings(z,names)
            if any('presentationml.presentation.main+xml' in x or 'presentationml.template.main+xml' in x or 'ms-powerpoint.presentation.macroenabled.main+xml' in x.lower() for x in types):
                if 'ppt/presentation.xml' not in names: raise ParseError('malformed_document')
                return 'pptx',_zip_warnings(z,names)
            raise ParseError('unsupported_format')
        finally:z.close()
    try:
        # The detection window may end in the middle of a valid multibyte UTF-8
        # character. Incremental decoding with final=False tolerates only that
        # incomplete trailing sequence; malformed bytes inside the window still
        # fail closed. Small files are final and therefore fully validated here.
        decoder=codecs.getincrementaldecoder('utf-8-sig')('strict')
        text=decoder.decode(head,final=size<=len(head))
    except UnicodeDecodeError: raise ParseError('unsupported_format')
    stripped=text.lstrip()
    if stripped.startswith(('<!DOCTYPE','<?xml','<')):
        if re.search(r'<!DOCTYPE|<!ENTITY',text,re.I):raise ParseError('active_content_policy')
        try:
            with path.open('rb') as stream: SafeET.parse(stream)
        except Exception: raise ParseError('malformed_document')
        return 'xml',[]
    if stripped.startswith(('{','[')):
        if size>limits.max_json_bytes: raise ParseError('resource_limit')
        try:
            with path.open('r',encoding='utf-8-sig') as stream: json.load(stream)
        except Exception: raise ParseError('malformed_document')
        return 'json',[]
    lines=text.splitlines()
    if lines and any(x in lines[0] for x in ',\t'):
        try:
            dialect=csv.Sniffer().sniff(text,delimiters=',\t;')
            if len(list(csv.reader(io.StringIO(text),dialect)))>1:return 'csv',[]
        except csv.Error:
            # Sniffer may reject a bounded head ending midway through a huge
            # field. A delimiter-bearing header plus a following line remains
            # a conservative CSV candidate; extraction applies strict caps.
            if len(lines)>1:return 'csv',[]
    if re.search(r'(?m)^#{1,6}\s|^\|.*\|$',text):return 'md',[]
    return 'txt',[]

def _zip_warnings(z,names):
    macro=sum(1 for n in names if n.lower().endswith(('vbaproject.bin','macros.xml')))
    external=0; relationships=0
    for n in names:
        if n.lower().endswith('.rels'):
            try:
                root=SafeET.fromstring(z.read(n))
                for rel in root:
                    if rel.tag.rsplit('}',1)[-1].lower()!='relationship':continue
                    relationships+=1
                    attrs={k.rsplit('}',1)[-1].lower():v for k,v in rel.attrib.items()}
                    if attrs.get('targetmode','').lower()=='external':external+=1
            except ParseError:raise
            except Exception:raise ParseError('malformed_document')
    if relationships>10_000:raise ParseError('archive_policy_violation')
    out=[]
    if macro:out.append({'code':'active_content_present','count':macro})
    if external:out.append({'code':'external_relationship_ignored','count':external})
    return out

def _value(v):
    if v is None:return {'kind':'blank','display':None,'raw':None}
    if isinstance(v,bool):return {'kind':'boolean','display':str(v).lower(),'raw':str(v).lower()}
    if isinstance(v,(int,float)) and math.isfinite(v):return {'kind':'number','display':str(v),'raw':str(v)}
    if isinstance(v,(datetime,date)):return {'kind':'date','display':v.isoformat(),'raw':v.isoformat()}
    s,t=_clean(v);return {'kind':'string','display':s,'raw':s}

def _json_depth(value, limit, depth=0):
    if depth>limit: raise ParseError('resource_limit')
    if isinstance(value,dict):
        for v in value.values(): _json_depth(v,limit,depth+1)
    elif isinstance(value,list):
        for v in value: _json_depth(v,limit,depth+1)

def _xml_text(path,limits):
    depth=nodes=0; parts=[]; chars=0
    try:
        with path.open('rb') as stream:
            for event,node in SafeET.iterparse(stream,events=('start','end')):
                if event=='start':
                    depth+=1;nodes+=1
                    if depth>limits.max_xml_depth or nodes>limits.max_xml_nodes or len(node.attrib)>limits.max_xml_attributes: raise ParseError('resource_limit')
                else:
                    if node.text and node.text.strip():
                        s=node.text.strip(); remain=limits.max_text_chars-chars
                        if remain<=0: raise ParseError('resource_limit')
                        parts.append(s[:remain]); chars+=len(parts[-1])
                    depth-=1;node.clear()
    except ParseError: raise
    except Exception: raise ParseError('malformed_document')
    return ' '.join(parts)

def _csv_rows(path,limits):
    rows=[]; cells=0
    old=csv.field_size_limit();csv.field_size_limit(limits.max_csv_field)
    try:
        with path.open('r',encoding='utf-8-sig',newline='') as stream:
            for ri,row in enumerate(csv.reader(stream),1):
                if ri>limits.max_rows_per_sheet or len(row)>limits.max_columns: raise ParseError('resource_limit')
                if sum(len(x.encode('utf-8'))+1 for x in row)>limits.max_csv_row: raise ParseError('resource_limit')
                cells+=len(row)
                if cells>limits.max_cells: raise ParseError('resource_limit')
                rows.append(row)
    except csv.Error: raise ParseError('resource_limit')
    finally: csv.field_size_limit(old)
    return rows

def _bounded_text(path, encoding, char_cap, byte_cap=None):
    decoder=codecs.getincrementaldecoder(encoding)(errors='strict'); out=[]; chars=bytes_read=0
    try:
        with path.open('rb') as stream:
            while chars<=char_cap:
                want=min(8192, byte_cap+1-bytes_read) if byte_cap is not None else 8192
                if want<=0: raise ParseError('resource_limit')
                chunk=stream.read(want)
                if not chunk: break
                bytes_read+=len(chunk)
                if byte_cap is not None and bytes_read>byte_cap: raise ParseError('resource_limit')
                text=decoder.decode(chunk,final=False);out.append(text);chars+=len(text)
            if chars<=char_cap:
                tail=decoder.decode(b'',final=True);out.append(tail);chars+=len(tail)
    except UnicodeDecodeError: raise ParseError('malformed_document')
    return ''.join(out)[:char_cap]

def parse_document(path:Path|str, request_id:str, options:dict|None=None, limits:Limits=Limits(), *, ocr_adapter=None, tika_adapter=None)->list[dict]:
    path=Path(path); options=options or {}
    ocr=options.get('ocr','auto')
    if ocr not in {'off','auto','force'} or set(options.get('include',[]))&{'comments','metadata'}: raise ParseError('invalid_request')
    hints=options.get('language_hints',[])
    allowed={'en','eng','ru','rus'}
    if not isinstance(hints,list) or len(hints)>2 or len(set(hints))!=len(hints) or any(not isinstance(x,str) or x.lower() not in allowed for x in hints):raise ParseError('invalid_request')
    fmt,warnings=_detect(path,limits)
    if fmt in {'odt','ods','odp'}:
        z,_=_zip_preflight(path,limits)
        try:
            for name in ('content.xml','styles.xml','META-INF/manifest.xml'):
                if name not in z.namelist():continue
                data=z.read(name)
                if re.search(br'<\s*(?:\w+:)?scripts?\b|xlink:href\s*=\s*["\'](?:https?|file):',data,re.I):raise ParseError('active_content_policy')
                for value in re.findall(br'(?:number-(?:rows|columns)-repeated)\s*=\s*["\'](\d+)',data,re.I):
                    if int(value)>limits.max_cells:raise ParseError('resource_limit')
        finally:z.close()
    rng=options.get('range'); expected='sheet' if fmt in {'xlsx','ods'} else 'slide' if fmt in {'pptx','odp'} else 'page'
    if rng and rng.get('unit')!=expected: raise ParseError('invalid_request')
    units=[]
    if fmt in {'txt','md'}:
        text=_bounded_text(path,'utf-8-sig',limits.max_text_chars)
        units=[('page','1',[('text',text)])]
    elif fmt=='json':
        with path.open('r',encoding='utf-8-sig') as stream: obj=json.load(stream)
        _json_depth(obj,limits.max_json_depth); units=[('page','1',[('text',json.dumps(obj,ensure_ascii=False,indent=2)[:limits.max_text_chars])])]
    elif fmt=='xml': units=[('page','1',[('text',_xml_text(path,limits))])]
    elif fmt=='csv': units=[('page','1',[('tablechunks',_csv_rows(path,limits))])]
    elif fmt=='rtf':
        from striprtf.striprtf import rtf_to_text
        units=[('page','1',[('text',rtf_to_text(_bounded_text(path,'ascii',limits.max_rtf_bytes,limits.max_rtf_bytes)))])]
    elif fmt=='pdf':
        import pymupdf
        page_count=0
        try:
            with pymupdf.open(path) as d:
                if d.needs_pass: raise ParseError('encrypted_document')
                if d.page_count>limits.max_units:raise ParseError('resource_limit')
                if d.xref_length()>limits.max_pdf_objects:raise ParseError('resource_limit')
                page_count=d.page_count
                start,end=(rng['start'],rng['end']) if rng else (1,page_count)
                end=min(end,page_count)
                units=[('page',str(i),[('pdftext',p.get_text('blocks'))],(p.rect.width,p.rect.height),i) for i in range(start,end+1) for p in [d.load_page(i-1)]]
        except ParseError:raise
        except Exception:raise ParseError('malformed_document','extract')
        # OCR auto is decided per selected page.  Counting non-whitespace
        # characters avoids treating layout whitespace or a tiny stray label as
        # an adequately textual page.
        deficient=[]
        if ocr=='auto':
            for unit in units:
                chars=sum(len(re.sub(r'\s+', '', str(block[4])))
                          for typ,blocks in unit[2] if typ=='pdftext' for block in blocks)
                if chars<20:deficient.append(unit[4])
        pages=list(range(start,end+1)) if ocr=='force' else deficient
        if pages:
            if ocr_adapter is None:
                from .adapters import OcrAdapter
                ocr_adapter=OcrAdapter()
            try:
                if hasattr(ocr_adapter,'extract_pdf_pages'):
                    ocr_units=ocr_adapter.extract_pdf_pages(path,hints,pages)
                else:
                    # Compatibility for injected adapters: coalesce adjacent
                    # deficient pages while never including an adequate page.
                    ranges=[]
                    for page in pages:
                        if ranges and page==ranges[-1][1]+1:ranges[-1]=(ranges[-1][0],page)
                        else:ranges.append((page,page))
                    ocr_units=[]
                    for page_range in ranges:
                        ocr_units.extend(ocr_adapter.extract_pdf(path,hints,page_range))
                by_page={int(unit[4] if len(unit)>4 else unit[1]):unit[2] for unit in ocr_units}
                if len(by_page)!=len(ocr_units) or set(by_page)!=set(pages):
                    raise ValueError('OCR adapter returned an invalid page set')
                # Retain native dimensions/index metadata while replacing only
                # the content of pages selected for OCR.
                units=[(unit[0],unit[1],by_page.get(unit[4],unit[2]),*unit[3:]) for unit in units]
            except Exception as exc:
                from .adapters import ExternalToolError
                if not isinstance(exc,ExternalToolError):raise ParseError('parser_failed','ocr')
                mapping={'ocr_timeout':'timeout','ocr_output_limit':'output_limit','ocr_page_limit':'resource_limit','ocr_pixel_limit':'resource_limit','ocr_resource_limit':'resource_limit','unsupported_ocr_language':'invalid_request'}
                raise ParseError(mapping.get(exc.code,'parser_failed'),'ocr')
    elif fmt=='docx':
        from docx import Document
        try:
            source=path
            if any(w.get('code')=='active_content_present' for w in warnings):
                # python-docx rejects the macro-enabled main content type even
                # though the XML vocabulary is identical; normalize in memory,
                # never executing or exposing the VBA part.
                out=io.BytesIO()
                with zipfile.ZipFile(path) as zin, zipfile.ZipFile(out,'w') as zout:
                    for info in zin.infolist():
                        if info.filename.lower().endswith(('vbaproject.bin','macros.xml')):continue
                        data=zin.read(info)
                        if info.filename=='[Content_Types].xml':data=data.replace(b'application/vnd.ms-word.document.macroEnabled.main+xml',b'application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml')
                        zout.writestr(info,data)
                out.seek(0);source=out
            d=Document(source); content=[('text',p.text) for p in d.paragraphs if p.text]
            content += [('table',[[c.text for c in row.cells] for row in table.rows]) for table in d.tables]
            units=[('page','1',content)]
        except Exception:raise ParseError('malformed_document','extract')
    elif fmt=='xlsx':
        from openpyxl import load_workbook
        try:
            with path.open('rb') as stream:
             wb=load_workbook(stream,read_only=True,data_only=False,keep_links=False)
             try:
              if len(wb.sheetnames)>limits.max_sheets:raise ParseError('resource_limit')
              units=[]; visited_cells=0
              formula_count=external_formula=dde_formula=0
              start,end=(rng['start'],rng['end']) if rng else (1,len(wb.worksheets))
              for wi,ws in enumerate(wb.worksheets,1):
                if wi<start or wi>end:continue
                rows=[]
                for ri,row in enumerate(ws.iter_rows(values_only=False),1):
                    if ri>limits.max_rows_per_sheet:raise ParseError('resource_limit')
                    vals=[]
                    for ci,c in enumerate(row,1):
                        visited_cells += 1
                        if visited_cells>limits.max_cells:raise ParseError('resource_limit')
                        if ci>limits.max_columns:raise ParseError('resource_limit')
                        if c.data_type=='f':
                            formula_count+=1; formula=str(c.value or '')
                            if re.search(r'\[[^\]]+\]',formula):external_formula+=1
                            if re.search(r"(?i)(?:^|=)\s*[^=]+\|[^!]+!",formula):dde_formula+=1
                        vals.append((c.value,c.value if c.data_type=='f' else None))
                    rows.append(vals)
                units.append(('sheet',ws.title,[('celltable',rows)],ws.sheet_state!='visible',wi))
              for code,count in (('formula_cache_unavailable',formula_count),('external_formula_ignored',external_formula),('dde_formula_ignored',dde_formula)):
                if count:warnings.append({'code':code,'count':count})
             finally: wb.close()
        except ParseError:raise
        except Exception:raise ParseError('malformed_document','extract')
    elif fmt=='pptx':
        from pptx import Presentation
        try:
            p=Presentation(path)
            if len(p.slides)>limits.max_slides:raise ParseError('resource_limit')
            units=[]
            start,end=(rng['start'],rng['end']) if rng else (1,len(p.slides))
            for i,slide in enumerate(p.slides,1):
                if i<start or i>end:continue
                content=[]
                for sh in slide.shapes:
                    if getattr(sh,'has_table',False):content.append(('table',[[c.text for c in row.cells] for row in sh.table.rows]))
                    elif hasattr(sh,'text') and sh.text:content.append(('text',sh.text))
                try:
                    nt=slide.notes_slide.notes_text_frame.text
                    if nt.strip():content.append(('note',nt))
                except Exception:pass
                units.append(('slide',str(i),content,None,i))
        except ParseError:raise
        except Exception:raise ParseError('malformed_document','extract')
    elif fmt in {'doc','xls','ppt','ole'}:
        if tika_adapter is None:
            from .adapters import TikaAdapter
            tika_adapter=TikaAdapter()
        try:units=[('page','1',[('text',tika_adapter.extract(path))])]
        except Exception as exc:
            from .adapters import ExternalToolError
            if isinstance(exc,ExternalToolError):
                mapping={'tika_timeout':'timeout','tika_output_limit':'output_limit'}
                raise ParseError(mapping.get(exc.code,'parser_failed'),'extract')
            raise ParseError('parser_failed','extract')
    else:
        units=_extract_odf(path,fmt,limits,rng)
    return _records(path,fmt,request_id,units,warnings,options,limits)

def _extract_odf(path,fmt,limits,rng=None):
    from odf.opendocument import load
    from odf import teletype
    from odf.table import Table,TableCell,TableRow
    from odf.draw import Page
    try:d=load(str(path))
    except Exception:raise ParseError('malformed_document','extract')
    if fmt=='odt':return [('page','1',[('text',teletype.extractText(d.text))])]
    if fmt=='ods':
        out=[]
        tables=d.spreadsheet.getElementsByType(Table)
        if len(tables)>limits.max_sheets:raise ParseError('resource_limit')
        start,end=(rng['start'],rng['end']) if rng else (1,len(tables))
        for i,t in enumerate(tables,1):
            if i<start or i>end:continue
            rows=[]
            cells_total=0
            for row in t.getElementsByType(TableRow):
                rr=int(row.getAttribute('numberrowsrepeated') or 1);logical=[]
                for c in row.getElementsByType(TableCell):
                    cr=int(c.getAttribute('numbercolumnsrepeated') or 1)
                    if len(logical)+cr>limits.max_columns:raise ParseError('resource_limit')
                    logical.extend([teletype.extractText(c)]*cr)
                if len(rows)+rr>limits.max_rows_per_sheet or cells_total+rr*len(logical)>limits.max_cells:raise ParseError('resource_limit')
                rows.extend([list(logical) for _ in range(rr)]);cells_total+=rr*len(logical)
            out.append(('sheet',t.getAttribute('name') or str(i),[('table',rows)],False,i))
        return out
    pages=d.presentation.getElementsByType(Page)
    if len(pages)>limits.max_slides:raise ParseError('resource_limit')
    start,end=(rng['start'],rng['end']) if rng else (1,len(pages))
    return [('slide',str(i),[('text',teletype.extractText(p))],None,i) for i,p in enumerate(pages,1) if start<=i<=end]

def _split_text_record(raw, cap=48000):
    """Split text so every JSON string payload stays under a byte budget."""
    parts=[];start=0
    while start<len(raw):
        lo,hi=1,min(len(raw)-start,cap)
        while lo<hi:
            mid=(lo+hi+1)//2
            if len(json.dumps(raw[start:start+mid],ensure_ascii=False).encode())<=cap:lo=mid
            else:hi=mid-1
        parts.append(raw[start:start+lo]);start+=lo
    return parts or [raw]


def _records(path,fmt,rid,units,warnings,options,limits):
    kind=units[0][0] if units else ('sheet' if fmt in {'xlsx','ods'} else 'slide' if fmt in {'pptx','odp'} else 'page')
    rec=[{'schema':SCHEMA,'type':'document','request_id':rid,'document':{'detected_format':fmt,'media_type':MEDIA[fmt],'size_bytes':path.stat().st_size,'title':None,'language':None},'parser':{'bundle_version':BUNDLE,'registry_version':1},'structure':{'unit':kind,'unit_count':len(units),'pagination':'native' if fmt=='pdf' else 'logical'},'warnings':warnings}]
    textn=tabn=cellsn=0; ids={'text':0,'table':0,'note':0}; truncated=False; reason=None
    rng=options.get('range'); include=set(options.get('include',['text','tables','notes'])); maxrec=options.get('max_records',limits.max_records)
    record_offset=options.get('record_offset',0);unit_offset=options.get('unit_offset',0)
    if type(maxrec) is not int or not 1<=maxrec<=500 or type(record_offset) is not int or record_offset<0 or type(unit_offset) is not int or unit_offset<0:raise ParseError('invalid_request')
    seen_content=0
    for ordinal,u in enumerate(units,1):
        uk,label,content,*meta=u
        ui=meta[1] if len(meta)>1 and isinstance(meta[1],int) else ordinal
        if rng and rng.get('unit')==uk and not rng['start']<=ui<=rng['end']:continue
        label,_=_clean(label,256)
        unit={'schema':SCHEMA,'type':'unit','id':f'u{ui}','unit_kind':uk,'index':ui,'label':label,'parent_id':None}
        if meta and meta[0] is not None and uk=='page':unit['dimensions']={'width_pt':meta[0][0],'height_pt':meta[0][1]}
        if meta and uk=='sheet':unit['hidden']=meta[0]
        unit_added=False; order=0
        def append_content(row):
            nonlocal seen_content,unit_added,truncated,reason
            seen_content+=1
            if seen_content<=record_offset:return False
            if not unit_added:
                if len(rec)>=maxrec:truncated=True;reason='records';return True
                rec.append(unit);unit_added=True
            if len(rec)>=maxrec:truncated=True;reason='records';return True
            rec.append(row);return False
        stop=False
        for typ,data in content:
            if typ=='tablechunks':
                # Keep each table record comfortably below the protocol and
                # model envelope limits. Row numbers remain absolute so chunks
                # are independently auditable and gap/overlap checks are simple.
                chunks=[];current=[]
                for row_index,row in enumerate(data,1):
                    trial=current+[row]
                    # Size the actual normalized cell objects, including display/raw
                    # duplication and JSON escaping, rather than source CSV bytes.
                    trial_cells=[]
                    for r_index,r_values in enumerate(trial,row_index-len(trial)+1):
                        for c_index,value in enumerate(r_values[:limits.max_columns],1):
                            trial_cells.append({'r':r_index,'c':c_index,'row_span':1,'col_span':1,'value':_value(value),'formula':None})
                    estimated=len(json.dumps(trial_cells,ensure_ascii=False,separators=(',',':')).encode())
                    if current and (len(current)>=128 or estimated>40*1024):
                        chunks.append((row_index-len(current),row_index-1,current));current=[row]
                    elif not current and estimated>40*1024:
                        raise ParseError('output_limit','output')
                    else:current=trial
                if current:chunks.append((len(data)-len(current)+1,len(data),current))
                for row_start,row_end,chunk_rows in chunks:
                    ids['table']+=1;cells=[];cols=0;table_text=0
                    for ri,row in enumerate(chunk_rows,row_start):
                        cols=max(cols,len(row))
                        for ci,x in enumerate(row[:limits.max_columns],1):
                            if cellsn+len(cells)+1>limits.max_cells:raise ParseError('resource_limit','extract')
                            val=_value(x);charge=sum(len(y or '') for y in (val['display'],val['raw']))
                            if textn+table_text+charge>limits.max_text_chars:raise ParseError('resource_limit','extract')
                            table_text+=charge;cells.append({'r':ri,'c':ci,'row_span':1,'col_span':1,'value':val,'formula':None})
                    order+=1
                    r={'schema':SCHEMA,'type':'table','id':f"t{ids['table']}",'unit_id':f'u{ui}','order':order,'caption':None,'row_count':len(chunk_rows),'row_start':row_start,'row_end':row_end,'column_count':cols,'columns':[{'index':i,'label':None} for i in range(1,cols+1)],'cells':cells,'truncated':False}
                    textn+=table_text;cellsn+=len(cells);tabn+=1
                    if append_content(r):stop=True;break
                if stop:break
            elif typ in {'text','pdftext','ocrtext'} and 'text' in include:
                blocks=data if typ=='pdftext' else [(0,0,0,0,data)]
                for b in blocks:
                    raw=str(b[4])
                    parts=_split_text_record(raw)
                    for part in parts:
                        s,tr=_clean(part)
                        if not s:continue
                        if textn>=limits.max_text_chars:truncated=True;reason='text_chars';stop=True;break
                        if textn+len(s)>limits.max_text_chars:s=s[:limits.max_text_chars-textn];tr=True;truncated=True;reason='text_chars'
                        order+=1;ids['text']+=1
                        r={'schema':SCHEMA,'type':'text','id':f"b{ids['text']}",'unit_id':f'u{ui}','order':order,'text':s,'source':'ocr' if typ=='ocrtext' else 'native','truncated':tr or len(parts)>1}
                        if typ=='pdftext':r['bbox']=[max(0,float(x)) for x in b[:4]]
                        textn+=len(s)
                        if append_content(r):stop=True;break
                    if stop:break
            elif typ=='note' and 'notes' in include:
                s,tr=_clean(data);remain=limits.max_text_chars-textn
                if remain<=0:truncated=True;reason='text_chars';stop=True;break
                if len(s)>remain:s=s[:remain];tr=True;truncated=True;reason='text_chars'
                order+=1;ids['note']+=1
                r={'schema':SCHEMA,'type':'note','id':f"n{ids['note']}",'unit_id':f'u{ui}','order':order,'note_kind':'speaker_note','text':s,'truncated':tr}
                textn+=len(s)
                if append_content(r):stop=True;break
            elif typ in {'table','celltable'} and 'tables' in include:
                if len(data)>limits.max_rows_per_sheet or any(len(row)>limits.max_columns for row in data):raise ParseError('resource_limit','extract')
                ids['table']+=1; cells=[]; cols=0; table_text=0
                for ri,row in enumerate(data,1):
                    cols=max(cols,len(row))
                    for ci,x in enumerate(row[:limits.max_columns],1):
                        if cellsn+len(cells)+1>limits.max_cells:raise ParseError('resource_limit','extract')
                        value,formula=(x if typ=='celltable' else (x,None)); val=_value(None if formula else value); fs=_clean(formula)[0] if formula else None
                        charge=sum(len(y or '') for y in (val['display'],val['raw'],fs))
                        if textn+table_text+charge>limits.max_text_chars:raise ParseError('resource_limit','extract')
                        table_text+=charge;cells.append({'r':ri,'c':ci,'row_span':1,'col_span':1,'value':val,'formula':fs})
                order+=1
                r={'schema':SCHEMA,'type':'table','id':f"t{ids['table']}",'unit_id':f'u{ui}','order':order,'caption':None,'row_count':len(data),'column_count':cols,'columns':[{'index':i,'label':None} for i in range(1,cols+1)],'cells':cells,'truncated':False}
                textn+=table_text;cellsn+=len(cells);tabn+=1
                if append_content(r):stop=True;break
        if stop:break
        # Preserve structural units even when blank or fully filtered by include.
        # On continuation pages these units were already emitted by the initial
        # page and history validates/deduplicates the repeated definition.
        if not unit_added:
            # Structural units are paged by absolute unit index independently of
            # content offset. Emit only units at/after the unit containing the
            # next content record; this preserves trailing blanks without
            # duplicating earlier blank units across continuation pages.
            content_positions=[]
            for pos,candidate_unit in enumerate(units,1):
                if rng and rng.get('unit')==candidate_unit[0] and not rng['start']<=pos<=rng['end']:continue
                included=0
                for candidate_type,candidate_data in candidate_unit[2]:
                    if candidate_type in {'text','pdftext','ocrtext'} and 'text' in include:
                        vals=candidate_data if candidate_type=='pdftext' else [(0,0,0,0,candidate_data)]
                        included+=sum(len(_split_text_record(str(v[4]))) for v in vals if _clean(v[4])[0])
                    elif candidate_type=='note' and 'notes' in include:included+=bool(_clean(candidate_data)[0])
                    elif candidate_type in {'table','celltable','tablechunks'} and 'tables' in include:included+=1
                content_positions.append(included)
            before=sum(content_positions[:ordinal-1]);here=content_positions[ordinal-1] if ordinal-1<len(content_positions) else 0
            if before+here>=record_offset and ui>unit_offset:
                if len(rec)>=maxrec:truncated=True;reason='records';break
                rec.append(unit)
    def counts(rows):
        return {'units_emitted':sum(r['type']=='unit' for r in rows),'records_emitted':len(rows)+1,'text_chars':sum(len(r.get('text','')) for r in rows if r['type'] in {'text','note'}),'tables':sum(r['type']=='table' for r in rows),'cells':sum(len(r.get('cells',[])) for r in rows if r['type']=='table')}
    end={'schema':SCHEMA,'type':'end','request_id':rid,'status':'ok','counts':counts(rec),'truncated':truncated,'limit_reason':reason,'warnings':warnings}
    rec.append(end)
    encode=lambda rows:sum(len((json.dumps(x,ensure_ascii=False,separators=(',',':'))+'\n').encode()) for x in rows)
    while encode(rec)>limits.max_output_bytes and len(rec)>2:
        rec.pop(-2);end['truncated']=True;end['limit_reason']='output_bytes';end['counts']=counts(rec[:-1])
    if encode(rec)>limits.max_output_bytes:
        error={'schema':SCHEMA,'type':'error','request_id':rid,'status':'error','code':'output_limit','retryable':False,'stage':'output'}
        return [error] if encode([error])<=limits.max_output_bytes else []
    return rec
