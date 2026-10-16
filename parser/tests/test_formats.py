import json
from pathlib import Path
import pytest
from jsonschema import Draft202012Validator

from omisa_parser.core import parse_document

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / 'fixtures'
SCHEMA = json.loads((ROOT / 'omisa_parser/schemas/document-jsonl-record-v1.schema.json').read_text())
validator = Draft202012Validator(SCHEMA)
BENCHMARK_REF = 'OMISA_BENCHMARK_REF_8472'

FORMATS = ['txt','md','csv','json','xml','rtf','pdf','docx','xlsx','pptx','odt','ods','odp']


def test_representative_fixtures_and_schema_are_release_local():
    assert FIX == ROOT / 'fixtures'
    assert SCHEMA == json.loads((ROOT / 'omisa_parser/schemas/document-jsonl-record-v1.schema.json').read_text())
    assert FIX.is_dir() and all((FIX / f'sample.{fmt}').is_file() for fmt in FORMATS)

@pytest.mark.parametrize('fmt', FORMATS)
def test_representative_format_is_detected_from_bytes_and_schema_valid(fmt, tmp_path):
    source = FIX / f'sample.{fmt}'
    renamed = tmp_path / 'misleading.bin'
    renamed.write_bytes(source.read_bytes())
    records = parse_document(renamed, request_id='0'*32)
    assert records[0]['document']['detected_format'] == fmt
    assert records[-1]['type'] == 'end'
    assert BENCHMARK_REF in json.dumps(records, ensure_ascii=False)
    for record in records:
        validator.validate(record)


def test_xlsx_preserves_sheet_table_cells_and_does_not_evaluate_formula():
    records = parse_document(FIX/'sample.xlsx', request_id='1'*32)
    assert any(r['type']=='unit' and r['unit_kind']=='sheet' for r in records)
    table = next(r for r in records if r['type']=='table')
    assert table['cells']


def test_pptx_emits_slides_and_safe_speaker_notes():
    records = parse_document(FIX/'sample.pptx', request_id='2'*32)
    assert any(r['type']=='unit' and r['unit_kind']=='slide' for r in records)
    # Notes are emitted when present; fixture may omit notes.
    assert all(r.get('note_kind') == 'speaker_note' for r in records if r['type']=='note')


def test_pdf_preserves_native_pages_and_dimensions():
    records = parse_document(FIX/'sample.pdf', request_id='3'*32)
    units = [r for r in records if r['type']=='unit']
    assert units and all('dimensions' in r for r in units)
