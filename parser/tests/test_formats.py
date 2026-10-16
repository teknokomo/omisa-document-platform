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


@pytest.mark.parametrize('heading', [
    '# Document processing: engineering, language design, and implementation',
    '# **Architecture, formal specification, and implementation plan**',
])
def test_markdown_heading_with_commas_is_not_misclassified_as_csv(heading, tmp_path):
    source = tmp_path / 'misleading.bin'
    source.write_text(f'{heading}\n\nThis is ordinary Markdown prose.\nA second paragraph follows.\n')

    records = parse_document(source, request_id='4'*32)

    assert records[0]['document']['detected_format'] == 'md'
    assert not any(record['type'] == 'table' for record in records)


def test_large_markdown_heading_with_commas_is_detected_as_markdown(tmp_path):
    target_size = 800_000
    heading = '# **Architecture, formal specification, and implementation plan**\n\n'.encode()
    paragraph = b'Ordinary Markdown prose without tabular delimiters.\n\n'
    body = paragraph * ((target_size - len(heading)) // len(paragraph))
    body += b'x' * (target_size - len(heading) - len(body))
    source = tmp_path / 'large.bin'
    source.write_bytes(heading + body)

    records = parse_document(source, request_id='5'*32)

    assert source.stat().st_size == target_size
    assert records[0]['document']['detected_format'] == 'md'
    assert not any(record['type'] == 'table' for record in records)


@pytest.mark.parametrize('contents', [
    'name,notes\nAlpha,"research, development"\nBeta,"quoted value"\n',
    'name\tnotes\nAlpha\tresearch and development\nBeta\tquoted value\n',
    'name;notes\nAlpha;research and development\nBeta;quoted value\n',
    'item,notes\n1. First step,alpha\n2. Second step,beta\n',
])
def test_consistent_delimited_rows_are_still_detected_as_csv(contents, tmp_path):
    source = tmp_path / 'misleading.bin'
    source.write_text(contents)

    records = parse_document(source, request_id='6'*32)

    assert records[0]['document']['detected_format'] == 'csv'
    table = next(record for record in records if record['type'] == 'table')
    assert table['column_count'] == 2


def test_unstructured_markdown_list_with_commas_is_not_misclassified_as_csv(tmp_path):
    source = tmp_path / 'misleading.bin'
    source.write_text('- First item, with details\n- Second item has additional, punctuation, and another phrase\n')

    records = parse_document(source, request_id='7'*32)

    assert records[0]['document']['detected_format'] == 'md'
    assert not any(record['type'] == 'table' for record in records)


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
