"""Reading the JSONL audit log, shared by the verifier, exporters, and signals."""

from __future__ import annotations

import pytest

from mcp_auth_gateway.audit.log import CorruptRecord, iter_records


def test_iter_records_numbers_lines_and_skips_blank_and_corrupt(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text('{"a":1}\n\n   \n{not json\n{"a":2}\n', encoding="utf-8")
    assert list(iter_records(log)) == [(1, {"a": 1}), (5, {"a": 2})]


def test_iter_records_strict_reports_the_first_bad_line(tmp_path):
    log = tmp_path / "audit.log"
    log.write_text('{"a":1}\n{not json\n{"a":2}\n', encoding="utf-8")
    it = iter_records(log, skip_corrupt=False)
    assert next(it) == (1, {"a": 1})
    with pytest.raises(CorruptRecord) as info:
        next(it)
    assert info.value.lineno == 2
    assert str(info.value).startswith("line 2: not valid JSON (")


def test_iter_records_absent_file_yields_nothing(tmp_path):
    assert list(iter_records(tmp_path / "missing.log")) == []
