import json
import subprocess
import sys

from mailtrace.cli import main
from mailtrace.report import render_json, render_text
from mailtrace.analysis import analyze_bytes
from conftest import CLEAN, SPOOFED


def _run_cli(args, tmp_path, filename="msg.eml", content=CLEAN):
    path = tmp_path / filename
    path.write_bytes(content)
    return main([str(path), *args])


def test_cli_clean_file_exits_zero(capsys, tmp_path):
    assert _run_cli([], tmp_path) == 0
    out = capsys.readouterr().out
    assert "Verdict: CLEAN" in out
    assert "203.0.113.10" in out
    assert "SPF" in out


def test_cli_spoofed_file_exits_two(capsys, tmp_path):
    assert _run_cli([], tmp_path, content=SPOOFED) == 2
    out = capsys.readouterr().out
    assert "Verdict: LIKELY SPOOFED" in out
    assert "display-name-spoof" in out


def test_cli_json_output_is_valid_json(capsys, tmp_path):
    assert _run_cli(["--json"], tmp_path) == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "clean"
    assert data["from"]["address"] == "alice@example.com"


def test_cli_trace_only_hides_findings(capsys, tmp_path):
    assert _run_cli(["--trace"], tmp_path, content=SPOOFED) == 2
    out = capsys.readouterr().out
    assert "Delivery path" in out
    assert "Findings" not in out


def test_cli_missing_file_exits_three(capsys, tmp_path):
    assert main([str(tmp_path / "nope.eml")]) == 3
    assert "mailtrace:" in capsys.readouterr().err


def test_cli_multiple_files_reports_worst_exit_code(capsys, tmp_path):
    clean = tmp_path / "clean.eml"
    clean.write_bytes(CLEAN)
    bad = tmp_path / "bad.eml"
    bad.write_bytes(SPOOFED)
    assert main([str(clean), str(bad)]) == 2
    out = capsys.readouterr().out
    assert "== " in out  # per-file headers when several files are given


def test_cli_stdin(monkeypatch, capsys):
    import io
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(CLEAN)))
    assert main([]) == 0
    assert "Verdict: CLEAN" in capsys.readouterr().out


def test_module_entrypoint_via_subprocess(tmp_path):
    import os
    from pathlib import Path
    project_root = Path(__file__).resolve().parent.parent
    path = tmp_path / "msg.eml"
    path.write_bytes(CLEAN)
    env = dict(os.environ)
    env["PYTHONPATH"] = str(project_root / "src")
    result = subprocess.run(
        [sys.executable, "-m", "mailtrace", str(path)],
        capture_output=True, text=True, cwd=project_root, env=env,
    )
    assert result.returncode == 0
    assert "Verdict: CLEAN" in result.stdout


def test_render_text_attachment_section():
    analysis = analyze_bytes(CLEAN)
    assert "(none)" in render_text(analysis)
    assert "Attachments" in render_text(analysis)


def test_render_json_round_trip():
    data = json.loads(render_json(analyze_bytes(SPOOFED)))
    assert data["from"]["name"] == "support@paypal.com"
