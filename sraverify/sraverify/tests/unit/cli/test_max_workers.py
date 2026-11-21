"""``--max-workers``: rejected by argparse when not a positive integer, else forwarded."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sraverify import scanner as scanner_module
from sraverify.tests.unit.cli.test_exit_codes import _run_cli
from sraverify.tests.unit.cli.test_exit_codes_scan import _PROBE_REGION, probe_scan  # noqa: F401


@pytest.mark.parametrize("value", ["0", "-1", "abc", "1.5", ""])
def test_an_invalid_max_workers_exits_2_before_a_session_or_a_file(
    value: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    sessions: list[dict[str, Any]] = []
    monkeypatch.setattr(scanner_module, "get_session", lambda **kwargs: sessions.append(kwargs))

    status = _run_cli(monkeypatch, ["--max-workers", value, "--regions", _PROBE_REGION])

    assert status == 2
    assert sessions == []
    assert list(tmp_path.iterdir()) == []
    assert "argument --max-workers:" in capsys.readouterr().err


@pytest.mark.usefixtures("probe_scan")
@pytest.mark.parametrize(
    "argv,expected",
    [
        pytest.param([], 1, id="default"),
        pytest.param(["--max-workers", "3"], 3, id="explicit"),
    ],
)
def test_max_workers_reaches_run_checks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    argv: list[str],
    expected: int,
) -> None:
    seen: list[Any] = []
    real = scanner_module.SRAVerify.run_checks

    def spy(self: Any, *args: Any, **kwargs: Any) -> Any:
        seen.append(kwargs.get("max_workers"))
        return real(self, *args, **kwargs)

    monkeypatch.setattr(scanner_module.SRAVerify, "run_checks", spy)
    output = tmp_path / "findings.csv"

    status = _run_cli(monkeypatch, ["--regions", _PROBE_REGION, "--output", str(output), *argv])

    assert status == 0
    assert seen == [expected]
    assert output.exists()
