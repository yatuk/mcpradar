"""Ed25519 snapshot provenance and CLI tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from typer.testing import CliRunner

from mcpradar.cli import app
from mcpradar.snapshot import (
    SnapshotSignatureError,
    generate_keypair,
    sign_snapshot,
    verify_snapshot,
)


def _keys(tmp_path: Path, prefix: str = "key") -> tuple[Path, Path]:
    private = tmp_path / f"{prefix}.pem"
    public = tmp_path / f"{prefix}.pub.pem"
    generate_keypair(private, public)
    return private, public


def test_signed_snapshot_round_trip_and_deterministic_provenance(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    payload = {"report_schema_version": "1.1", "target": "demo", "findings": []}
    envelope = sign_snapshot(
        payload,
        private,
        signed_at=datetime(2026, 7, 18, 12, tzinfo=UTC),
    )
    assert verify_snapshot(envelope, public) == payload
    assert envelope["provenance"]["signed_at"] == "2026-07-18T12:00:00+00:00"
    assert envelope["signature"]["algorithm"] == "Ed25519"


def test_tampering_and_wrong_signer_are_rejected(tmp_path: Path) -> None:
    private, public = _keys(tmp_path, "one")
    _other_private, other_public = _keys(tmp_path, "two")
    envelope = sign_snapshot({"target": "before"}, private)
    envelope["payload"]["target"] = "after"
    with pytest.raises(SnapshotSignatureError, match="digest"):
        verify_snapshot(envelope, public)
    envelope = sign_snapshot({"target": "before"}, private)
    with pytest.raises(SnapshotSignatureError, match="expected key"):
        verify_snapshot(envelope, other_public)


def test_keygen_refuses_overwrite_and_invalid_keys(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    with pytest.raises(SnapshotSignatureError, match="overwrite"):
        generate_keypair(private, public)
    invalid = tmp_path / "invalid.pem"
    invalid.write_text("not a key", encoding="utf-8")
    with pytest.raises(SnapshotSignatureError, match="private key"):
        sign_snapshot({}, invalid)


def test_snapshot_cli_keygen_sign_verify_extract(tmp_path: Path) -> None:
    runner = CliRunner()
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    result = runner.invoke(
        app,
        [
            "snapshot",
            "keygen",
            "--private-key",
            str(private),
            "--public-key",
            str(public),
        ],
    )
    assert result.exit_code == 0, result.output
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"target": "demo", "findings": []}), encoding="utf-8")
    envelope = tmp_path / "signed.json"
    result = runner.invoke(
        app,
        [
            "snapshot",
            "sign",
            "--private-key",
            str(private),
            "--report",
            str(report),
            "--output",
            str(envelope),
        ],
    )
    assert result.exit_code == 0, result.output
    extracted = tmp_path / "verified.json"
    result = runner.invoke(
        app,
        [
            "snapshot",
            "verify",
            str(envelope),
            "--public-key",
            str(public),
            "--extract",
            str(extracted),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(extracted.read_text(encoding="utf-8"))["target"] == "demo"
