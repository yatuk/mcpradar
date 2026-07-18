"""Ed25519 snapshot envelopes with deterministic payload canonicalization."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from mcpradar import __version__

_ENVELOPE_SCHEMA = "https://mcpradar.dev/schema/signed-snapshot/v1"


class SnapshotSignatureError(ValueError):
    """Snapshot provenance or signature verification failed."""


def generate_keypair(private_path: Path, public_path: Path) -> None:
    """Generate a PEM-encoded Ed25519 keypair without overwriting files."""
    if private_path.exists() or public_path.exists():
        raise SnapshotSignatureError("refusing to overwrite an existing key file")
    private_key = Ed25519PrivateKey.generate()
    private_path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private_path.chmod(0o600)
    public_path.write_bytes(
        private_key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def sign_snapshot(
    payload: dict[str, Any],
    private_key_path: Path,
    *,
    signed_at: datetime | None = None,
) -> dict[str, Any]:
    """Wrap a report payload in a self-contained Ed25519 signature envelope."""
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    public_raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    canonical = _canonical_bytes(payload)
    signature = private_key.sign(canonical)
    timestamp = (signed_at or datetime.now(UTC)).astimezone(UTC).isoformat()
    return {
        "$schema": _ENVELOPE_SCHEMA,
        "payload": payload,
        "provenance": {
            "scanner": "mcpradar",
            "scanner_version": __version__,
            "report_schema_version": str(payload.get("report_schema_version", "unknown")),
            "target": str(payload.get("target", "")),
            "signed_at": timestamp,
            "payload_sha256": hashlib.sha256(canonical).hexdigest(),
        },
        "signature": {
            "algorithm": "Ed25519",
            "key_id": hashlib.sha256(public_raw).hexdigest()[:24],
            "public_key": base64.b64encode(public_raw).decode("ascii"),
            "value": base64.b64encode(signature).decode("ascii"),
        },
    }


def verify_snapshot(
    envelope: dict[str, Any],
    public_key_path: Path | None = None,
) -> dict[str, Any]:
    """Verify schema, digest, embedded key identity, and Ed25519 signature."""
    if envelope.get("$schema") != _ENVELOPE_SCHEMA:
        raise SnapshotSignatureError("unsupported signed snapshot schema")
    payload = envelope.get("payload")
    provenance = envelope.get("provenance")
    signature = envelope.get("signature")
    if not isinstance(payload, dict) or not isinstance(provenance, dict):
        raise SnapshotSignatureError("snapshot payload or provenance is malformed")
    if not isinstance(signature, dict) or signature.get("algorithm") != "Ed25519":
        raise SnapshotSignatureError("snapshot signature metadata is malformed")
    try:
        embedded_raw = base64.b64decode(str(signature["public_key"]), validate=True)
        signature_raw = base64.b64decode(str(signature["value"]), validate=True)
        embedded_key = Ed25519PublicKey.from_public_bytes(embedded_raw)
    except (KeyError, ValueError, TypeError):
        raise SnapshotSignatureError("snapshot signature encoding is invalid") from None
    key_id = hashlib.sha256(embedded_raw).hexdigest()[:24]
    if signature.get("key_id") != key_id:
        raise SnapshotSignatureError("snapshot key identity does not match public key")
    if public_key_path is not None:
        expected = _load_public_key(public_key_path).public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if expected != embedded_raw:
            raise SnapshotSignatureError("snapshot was not signed by the expected key")
    canonical = _canonical_bytes(payload)
    digest = hashlib.sha256(canonical).hexdigest()
    if provenance.get("payload_sha256") != digest:
        raise SnapshotSignatureError("snapshot payload digest mismatch")
    try:
        embedded_key.verify(signature_raw, canonical)
    except InvalidSignature:
        raise SnapshotSignatureError("snapshot signature is invalid") from None
    return payload


def _canonical_bytes(payload: dict[str, Any]) -> bytes:
    try:
        return json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise SnapshotSignatureError(f"snapshot payload is not canonical JSON: {exc}") from None


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError):
        raise SnapshotSignatureError("cannot load Ed25519 private key") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise SnapshotSignatureError("private key is not Ed25519")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError):
        raise SnapshotSignatureError("cannot load Ed25519 public key") from None
    if not isinstance(key, Ed25519PublicKey):
        raise SnapshotSignatureError("public key is not Ed25519")
    return key
