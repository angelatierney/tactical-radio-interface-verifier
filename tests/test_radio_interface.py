"""
Pytest suite for the Tactical Radio Interface & Verification Framework.

Verifies ICD boundary conditions:
  - ICD-REQ-01: Corrupt CRC detection
  - ICD-REQ-02: Key handshake timeout
  - ICD-REQ-03: Out-of-spec SNR parameters
  - ICD-REQ-04: Latency limit (supporting coverage)
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from src.radio_interface import (
    ICD_KEY_HANDSHAKE_TIMEOUT_MS,
    ICD_MAX_LATENCY_MS,
    ICD_MAX_SNR_DB,
    ICD_MIN_SNR_DB,
    CryptoMode,
    FrameType,
    RadioFrame,
    ValidationSeverity,
    build_valid_frame,
)
from src.verifier import (
    build_report,
    evaluate_frame,
    ingest_stream,
    write_binary_stream,
    write_report,
)


# ---------------------------------------------------------------------------
# ICD-REQ-01 — Corrupt CRC Detection
# ---------------------------------------------------------------------------


class TestCorruptCRCDetection:
    """Boundary tests for frame integrity (ICD-REQ-01)."""

    def test_valid_crc_passes(self) -> None:
        frame = build_valid_frame()
        passed, message = frame.validate_crc()
        assert passed is True
        assert "integrity OK" in message

    def test_corrupt_crc_detected(self) -> None:
        frame = build_valid_frame(corrupt_crc=True)
        passed, message = frame.validate_crc()
        assert passed is False
        assert "CRC mismatch" in message
        assert "ICD-REQ-01" in message

    def test_corrupt_crc_in_validate_all(self) -> None:
        frame = build_valid_frame(corrupt_crc=True)
        findings = frame.validate_all()
        crc_finding = next(f for f in findings if f["requirement_id"] == "ICD-REQ-01")
        assert crc_finding["severity"] == ValidationSeverity.FAIL.value
        assert crc_finding["check_name"] == "crc_integrity"

    def test_bit_flip_in_payload_invalidates_crc(self) -> None:
        """Simulated air-interface bit error in payload octets."""
        frame = build_valid_frame(payload_hex="cafebabe")
        assert frame.validate_crc()[0] is True

        mutated = frame.model_dump()
        mutated["payload"]["payload_hex"] = "cafebabf"  # single-nibble flip
        # Retain original CRC — now mismatched against mutated body
        mutated_frame = RadioFrame.model_validate(mutated)
        passed, message = mutated_frame.validate_crc()
        assert passed is False
        assert "CRC mismatch" in message


# ---------------------------------------------------------------------------
# ICD-REQ-02 — Key Handshake Timeout
# ---------------------------------------------------------------------------


class TestKeyHandshakeTimeout:
    """Boundary tests for cryptographic key-exchange timing (ICD-REQ-02)."""

    def test_handshake_within_timeout_passes(self) -> None:
        frame = build_valid_frame(
            frame_type=FrameType.KEY_EXCHANGE,
            handshake_elapsed_ms=ICD_KEY_HANDSHAKE_TIMEOUT_MS - 1.0,
        )
        passed, message = frame.validate_key_handshake()
        assert passed is True
        assert "within ICD-REQ-02" in message

    def test_handshake_at_exact_timeout_passes(self) -> None:
        """Inclusive upper bound — elapsed == timeout is still compliant."""
        frame = build_valid_frame(
            frame_type=FrameType.KEY_EXCHANGE,
            handshake_elapsed_ms=ICD_KEY_HANDSHAKE_TIMEOUT_MS,
        )
        passed, _ = frame.validate_key_handshake()
        assert passed is True

    def test_handshake_timeout_exceeded_fails(self) -> None:
        frame = build_valid_frame(
            frame_type=FrameType.KEY_EXCHANGE,
            handshake_elapsed_ms=ICD_KEY_HANDSHAKE_TIMEOUT_MS + 50.0,
        )
        passed, message = frame.validate_key_handshake()
        assert passed is False
        assert "exceeds ICD-REQ-02 timeout" in message

    def test_key_exchange_missing_timing_fails(self) -> None:
        frame = build_valid_frame(
            frame_type=FrameType.KEY_EXCHANGE,
            handshake_elapsed_ms=None,
        )
        passed, message = frame.validate_key_handshake()
        assert passed is False
        assert "missing handshake_elapsed_ms" in message

    def test_non_key_exchange_skips_handshake_check(self) -> None:
        frame = build_valid_frame(frame_type=FrameType.DATA)
        passed, message = frame.validate_key_handshake()
        assert passed is True
        assert "N/A" in message


# ---------------------------------------------------------------------------
# ICD-REQ-03 — Out-of-Spec SNR Parameters
# ---------------------------------------------------------------------------


class TestOutOfSpecSNR:
    """Boundary tests for SNR envelope (ICD-REQ-03)."""

    def test_snr_nominal_passes(self) -> None:
        frame = build_valid_frame(snr_db=25.0)
        passed, message = frame.validate_snr()
        assert passed is True
        assert "within ICD-REQ-03" in message

    def test_snr_at_minimum_boundary_passes(self) -> None:
        frame = build_valid_frame(snr_db=ICD_MIN_SNR_DB)
        assert frame.validate_snr()[0] is True

    def test_snr_at_maximum_boundary_passes(self) -> None:
        frame = build_valid_frame(snr_db=ICD_MAX_SNR_DB)
        assert frame.validate_snr()[0] is True

    def test_snr_below_minimum_fails(self) -> None:
        frame = build_valid_frame(snr_db=ICD_MIN_SNR_DB - 0.1)
        passed, message = frame.validate_snr()
        assert passed is False
        assert "below ICD minimum" in message
        assert "link unusable" in message

    def test_snr_above_maximum_fails(self) -> None:
        frame = build_valid_frame(snr_db=ICD_MAX_SNR_DB + 1.0)
        passed, message = frame.validate_snr()
        assert passed is False
        assert "exceeds ICD maximum" in message
        assert "AGC saturation" in message

    def test_snr_deeply_out_of_spec_in_validate_all(self) -> None:
        frame = build_valid_frame(snr_db=2.0)
        findings = frame.validate_all()
        snr_finding = next(f for f in findings if f["requirement_id"] == "ICD-REQ-03")
        assert snr_finding["severity"] == ValidationSeverity.FAIL.value


# ---------------------------------------------------------------------------
# ICD-REQ-04 — Latency Limit (supporting)
# ---------------------------------------------------------------------------


class TestLatencyLimit:
    """Boundary tests for receive-path latency (ICD-REQ-04)."""

    def test_latency_within_limit_passes(self) -> None:
        frame = build_valid_frame(rx_latency_ms=ICD_MAX_LATENCY_MS)
        assert frame.validate_latency()[0] is True

    def test_latency_exceeds_limit_fails(self) -> None:
        frame = build_valid_frame(rx_latency_ms=ICD_MAX_LATENCY_MS + 0.5)
        passed, message = frame.validate_latency()
        assert passed is False
        assert "exceeds ICD maximum" in message


# ---------------------------------------------------------------------------
# Schema / Crypto Guardrails
# ---------------------------------------------------------------------------


class TestSchemaGuardrails:
    """Structural ICD compliance for crypto and payload fields."""

    def test_aes_mode_requires_iv(self) -> None:
        frame = build_valid_frame(crypto_mode=CryptoMode.AES_256_GCM)
        data = frame.model_dump()
        data["crypto"]["iv_hex"] = None
        data["crc32"] = 0
        with pytest.raises(ValidationError, match="iv_hex is mandatory"):
            RadioFrame.model_validate(data)

    def test_invalid_sync_word_rejected(self) -> None:
        frame = build_valid_frame()
        data = frame.model_dump()
        data["preamble"]["sync_word_hex"] = "deadbeef"
        data["crc32"] = 0
        with pytest.raises(ValidationError, match="Sync word"):
            RadioFrame.model_validate(data)

    def test_clear_mode_allows_null_iv(self) -> None:
        frame = build_valid_frame(crypto_mode=CryptoMode.CLEAR)
        assert frame.crypto.iv_hex is None
        assert frame.validate_crc()[0] is True


# ---------------------------------------------------------------------------
# Verifier CLI Pipeline Integration
# ---------------------------------------------------------------------------


class TestVerifierPipeline:
    """End-to-end evaluation of mixed pass/fail packet streams."""

    def test_evaluate_passing_frame(self) -> None:
        frame = build_valid_frame()
        result = evaluate_frame(frame.model_dump(), index=0)
        assert result["overall_result"] == "PASS"
        assert all(f["severity"] == "PASS" for f in result["findings"])

    def test_evaluate_failing_snr_frame(self) -> None:
        frame = build_valid_frame(snr_db=5.0)
        result = evaluate_frame(frame.model_dump(), index=0)
        assert result["overall_result"] == "FAIL"
        snr = next(f for f in result["findings"] if f["requirement_id"] == "ICD-REQ-03")
        assert snr["severity"] == "FAIL"

    def test_report_aggregation(self, tmp_path: Path) -> None:
        good = build_valid_frame().model_dump()
        bad = build_valid_frame(corrupt_crc=True).model_dump()
        results = [evaluate_frame(good, 0), evaluate_frame(bad, 1)]
        report = build_report(results, Path("synthetic.json"), "json")

        assert report["summary"]["total_frames"] == 2
        assert report["summary"]["frames_passed"] == 1
        assert report["summary"]["frames_failed"] == 1
        assert report["summary"]["overall_result"] == "FAIL"
        assert report["requirements_allocation_status"]["ICD-REQ-01"] == "FAIL"
        assert report["requirements_allocation_status"]["ICD-REQ-03"] == "PASS"

        out = tmp_path / "verification_report.json"
        write_report(report, out)
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["summary"]["overall_result"] == "FAIL"

    def test_json_and_binary_ingest_roundtrip(self, tmp_path: Path) -> None:
        frames = [
            build_valid_frame().model_dump(),
            build_valid_frame(
                frame_type=FrameType.KEY_EXCHANGE,
                handshake_elapsed_ms=100.0,
            ).model_dump(),
        ]
        json_path = tmp_path / "stream.json"
        json_path.write_text(json.dumps({"frames": frames}), encoding="utf-8")
        bin_path = tmp_path / "stream.bin"
        write_binary_stream(frames, bin_path)

        json_frames = ingest_stream(json_path, "json")
        bin_frames = ingest_stream(bin_path, "binary")
        assert len(json_frames) == 2
        assert len(bin_frames) == 2
        assert json_frames[0]["preamble"]["source_node_id"] == (
            bin_frames[0]["preamble"]["source_node_id"]
        )

    def test_schema_invalid_frame_recorded_as_fail(self) -> None:
        result = evaluate_frame({"not": "a valid frame"}, index=0)
        assert result["overall_result"] == "FAIL"
        assert result["findings"][0]["requirement_id"] == "ICD-REQ-01"
        assert result["findings"][0]["check_name"] == "schema_compliance"
