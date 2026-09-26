"""
Tactical Radio Interface models and ICD-compliant validation logic.

Defines frame structures for the RF Frontend, Cryptographic Engine, and
Data Payload Handler subsystems of a Software-Defined Radio (SDR)
communications node, per the Interface Control Document (ICD).
"""

from __future__ import annotations

import struct
import zlib
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# ICD Constants — Requirements Allocation Baseline
# ---------------------------------------------------------------------------

ICD_PREAMBLE_SYNC_WORD: bytes = b"\xAA\x55\xAA\x55"
ICD_MIN_SNR_DB: float = 10.0          # ICD-REQ-03: minimum usable SNR
ICD_MAX_SNR_DB: float = 40.0          # ICD-REQ-03: upper bound (AGC saturation)
ICD_MAX_LATENCY_MS: float = 50.0      # ICD-REQ-04: end-to-end frame latency
ICD_KEY_HANDSHAKE_TIMEOUT_MS: float = 200.0  # ICD-REQ-02: crypto key exchange
ICD_MAX_PAYLOAD_BYTES: int = 1024     # ICD-REQ-05: payload size ceiling
ICD_MIN_PAYLOAD_BYTES: int = 1        # ICD-REQ-05: payload size floor
ICD_FRAME_VERSION: int = 1


class CryptoMode(str, Enum):
    """Cryptographic operating modes supported by the Crypto Engine (ICD §3.2)."""

    CLEAR = "CLEAR"
    AES_256_GCM = "AES-256-GCM"
    AES_256_CTR = "AES-256-CTR"
    SUITE_B = "SUITE-B"


class FrameType(str, Enum):
    """Tactical radio frame classification (ICD §2.1)."""

    DATA = "DATA"
    CONTROL = "CONTROL"
    KEY_EXCHANGE = "KEY_EXCHANGE"
    HEARTBEAT = "HEARTBEAT"


class ValidationSeverity(str, Enum):
    """Severity classification for verification findings."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"


# ---------------------------------------------------------------------------
# Subsystem Data Structures (ICD Breakdown)
# ---------------------------------------------------------------------------


class RFFrontendParams(BaseModel):
    """
    RF Frontend interface parameters (ICD §3.1 — RF Frontend).

    Captures physical-layer observables accompanying each received frame:
    carrier frequency, instantaneous SNR, and receive-path latency.
    """

    model_config = ConfigDict(frozen=True)

    carrier_freq_mhz: float = Field(
        ...,
        ge=30.0,
        le=3000.0,
        description="Carrier frequency in MHz (VHF/UHF/L-band tactical band).",
    )
    snr_db: float = Field(
        ...,
        description="Measured signal-to-noise ratio in dB at the demodulator.",
    )
    rx_latency_ms: float = Field(
        ...,
        ge=0.0,
        description="Receive-path processing latency in milliseconds.",
    )
    rssi_dbm: Optional[float] = Field(
        default=None,
        description="Received Signal Strength Indicator in dBm.",
    )

    def validate_snr(self) -> tuple[bool, str]:
        """
        Evaluate SNR against ICD-REQ-03 thresholds.

        Returns:
            Tuple of (is_within_spec, diagnostic_message).
        """
        if self.snr_db < ICD_MIN_SNR_DB:
            return (
                False,
                f"SNR {self.snr_db:.1f} dB below ICD minimum "
                f"({ICD_MIN_SNR_DB} dB) — link unusable.",
            )
        if self.snr_db > ICD_MAX_SNR_DB:
            return (
                False,
                f"SNR {self.snr_db:.1f} dB exceeds ICD maximum "
                f"({ICD_MAX_SNR_DB} dB) — possible AGC saturation / spoof.",
            )
        return True, f"SNR {self.snr_db:.1f} dB within ICD-REQ-03 envelope."

    def validate_latency(self) -> tuple[bool, str]:
        """
        Evaluate receive latency against ICD-REQ-04 limit.

        Returns:
            Tuple of (is_within_spec, diagnostic_message).
        """
        if self.rx_latency_ms > ICD_MAX_LATENCY_MS:
            return (
                False,
                f"RX latency {self.rx_latency_ms:.1f} ms exceeds ICD maximum "
                f"({ICD_MAX_LATENCY_MS} ms).",
            )
        return (
            True,
            f"RX latency {self.rx_latency_ms:.1f} ms within ICD-REQ-04 limit.",
        )


class CryptographicHeader(BaseModel):
    """
    Cryptographic Engine header (ICD §3.2 — Cryptographic Engine).

    Encodes key material identifiers, cipher mode, initialization vector,
    and key-handshake timing for Suite-B / AES-256 protected links.
    """

    model_config = ConfigDict(frozen=True)

    crypto_mode: CryptoMode = Field(
        ...,
        description="Active cipher suite for this frame.",
    )
    key_id: str = Field(
        ...,
        min_length=1,
        max_length=64,
        description="Cryptographic key identifier (TEK / KEK reference).",
    )
    iv_hex: Optional[str] = Field(
        default=None,
        description="Initialization vector as hexadecimal string (required for AES modes).",
    )
    handshake_elapsed_ms: Optional[float] = Field(
        default=None,
        ge=0.0,
        description="Elapsed time for key-exchange handshake in milliseconds.",
    )
    sequence_number: int = Field(
        ...,
        ge=0,
        description="Anti-replay sequence number.",
    )

    @field_validator("iv_hex")
    @classmethod
    def _validate_iv_hex(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return value
        try:
            bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"iv_hex must be valid hexadecimal: {exc}") from exc
        if len(value) < 16:
            raise ValueError("iv_hex must be at least 8 bytes (16 hex chars).")
        return value.lower()

    @model_validator(mode="after")
    def _require_iv_for_aes(self) -> CryptographicHeader:
        if self.crypto_mode in (
            CryptoMode.AES_256_GCM,
            CryptoMode.AES_256_CTR,
            CryptoMode.SUITE_B,
        ) and self.iv_hex is None:
            raise ValueError(
                f"iv_hex is mandatory for crypto_mode={self.crypto_mode.value}."
            )
        return self

    def validate_handshake_timeout(self) -> tuple[bool, str]:
        """
        Evaluate key-handshake timing against ICD-REQ-02 timeout.

        Applies only to KEY_EXCHANGE frames; returns PASS with advisory
        when handshake_elapsed_ms is not populated.

        Returns:
            Tuple of (is_within_spec, diagnostic_message).
        """
        if self.handshake_elapsed_ms is None:
            return True, "No handshake timing recorded — not a key-exchange frame."
        if self.handshake_elapsed_ms > ICD_KEY_HANDSHAKE_TIMEOUT_MS:
            return (
                False,
                f"Key handshake {self.handshake_elapsed_ms:.1f} ms exceeds "
                f"ICD-REQ-02 timeout ({ICD_KEY_HANDSHAKE_TIMEOUT_MS} ms).",
            )
        return (
            True,
            f"Key handshake {self.handshake_elapsed_ms:.1f} ms within "
            f"ICD-REQ-02 timeout.",
        )


class DataPayload(BaseModel):
    """
    Data Payload Handler structure (ICD §3.3 — Data Payload Handler).

    Contains the mission application PDU and associated metadata.
    """

    model_config = ConfigDict(frozen=True)

    payload_hex: str = Field(
        ...,
        min_length=2,
        description="Application PDU as hexadecimal string.",
    )
    payload_type: str = Field(
        default="MISSION_DATA",
        description="Semantic payload classification tag.",
    )

    @field_validator("payload_hex")
    @classmethod
    def _validate_payload_hex(cls, value: str) -> str:
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"payload_hex must be valid hexadecimal: {exc}") from exc
        if len(raw) < ICD_MIN_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload length {len(raw)} below ICD minimum "
                f"({ICD_MIN_PAYLOAD_BYTES} byte)."
            )
        if len(raw) > ICD_MAX_PAYLOAD_BYTES:
            raise ValueError(
                f"Payload length {len(raw)} exceeds ICD maximum "
                f"({ICD_MAX_PAYLOAD_BYTES} bytes)."
            )
        return value.lower()

    @property
    def payload_bytes(self) -> bytes:
        """Decoded application PDU octets."""
        return bytes.fromhex(self.payload_hex)

    @property
    def length(self) -> int:
        """Payload length in octets."""
        return len(self.payload_bytes)


class FramePreamble(BaseModel):
    """
    Physical-layer preamble and sync word (ICD §2.2 — Frame Preamble).
    """

    model_config = ConfigDict(frozen=True)

    sync_word_hex: str = Field(
        default=ICD_PREAMBLE_SYNC_WORD.hex(),
        description="Synchronization word (default AA55AA55).",
    )
    frame_version: int = Field(
        default=ICD_FRAME_VERSION,
        ge=1,
        description="ICD frame format version.",
    )
    frame_type: FrameType = Field(
        ...,
        description="Frame classification.",
    )
    source_node_id: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Originating tactical node identifier.",
    )
    destination_node_id: str = Field(
        ...,
        min_length=1,
        max_length=32,
        description="Intended destination node identifier.",
    )

    @field_validator("sync_word_hex")
    @classmethod
    def _validate_sync_word(cls, value: str) -> str:
        try:
            raw = bytes.fromhex(value)
        except ValueError as exc:
            raise ValueError(f"sync_word_hex must be valid hexadecimal: {exc}") from exc
        if raw != ICD_PREAMBLE_SYNC_WORD:
            raise ValueError(
                f"Sync word {value} does not match ICD preamble "
                f"({ICD_PREAMBLE_SYNC_WORD.hex()})."
            )
        return value.lower()


# ---------------------------------------------------------------------------
# Composite Radio Frame
# ---------------------------------------------------------------------------


class RadioFrame(BaseModel):
    """
    Complete tactical radio frame (ICD §2 — Frame Structure).

    Composition: Preamble | Encryption Header | Payload | CRC32 trailer.
    Provides integrity, SNR, and latency validation methods used by the
    verification pipeline.
    """

    model_config = ConfigDict(frozen=True)

    preamble: FramePreamble
    crypto: CryptographicHeader
    payload: DataPayload
    rf: RFFrontendParams
    crc32: int = Field(
        ...,
        ge=0,
        le=0xFFFFFFFF,
        description="CRC-32 frame check sequence (IEEE 802.3 polynomial).",
    )
    timestamp_utc: Optional[str] = Field(
        default=None,
        description="ISO-8601 UTC capture timestamp from the RF stream recorder.",
    )

    # -- Integrity ----------------------------------------------------------

    def compute_crc32(self) -> int:
        """
        Compute CRC-32 over the protected frame body.

        Covered fields (big-endian packed):
            sync_word | frame_version | frame_type | source | dest |
            crypto_mode | key_id | sequence | payload octets
        """
        body = self._protected_body()
        return zlib.crc32(body) & 0xFFFFFFFF

    def _protected_body(self) -> bytes:
        """Serialize ICD-protected octets for CRC computation."""
        parts = [
            bytes.fromhex(self.preamble.sync_word_hex),
            struct.pack(">B", self.preamble.frame_version),
            self.preamble.frame_type.value.encode("ascii"),
            self.preamble.source_node_id.encode("ascii"),
            self.preamble.destination_node_id.encode("ascii"),
            self.crypto.crypto_mode.value.encode("ascii"),
            self.crypto.key_id.encode("ascii"),
            struct.pack(">I", self.crypto.sequence_number),
            self.payload.payload_bytes,
        ]
        return b"".join(parts)

    def validate_crc(self) -> tuple[bool, str]:
        """
        Verify frame integrity against the embedded CRC32 (ICD-REQ-01).

        Returns:
            Tuple of (crc_valid, diagnostic_message).
        """
        expected = self.compute_crc32()
        if self.crc32 != expected:
            return (
                False,
                f"CRC mismatch: received 0x{self.crc32:08X}, "
                f"computed 0x{expected:08X} — frame corrupt (ICD-REQ-01).",
            )
        return True, f"CRC32 0x{self.crc32:08X} verified — frame integrity OK."

    def validate_snr(self) -> tuple[bool, str]:
        """Delegate SNR check to RF Frontend parameters (ICD-REQ-03)."""
        return self.rf.validate_snr()

    def validate_latency(self) -> tuple[bool, str]:
        """Delegate latency check to RF Frontend parameters (ICD-REQ-04)."""
        return self.rf.validate_latency()

    def validate_key_handshake(self) -> tuple[bool, str]:
        """
        Validate key-handshake timeout when frame is a KEY_EXCHANGE type.

        For non-key-exchange frames, returns PASS with advisory.
        """
        if self.preamble.frame_type != FrameType.KEY_EXCHANGE:
            return True, "Not a KEY_EXCHANGE frame — handshake check N/A."
        if self.crypto.handshake_elapsed_ms is None:
            return (
                False,
                "KEY_EXCHANGE frame missing handshake_elapsed_ms (ICD-REQ-02).",
            )
        return self.crypto.validate_handshake_timeout()

    def validate_all(self) -> list[dict[str, Any]]:
        """
        Execute the full ICD verification checklist against this frame.

        Returns:
            List of finding dictionaries with requirement_id, severity,
            check_name, and message fields.
        """
        checks = [
            ("ICD-REQ-01", "crc_integrity", self.validate_crc),
            ("ICD-REQ-02", "key_handshake_timeout", self.validate_key_handshake),
            ("ICD-REQ-03", "snr_threshold", self.validate_snr),
            ("ICD-REQ-04", "latency_limit", self.validate_latency),
        ]
        findings: list[dict[str, Any]] = []
        for req_id, check_name, method in checks:
            passed, message = method()
            findings.append(
                {
                    "requirement_id": req_id,
                    "check_name": check_name,
                    "severity": (
                        ValidationSeverity.PASS.value
                        if passed
                        else ValidationSeverity.FAIL.value
                    ),
                    "message": message,
                }
            )
        return findings

    @classmethod
    def from_dict_with_auto_crc(cls, data: dict[str, Any]) -> RadioFrame:
        """
        Construct a RadioFrame, auto-computing CRC32 when omitted or null.

        Useful for generating golden reference packets in test fixtures.
        """
        payload = dict(data)
        if payload.get("crc32") is None:
            # Temporary object with placeholder CRC to compute the real one
            payload["crc32"] = 0
            provisional = cls.model_validate(payload)
            payload["crc32"] = provisional.compute_crc32()
        return cls.model_validate(payload)


def build_valid_frame(
    *,
    frame_type: FrameType = FrameType.DATA,
    snr_db: float = 25.0,
    rx_latency_ms: float = 12.0,
    handshake_elapsed_ms: Optional[float] = None,
    payload_hex: str = "deadbeef",
    crypto_mode: CryptoMode = CryptoMode.AES_256_GCM,
    corrupt_crc: bool = False,
) -> RadioFrame:
    """
    Factory helper for constructing ICD-compliant (or intentionally deviant)
    frames in unit tests and simulation harnesses.
    """
    iv = "00112233445566778899aabbccddeeff" if crypto_mode != CryptoMode.CLEAR else None
    data: dict[str, Any] = {
        "preamble": {
            "sync_word_hex": ICD_PREAMBLE_SYNC_WORD.hex(),
            "frame_version": ICD_FRAME_VERSION,
            "frame_type": frame_type.value,
            "source_node_id": "NODE-ALPHA-01",
            "destination_node_id": "NODE-BRAVO-02",
        },
        "crypto": {
            "crypto_mode": crypto_mode.value,
            "key_id": "TEK-7F3A",
            "iv_hex": iv,
            "handshake_elapsed_ms": handshake_elapsed_ms,
            "sequence_number": 42,
        },
        "payload": {
            "payload_hex": payload_hex,
            "payload_type": "MISSION_DATA",
        },
        "rf": {
            "carrier_freq_mhz": 225.0,
            "snr_db": snr_db,
            "rx_latency_ms": rx_latency_ms,
            "rssi_dbm": -65.0,
        },
        "crc32": None,
        "timestamp_utc": "2026-09-26T12:00:00Z",
    }
    frame = RadioFrame.from_dict_with_auto_crc(data)
    if corrupt_crc:
        # Flip CRC bits to simulate bit-error corruption on the air interface
        corrupted = frame.model_dump()
        corrupted["crc32"] = frame.crc32 ^ 0xFFFFFFFF
        frame = RadioFrame.model_validate(corrupted)
    return frame
