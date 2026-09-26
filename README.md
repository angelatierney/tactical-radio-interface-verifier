# Tactical Radio Interface & Verification Framework

SysML-aligned interface architecture and automated verification pipeline for a
**tactical Software-Defined Radio (SDR) communications node**. This repository
captures Interface Control Document (ICD) parameters for the RF Frontend,
Cryptographic Engine, and Data Payload Handler, and provides Python tooling to
validate packet timing, SNR thresholds, CRC integrity, and key-exchange
protocols against allocated system requirements.

---

## System Overview

The framework models a multi-node tactical radio mesh in which each
communications node exchanges framed PDUs over a contested RF link. Every
air-interface frame conforms to the ICD structure:

```
┌────────────┬──────────────────┬─────────────┬────────┐
│  Preamble  │ Encryption Hdr   │   Payload   │ CRC32  │
│  (sync /   │ (mode, key ID,   │ (mission    │ (FCS)  │
│   addressing)│  IV, sequence) │  application)│        │
└────────────┴──────────────────┴─────────────┴────────┘
```

The verification pipeline ingests **simulated RF packet streams** (JSON or
binary), evaluates each frame against ICD thresholds, and emits a structured
**Verification Pass/Fail Report** for requirements traceability.

| Subsystem | Responsibility |
|---|---|
| **RF Frontend** | Carrier selection, SNR measurement, receive-path latency |
| **Cryptographic Engine** | Suite-B / AES-256 cipher modes, TEK handshake timing, anti-replay |
| **Data Payload Handler** | Mission PDU encapsulation, length enforcement, payload typing |

---

## Interface Control Document (ICD) Breakdown

### ICD §3.1 — RF Frontend

| Parameter | Symbol | Constraint | Rationale |
|---|---|---|---|
| Carrier frequency | `carrier_freq_mhz` | 30–3000 MHz | VHF / UHF / L-band tactical allocation |
| Signal-to-noise ratio | `snr_db` | 10.0 ≤ SNR ≤ 40.0 dB | Link usability vs. AGC saturation |
| RX latency | `rx_latency_ms` | ≤ 50.0 ms | End-to-end demodulation budget |
| RSSI | `rssi_dbm` | Optional | Situational awareness only |

### ICD §3.2 — Cryptographic Engine

| Parameter | Symbol | Constraint | Rationale |
|---|---|---|---|
| Cipher mode | `crypto_mode` | CLEAR / AES-256-GCM / AES-256-CTR / SUITE-B | Approved tactical crypto profiles |
| Key identifier | `key_id` | 1–64 chars | TEK / KEK reference |
| Initialization vector | `iv_hex` | Mandatory for AES / Suite-B | Nonce uniqueness |
| Handshake elapsed | `handshake_elapsed_ms` | ≤ 200.0 ms | Key-exchange timeout (ICD-REQ-02) |
| Sequence number | `sequence_number` | ≥ 0 | Anti-replay counter |

### ICD §3.3 — Data Payload Handler

| Parameter | Symbol | Constraint | Rationale |
|---|---|---|---|
| Application PDU | `payload_hex` | 1–1024 octets | Mission data size envelope |
| Payload type | `payload_type` | Free-form tag | Semantic classification |

### Frame Preamble & Trailer

- **Sync word:** `AA55AA55` (fixed ICD preamble)
- **Frame types:** `DATA`, `CONTROL`, `KEY_EXCHANGE`, `HEARTBEAT`
- **CRC-32:** IEEE 802.3 polynomial over protected body (ICD-REQ-01)

---

## Requirements Allocation & Verification Matrix

| Requirement ID | Description | Allocated Subsystem | Verification Method | Automated Script / Check |
|---|---|---|---|---|
| **ICD-REQ-01** | Frame integrity — CRC32 must match protected body | Data Payload Handler / FCS | Test (T) | `RadioFrame.validate_crc()` · `tests/test_radio_interface.py::TestCorruptCRCDetection` |
| **ICD-REQ-02** | Key handshake completes within 200 ms | Cryptographic Engine | Test (T) | `RadioFrame.validate_key_handshake()` · `TestKeyHandshakeTimeout` |
| **ICD-REQ-03** | SNR within 10–40 dB envelope | RF Frontend | Test (T) | `RadioFrame.validate_snr()` · `TestOutOfSpecSNR` |
| **ICD-REQ-04** | RX latency ≤ 50 ms | RF Frontend | Test (T) | `RadioFrame.validate_latency()` · `TestLatencyLimit` |
| **ICD-REQ-05** | Payload length 1–1024 octets | Data Payload Handler | Analysis (A) / Test (T) | Pydantic `DataPayload` validators |

Batch verification of recorded streams is performed by the CLI:

```text
src/verifier.py  →  output/verification_report.json
```

The report includes a `requirements_allocation_status` roll-up that maps each
`ICD-REQ-*` identifier to `PASS`, `FAIL`, or `NOT_EVALUATED`.

---

## Repository Structure

```text
tactical-radio-interface-verifier/
├── README.md
├── pyproject.toml
├── requirements.txt
├── data/
│   ├── sample_stream.json      # Mixed pass/fail demo stream (JSON)
│   └── sample_stream.bin       # Same stream in TRIF binary framing
├── output/
│   └── .gitkeep                # verification_report.json written here
├── src/
│   ├── __init__.py
│   ├── radio_interface.py      # ICD dataclasses / Pydantic models
│   └── verifier.py             # Stream ingest CLI + report generator
└── tests/
    ├── __init__.py
    └── test_radio_interface.py # Boundary-condition pytest suite
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.10+ |
| Data models | [Pydantic v2](https://docs.pydantic.dev/) |
| CLI | [Click](https://click.palletsprojects.com/) |
| Unit test | [pytest](https://docs.pytest.org/) |
| Integrity | `zlib.crc32` (IEEE 802.3 polynomial) |

---

## Getting Started

### 1. Create a virtual environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Optional editable install (exposes the `trif-verify` console script):

```bash
pip install -e ".[dev]"
```

### 2. Run the verification CLI against the sample stream

```bash
python -m src.verifier --input data/sample_stream.json --output output/verification_report.json
```

Binary stream ingest:

```bash
python -m src.verifier --input data/sample_stream.bin --format binary
```

CLI options:

| Flag | Default | Description |
|---|---|---|
| `-i / --input` | *(required)* | Path to JSON or binary RF packet stream |
| `-f / --format` | `json` | `json` or `binary` |
| `-o / --output` | `output/verification_report.json` | Report destination |
| `--strict / --no-strict` | `--strict` | Non-zero exit if any frame fails |

### 3. Execute the pytest suite

```bash
pytest
```

Covered boundary conditions:

- Corrupt CRC detection (ICD-REQ-01)
- Key handshake timeout (ICD-REQ-02)
- Out-of-spec SNR parameters (ICD-REQ-03)
- Latency limit and schema guardrails

### 4. Interpret the Verification Report

`output/verification_report.json` contains:

- **report_metadata** — ICD revision, input stream, generation timestamp
- **summary** — overall PASS/FAIL, frame counts, pass rate
- **requirements_allocation_status** — roll-up of ICD-REQ-01..04
- **frame_results** — per-frame findings with severity and diagnostic text

---

## Binary Stream Wire Format

```text
Offset  Size  Field
0       4     Magic = "TRIF"
4       4     Body length (uint32, big-endian)
8       N     UTF-8 JSON body of one RadioFrame
…       …     Repeated for each packet
```

---

## License

Released for engineering demonstration and educational use within aerospace
systems engineering coursework and related verification lab exercises.
