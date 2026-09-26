#!/usr/bin/env python3
"""
Tactical Radio Interface Verification CLI.

Ingests simulated RF packet streams (JSON or binary) and evaluates each
frame against ICD parameters. Produces a structured Pass/Fail Verification
Report conforming to the Requirements Allocation & Verification Matrix.

Usage:
    python -m src.verifier --input data/sample_stream.json
    python -m src.verifier --input data/sample_stream.bin --format binary \\
        --output output/verification_report.json
"""

from __future__ import annotations

import json
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import click
from pydantic import ValidationError

from src.radio_interface import RadioFrame


# Default report destination relative to repository root
DEFAULT_OUTPUT = Path("output/verification_report.json")

# Binary stream framing: magic (4) | length (4 BE) | UTF-8 JSON body
BINARY_MAGIC = b"TRIF"  # Tactical Radio Interface Frame


# ---------------------------------------------------------------------------
# Stream Ingestion
# ---------------------------------------------------------------------------


def load_json_stream(path: Path) -> list[dict[str, Any]]:
    """
    Load a JSON RF packet stream.

    Accepts either a top-level list of frame objects or an object with a
    ``frames`` array key.
    """
    with path.open("r", encoding="utf-8") as handle:
        data = json.load(handle)

    if isinstance(data, list):
        return data
    if isinstance(data, dict) and "frames" in data:
        frames = data["frames"]
        if not isinstance(frames, list):
            raise ValueError("'frames' key must contain a JSON array.")
        return frames
    raise ValueError(
        "JSON stream must be an array of frames or an object with a 'frames' array."
    )


def load_binary_stream(path: Path) -> list[dict[str, Any]]:
    """
    Load a binary RF packet stream.

    Wire format (repeated):
        magic[4] = b'TRIF'
        length[4] = big-endian uint32 of following JSON body
        body[length] = UTF-8 JSON encoding of a single RadioFrame dict
    """
    frames: list[dict[str, Any]] = []
    raw = path.read_bytes()
    offset = 0
    packet_index = 0

    while offset < len(raw):
        if offset + 8 > len(raw):
            raise ValueError(
                f"Truncated binary header at offset {offset} "
                f"(packet index {packet_index})."
            )
        magic = raw[offset : offset + 4]
        if magic != BINARY_MAGIC:
            raise ValueError(
                f"Invalid magic at offset {offset}: expected {BINARY_MAGIC!r}, "
                f"got {magic!r}."
            )
        length = struct.unpack(">I", raw[offset + 4 : offset + 8])[0]
        offset += 8
        if offset + length > len(raw):
            raise ValueError(
                f"Truncated binary body at offset {offset} "
                f"(declared length {length}, packet index {packet_index})."
            )
        body = raw[offset : offset + length]
        offset += length
        frames.append(json.loads(body.decode("utf-8")))
        packet_index += 1

    return frames


def ingest_stream(path: Path, fmt: str) -> list[dict[str, Any]]:
    """Dispatch to JSON or binary loader based on ``fmt``."""
    if fmt == "json":
        return load_json_stream(path)
    if fmt == "binary":
        return load_binary_stream(path)
    raise ValueError(f"Unsupported format: {fmt}")


# ---------------------------------------------------------------------------
# Verification Engine
# ---------------------------------------------------------------------------


def evaluate_frame(
    frame_data: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    """
    Parse and evaluate a single frame against the ICD checklist.

    Schema-invalid frames are recorded as FAIL under ICD-REQ-01 (integrity /
    structural compliance) without aborting the batch.
    """
    result: dict[str, Any] = {
        "frame_index": index,
        "source_node_id": None,
        "destination_node_id": None,
        "frame_type": None,
        "overall_result": "FAIL",
        "findings": [],
    }

    try:
        frame = RadioFrame.model_validate(frame_data)
    except ValidationError as exc:
        result["findings"].append(
            {
                "requirement_id": "ICD-REQ-01",
                "check_name": "schema_compliance",
                "severity": "FAIL",
                "message": f"Frame failed ICD schema validation: {exc.error_count()} "
                f"error(s). First: {exc.errors()[0]['msg']}.",
            }
        )
        return result

    result["source_node_id"] = frame.preamble.source_node_id
    result["destination_node_id"] = frame.preamble.destination_node_id
    result["frame_type"] = frame.preamble.frame_type.value
    result["findings"] = frame.validate_all()

    failures = [f for f in result["findings"] if f["severity"] == "FAIL"]
    result["overall_result"] = "FAIL" if failures else "PASS"
    return result


def build_report(
    frame_results: list[dict[str, Any]],
    input_path: Path,
    stream_format: str,
) -> dict[str, Any]:
    """
    Assemble the structured Verification Pass/Fail Report.

    Aggregates per-frame findings and rolls up requirement-level status
    for the Requirements Allocation & Verification Matrix.
    """
    total = len(frame_results)
    passed = sum(1 for r in frame_results if r["overall_result"] == "PASS")
    failed = total - passed

    # Roll up requirement IDs across all findings
    requirement_ids = ("ICD-REQ-01", "ICD-REQ-02", "ICD-REQ-03", "ICD-REQ-04")
    req_status: dict[str, str] = {}
    for req_id in requirement_ids:
        req_findings = [
            f
            for r in frame_results
            for f in r["findings"]
            if f["requirement_id"] == req_id
        ]
        if not req_findings:
            req_status[req_id] = "NOT_EVALUATED"
        elif any(f["severity"] == "FAIL" for f in req_findings):
            req_status[req_id] = "FAIL"
        else:
            req_status[req_id] = "PASS"

    overall = "PASS" if failed == 0 and total > 0 else "FAIL"
    if total == 0:
        overall = "FAIL"

    return {
        "report_metadata": {
            "title": "Tactical Radio Interface Verification Report",
            "generated_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "input_stream": str(input_path),
            "stream_format": stream_format,
            "icd_revision": "1.0",
            "verifier_version": "1.0.0",
        },
        "summary": {
            "overall_result": overall,
            "total_frames": total,
            "frames_passed": passed,
            "frames_failed": failed,
            "pass_rate_percent": round((passed / total * 100.0), 2) if total else 0.0,
        },
        "requirements_allocation_status": req_status,
        "frame_results": frame_results,
    }


def write_report(report: dict[str, Any], output_path: Path) -> None:
    """Serialize the verification report to JSON on disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2)
        handle.write("\n")


# ---------------------------------------------------------------------------
# Binary stream writer (utility for test / simulation data generation)
# ---------------------------------------------------------------------------


def write_binary_stream(frames: list[dict[str, Any]], path: Path) -> None:
    """Encode a list of frame dictionaries into the TRIF binary wire format."""
    path.parent.mkdir(parents=True, exist_ok=True)
    chunks: list[bytes] = []
    for frame in frames:
        body = json.dumps(frame, separators=(",", ":")).encode("utf-8")
        chunks.append(BINARY_MAGIC + struct.pack(">I", len(body)) + body)
    path.write_bytes(b"".join(chunks))


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------


@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option(
    "--input",
    "-i",
    "input_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=True,
    help="Path to simulated RF packet stream (JSON or binary).",
)
@click.option(
    "--format",
    "-f",
    "stream_format",
    type=click.Choice(["json", "binary"], case_sensitive=False),
    default="json",
    show_default=True,
    help="Input stream encoding format.",
)
@click.option(
    "--output",
    "-o",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    default=DEFAULT_OUTPUT,
    show_default=True,
    help="Destination path for verification_report.json.",
)
@click.option(
    "--strict/--no-strict",
    default=True,
    show_default=True,
    help="Exit non-zero if any frame fails ICD verification.",
)
def main(
    input_path: Path,
    stream_format: str,
    output_path: Path,
    strict: bool,
) -> None:
    """
    Tactical Radio Interface & Verification Framework CLI.

    Evaluates an RF packet stream against ICD-REQ-01..04 and writes a
    structured Verification Pass/Fail Report.
    """
    stream_format = stream_format.lower()
    click.echo(
        f"[TRIF] Ingesting {stream_format.upper()} stream: {input_path}"
    )

    try:
        packets = ingest_stream(input_path, stream_format)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        click.echo(f"[TRIF] ERROR — failed to ingest stream: {exc}", err=True)
        sys.exit(2)

    click.echo(f"[TRIF] Evaluating {len(packets)} frame(s) against ICD checklist...")
    frame_results = [evaluate_frame(pkt, idx) for idx, pkt in enumerate(packets)]
    report = build_report(frame_results, input_path, stream_format)
    write_report(report, output_path)

    summary = report["summary"]
    click.echo(
        f"[TRIF] Result: {summary['overall_result']} | "
        f"{summary['frames_passed']}/{summary['total_frames']} frames passed "
        f"({summary['pass_rate_percent']}%)"
    )
    click.echo(f"[TRIF] Report written → {output_path}")

    for req_id, status in report["requirements_allocation_status"].items():
        marker = "✓" if status == "PASS" else "✗" if status == "FAIL" else "–"
        click.echo(f"  {marker} {req_id}: {status}")

    if strict and summary["overall_result"] != "PASS":
        sys.exit(1)


if __name__ == "__main__":
    main()
