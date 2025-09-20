#!/usr/bin/env python3
"""Phase 2 - enrich Phase 1 output and emit alert streams.

The original demo used the Pathway streaming engine.  The execution
here mirrors the same transformations using the standard library so it
can run in constrained environments where the Pathway wheel is not
available (for example the execution sandbox that backs these
exercises).  The logic stays equivalent which makes it possible to
swap back to the Pathway implementation later without changing the
inputs/outputs.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 2: SOC pipeline")
    parser.add_argument(
        "--infile",
        default="unified.jsonl",
        help="Input JSONL from Phase 1 (default: unified.jsonl)",
    )
    parser.add_argument(
        "--alerts",
        default="anomalies.jsonl",
        help="Output anomalies JSONL (default: anomalies.jsonl)",
    )
    parser.add_argument(
        "--events",
        default="events_norm.jsonl",
        help="Output normalized events JSONL (default: events_norm.jsonl)",
    )
    parser.add_argument(
        "--bucket",
        type=int,
        default=30,
        help="Seconds per aggregation bucket (default: 30)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Utility functions mirroring the former Pathway UDFs
# ---------------------------------------------------------------------------

KV_RE = re.compile(r"(\w+)=([^\s]+)")

def safe_float(value: object, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def bucketize(ts: float, bucket_s: int) -> int:
    bucket_size = bucket_s if bucket_s and bucket_s > 0 else 1
    return int(ts // bucket_size)


def classify(stream: Optional[str], raw: str, parsed: Optional[dict]) -> str:
    stream_normalized = (stream or "").lower()

    if stream_normalized == "auth":
        if "Failed password" in raw:
            return "SSH_FAIL"
        if "Accepted password" in raw or "Accepted publickey" in raw:
            return "SSH_OK"

    if stream_normalized in {"kernel", "kern"}:
        if "IPT-IN:" in raw:
            return "IPT_IN"
        if "IPT-OUT:" in raw:
            return "IPT_OUT"
        if "IPT-DROP:" in raw:
            return "IPT_DROP"

    if stream_normalized in {"web_access", "nginx", "apache", "http", "access"}:
        if "HTTP/1." in raw or "HTTP/2" in raw:
            return "WEB_ACCESS"

    if stream_normalized == "app_json" and isinstance(parsed, dict):
        return "APP_EVENT"

    if stream_normalized in {"syslog", "messages"}:
        return "SYS_EVENT"

    return "OTHER"


def parse_kv(raw: str) -> Dict[str, str]:
    return {key: value for key, value in KV_RE.findall(raw)}


def extract_user_ip(raw: str) -> Tuple[str, str]:
    user, ip = "unknown", "unknown"
    failed = re.search(r"Failed password for (\S+) from ([0-9\.]+)", raw)
    if failed:
        return failed.group(1), failed.group(2)

    accepted = re.search(
        r"Accepted (?:password|publickey) for (\S+) from ([0-9\.]+)", raw
    )
    if accepted:
        return accepted.group(1), accepted.group(2)

    return user, ip


def to_severity(etype: str) -> str:
    if etype in {"SSH_FAIL", "IPT_DROP"}:
        return "high"
    if etype in {"IPT_IN", "IPT_OUT"}:
        return "medium"
    if etype in {"WEB_ACCESS", "APP_EVENT", "SYS_EVENT", "SSH_OK"}:
        return "low"
    return "low"


def format_event_msg(
    etype: str,
    user: str,
    ip: str,
    src: str,
    dst: str,
    dpt: str,
    path: str,
) -> str:
    if etype == "SSH_FAIL":
        return f"🚨 SSH failed for user={user} from {ip} ({path})"
    if etype == "SSH_OK":
        return f"✅ SSH success for user={user} from {ip} ({path})"
    if etype == "IPT_IN":
        return f"🔎 iptables IN {src}->{dst}:{dpt} ({path})"
    if etype == "IPT_OUT":
        return f"🔎 iptables OUT {src}->{dst}:{dpt} ({path})"
    if etype == "IPT_DROP":
        return f"🚨 iptables DROP {src}->{dst}:{dpt} ({path})"
    if etype == "WEB_ACCESS":
        return f"🌐 web access ({path})"
    if etype == "APP_EVENT":
        return f"🧩 app event ({path})"
    if etype == "SYS_EVENT":
        return f"🖥️ syslog event ({path})"
    return ""


def ensure_parent(path: Path) -> None:
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Core processing
# ---------------------------------------------------------------------------

def load_events(infile: Path) -> Iterator[dict]:
    with infile.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                yield json.loads(stripped)
            except json.JSONDecodeError as exc:
                print(
                    f"Skipping malformed JSON on line {line_no} of {infile}: {exc}",
                    file=sys.stderr,
                )


def enrich_event(raw_event: dict, bucket_s: int) -> dict:
    ts = safe_float(raw_event.get("ts"), 0.0)
    path = str(raw_event.get("path", ""))
    raw = str(raw_event.get("raw", ""))
    stream_raw = raw_event.get("stream")
    stream = str(stream_raw) if stream_raw is not None else ""
    parsed = raw_event.get("parsed") if isinstance(raw_event.get("parsed"), dict) else None

    bucket = bucketize(ts, bucket_s)
    etype = classify(stream, raw, parsed)
    user, ip = extract_user_ip(raw)

    # If we still have unknowns for structured logs, try to pull from JSON.
    if isinstance(parsed, dict):
        if user == "unknown":
            user = str(parsed.get("user", user))
        if ip == "unknown":
            ip = str(parsed.get("ip", ip))

    kv = parse_kv(raw)
    src = kv.get("SRC", "unknown")
    dst = kv.get("DST", "unknown")
    dpt = kv.get("DPT", "")

    return {
        "ts": ts,
        "bucket": bucket,
        "path": path,
        "raw": raw,
        "stream": stream or "other",
        "etype": etype,
        "user": user,
        "ip": ip,
        "src": src,
        "dst": dst,
        "dpt": dpt,
        "severity": to_severity(etype),
        "source": raw_event.get("source_hint", ""),
    }


def aggregate_bruteforce(events: Sequence[dict]) -> List[dict]:
    counts: Dict[Tuple[str, int], int] = defaultdict(int)
    for event in events:
        if event["etype"] == "SSH_FAIL":
            counts[(event["user"], event["bucket"])] += 1

    return [
        {
            "alert": f"🚨🚨 Brute-force suspected on user={user} (fails={fails} in window)",
        }
        for (user, _bucket), fails in counts.items()
        if fails >= 3
    ]


def aggregate_port_scans(events: Sequence[dict]) -> List[dict]:
    distinct_ports: Dict[Tuple[str, int], set] = defaultdict(set)
    for event in events:
        if event["etype"] in {"IPT_IN", "IPT_DROP"}:
            distinct_ports[(event["src"], event["bucket"])].add(event["dpt"] or "")

    alerts: List[dict] = []
    for (src, bucket), ports in distinct_ports.items():
        if len(ports) >= 10:
            alerts.append(
                {
                    "alert": f"🚨 Port-scan behavior: src={src} touched {len(ports)} ports in window",
                }
            )
    return alerts


def aggregate_exfil(events: Sequence[dict]) -> List[dict]:
    distinct_dsts: Dict[Tuple[str, int], set] = defaultdict(set)
    for event in events:
        if event["etype"] == "IPT_OUT":
            distinct_dsts[(event["src"], event["bucket"])].add(event["dst"])

    alerts: List[dict] = []
    for (src, bucket), dsts in distinct_dsts.items():
        if len(dsts) >= 20:
            alerts.append(
                {
                    "alert": f"🚨 Possible exfiltration: {src} contacted {len(dsts)} destinations in window",
                }
            )
    return alerts


def write_jsonl(path: Path, rows: Iterable[dict]) -> None:
    ensure_parent(path)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def build_pipeline(infile: str, alerts_out: str, events_out: str, bucket_s: int) -> None:
    input_path = Path(infile)
    events_path = Path(events_out)
    alerts_path = Path(alerts_out)

    enriched_events: List[dict] = []
    per_event_alerts: List[dict] = []

    for raw_event in load_events(input_path):
        enriched = enrich_event(raw_event, bucket_s)
        enriched_events.append(enriched)

        message = format_event_msg(
            enriched["etype"],
            enriched["user"],
            enriched["ip"],
            enriched["src"],
            enriched["dst"],
            enriched["dpt"],
            enriched["path"],
        )
        if message:
            per_event_alerts.append({"alert": message})

    bf_alerts = aggregate_bruteforce(enriched_events)
    scan_alerts = aggregate_port_scans(enriched_events)
    exfil_alerts = aggregate_exfil(enriched_events)

    write_jsonl(events_path, enriched_events)
    write_jsonl(alerts_path, per_event_alerts)
    write_jsonl(alerts_path.with_name(alerts_path.stem + "_bf.jsonl"), bf_alerts)
    write_jsonl(alerts_path.with_name(alerts_path.stem + "_scan.jsonl"), scan_alerts)
    write_jsonl(alerts_path.with_name(alerts_path.stem + "_exfil.jsonl"), exfil_alerts)


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    build_pipeline(args.infile, args.alerts, args.events, args.bucket)


if __name__ == "__main__":
    main()
