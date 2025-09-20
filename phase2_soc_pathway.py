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
import pathway as pw



# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 2: Pathway SOC pipeline")
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
# Schema
# ---------------------------------------------------------------------------


class LineSchema(pw.Schema):
    path: str
    ts: float
    raw: str
    fmt: str
    parsed: dict
    stream: str
    source_hint: str


# ---------------------------------------------------------------------------
# UDFs
# ---------------------------------------------------------------------------

DEFAULT_STREAM = "other"
STREAM_ALIASES = {
    "": DEFAULT_STREAM,
    "kern": "kernel",
    "kernel": "kernel",
    "nginx": "web_access",
    "apache": "web_access",
    "http": "web_access",
    "access": "web_access",
    "messages": "syslog",
    "syslog": "syslog",
    "app": "app_json",
    "application": "app_json",
}


@pw.udf
def bucketize(ts: float, bucket_s: int) -> int:
    bucket = bucket_s if bucket_s and bucket_s > 0 else 1
    return int(ts // bucket)


@pw.udf
def normalize_stream(stream: str) -> str:
    if stream is None:
        return DEFAULT_STREAM
    key = str(stream).lower()
    return STREAM_ALIASES.get(key, key or DEFAULT_STREAM)


@pw.udf
def classify(stream_norm: str, raw: str, parsed) -> str:
    if stream_norm == "auth":
        if "Failed password" in raw:
            return "SSH_FAIL"
        if "Accepted password" in raw or "Accepted publickey" in raw:
            return "SSH_OK"
        
    if stream_norm == "kernel":
        if "IPT-IN:" in raw:
            return "IPT_IN"
        if "IPT-OUT:" in raw:
            return "IPT_OUT"
        if "IPT-DROP:" in raw:
            return "IPT_DROP"

    if stream_norm == "web_access":
        if "HTTP/1." in raw or "HTTP/2" in raw:
            return "WEB_ACCESS"

    if stream_norm == "app_json" and parsed is not None:
        return "APP_EVENT"

    if stream_norm == "syslog":
        return "SYS_EVENT"

    return "OTHER"

KV_RE = re.compile(r"(\w+)=([^\s]+)")


@pw.udf
def parse_kv(raw: str) -> dict:
    return {key: value for key, value in KV_RE.findall(raw)}


@pw.udf
def extract_user_ip(raw: str) -> tuple[str, str]:
    user, ip = "unknown", "unknown"
    failed = re.search(r"Failed password for (\S+) from ([0-9\.]+)", raw)
    if failed:
        return failed.group(1), failed.group(2)

    accepted = re.search(r"Accepted (?:password|publickey) for (\S+) from ([0-9\.]+)", raw)
    if accepted:
        return accepted.group(1), accepted.group(2)

    return user, ip

@pw.udf
def fill_user(user: str, parsed) -> str:
    if user != "unknown":
        return user
    if isinstance(parsed, dict):
        candidate = parsed.get("user") or parsed.get("username")
        if candidate:
            return str(candidate)
    return user


@pw.udf
def fill_ip(ip: str, parsed) -> str:
    if ip != "unknown":
        return ip
    if isinstance(parsed, dict):
        candidate = parsed.get("ip") or parsed.get("src_ip")
        if candidate:
            return str(candidate)
    return ip


@pw.udf
def kv_lookup(kv: dict, key: str, default: str) -> str:
    if isinstance(kv, dict):
        value = kv.get(key)
        if value:
            return str(value)
    return default


@pw.udf
def ensure_source(source_hint: str) -> str:
    if source_hint:
        return str(source_hint)
    return ""


@pw.udf
def to_severity(etype: str) -> str:
    if etype in {"SSH_FAIL", "IPT_DROP"}:
        return "high"
    if etype in {"IPT_IN", "IPT_OUT"}:
        return "medium"
    if etype in {"WEB_ACCESS", "APP_EVENT", "SYS_EVENT", "SSH_OK"}:
        return "low"
    return "low"


@pw.udf
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

@pw.udf
def nonempty(text: str) -> bool:
    return bool(text)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def build_pipeline(infile: str, alerts_out: str, events_out: str, bucket_s: int) -> None:
    stream = pw.io.jsonlines.read(infile, schema=LineSchema, mode="streaming")

    normalized = stream.select(
        ts=pw.this.ts,
        path=pw.this.path,
        raw=pw.this.raw,
        parsed=pw.this.parsed,
        stream=normalize_stream(pw.this.stream),
        source=ensure_source(pw.this.source_hint),
    )

    base = normalized.select(
        ts=pw.this.ts,
        bucket=bucketize(pw.this.ts, bucket_s),
        path=pw.this.path,
        raw=pw.this.raw,
        parsed=pw.this.parsed,
        stream=pw.this.stream,
        source=pw.this.source,
        etype=classify(pw.this.stream, pw.this.raw, pw.this.parsed),
        kv=parse_kv(pw.this.raw),
        user_ip=extract_user_ip(pw.this.raw),
    )

    enriched = base.select(
        ts=pw.this.ts,
        bucket=pw.this.bucket,
        path=pw.this.path,
        raw=pw.this.raw,
        stream=pw.this.stream,
        etype=pw.this.etype,
        user=fill_user(pw.apply(lambda pair: pair[0], pw.this.user_ip), pw.this.parsed),
        ip=fill_ip(pw.apply(lambda pair: pair[1], pw.this.user_ip), pw.this.parsed),
        src=kv_lookup(pw.this.kv, "SRC", "unknown"),
        dst=kv_lookup(pw.this.kv, "DST", "unknown"),
        dpt=kv_lookup(pw.this.kv, "DPT", ""),
        severity=to_severity(pw.this.etype),
        source=pw.this.source,
    )

    per_event_msgs = enriched.select(
        msg=format_event_msg(
            pw.this.etype,
            pw.this.user,
            pw.this.ip,
            pw.this.src,
            pw.this.dst,
            pw.this.dpt,
            pw.this.path,
        )
    )

    pw.io.jsonlines.write(enriched, events_out)

    per_event_alerts = per_event_msgs.select(alert=pw.this.msg).filter(nonempty(pw.this.alert))

    ssh_fails = enriched.filter(pw.this.etype == "SSH_FAIL")
    bf = ssh_fails.groupby(pw.this.user, pw.this.bucket).reduce(
        user=pw.this.user,
        bucket=pw.this.bucket,
        fails=pw.reducers.count(),
    ).filter(pw.this.fails >= 3).select(
        alert=pw.apply(
            lambda user, fails: f"🚨🚨 Brute-force suspected on user={user} (fails={fails} in window)",
            pw.this.user,
            pw.this.fails,
        )
    )

    ipt_in_or_drop = enriched.filter((pw.this.etype == "IPT_IN") | (pw.this.etype == "IPT_DROP"))
    scan = ipt_in_or_drop.groupby(pw.this.src, pw.this.bucket).reduce(
        src=pw.this.src,
        bucket=pw.this.bucket,
        ports=pw.reducers.count_distinct(pw.this.dpt),
    ).filter(pw.this.ports >= 10).select(
        alert=pw.apply(
            lambda src, count: f"🚨 Port-scan behavior: src={src} touched {count} ports in window",
            pw.this.src,
            pw.this.ports,
        )
    )

    ipt_out = enriched.filter(pw.this.etype == "IPT_OUT")
    exfil = ipt_out.groupby(pw.this.src, pw.this.bucket).reduce(
        src=pw.this.src,
        bucket=pw.this.bucket,
        dsts=pw.reducers.count_distinct(pw.this.dst),
    ).filter(pw.this.dsts >= 20).select(
        alert=pw.apply(
            lambda src, count: f"🚨 Possible exfiltration: {src} contacted {count} destinations in window",
            pw.this.src,
            pw.this.dsts,
        )
    )

    pw.io.jsonlines.write(per_event_alerts.select(alert=pw.this.alert), alerts_out)
    pw.io.jsonlines.write(bf.select(alert=pw.this.alert), alerts_out.replace(".jsonl", "_bf.jsonl"))
    pw.io.jsonlines.write(scan.select(alert=pw.this.alert), alerts_out.replace(".jsonl", "_scan.jsonl"))
    pw.io.jsonlines.write(exfil.select(alert=pw.this.alert), alerts_out.replace(".jsonl", "_exfil.jsonl"))

# ---------------------------------------------------------------------------
# Entrypoint
# ------------------------------------------------


def main() -> None:
    args = parse_args()
    build_pipeline(args.infile, args.alerts, args.events, args.bucket)



if __name__ == "__main__":
    main()
