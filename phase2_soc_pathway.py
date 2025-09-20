#!/usr/bin/env python3
# Phase 2: Pathway SOC pipeline (robust for older Pathway builds)
# - Consumes Phase 1 output (unified.jsonl)
# - Emits:
#     anomalies.jsonl              (per-event alerts)
#     anomalies_bf.jsonl           (brute-force window alerts)
#     anomalies_scan.jsonl         (port-scan window alerts)
#     anomalies_exfil.jsonl        (exfil window alerts)
#     events_norm.jsonl            (normalized events for RAG/LLM)
#
# Key choices:
# - Schema avoids unsupported types (no "parsed" column).
# - Typed UDFs; no .str.contains; no dict .get on Json.
# - No Table.concat (avoids "universes must be disjoint").

import argparse
import re
from typing import Tuple
import pathway as pw

# ---- Pathway API compatibility (older builds use reducers, newer use reductions)
try:
    RED = pw.reductions
except AttributeError:
    RED = pw.reducers

# ---------- CLI ----------
def parse_args():
    ap = argparse.ArgumentParser(description="Phase 2: Pathway SOC pipeline")
    ap.add_argument("--infile", default="unified.jsonl",
                    help="Input JSONL from Phase 1 (default: unified.jsonl)")
    ap.add_argument("--alerts", default="anomalies.jsonl",
                    help="Output anomalies JSONL (per-event) (default: anomalies.jsonl)")
    ap.add_argument("--events", default="events_norm.jsonl",
                    help="Output normalized events JSONL (default: events_norm.jsonl)")
    ap.add_argument("--bucket", type=int, default=30,
                    help="Seconds per window bucket (default: 30)")
    return ap.parse_args()

# ---------- Schema (match only the keys we need from Phase 1) ----------
class LineSchema(pw.Schema):
    path: str         # file path
    ts: float         # epoch seconds
    raw: str          # original line text
    fmt: str          # "json" | "text"
    stream: str       # "auth" | "kernel" | "web_access" | "app_json" | "syslog" | "other"
    source_hint: str  # hostname or source id

# ---------- UDFs ----------
@pw.udf
def bucketize(ts: float, bucket_s: int) -> int:
    return int(ts // bucket_s)

@pw.udf
def nonempty(s: str) -> bool:
    return s != ""

@pw.udf
def classify(stream: str, raw: str) -> str:
    # auth (sshd)
    if stream == "auth":
        if "Failed password" in raw:
            return "SSH_FAIL"
        if ("Accepted password" in raw) or ("Accepted publickey" in raw):
            return "SSH_OK"
    # kernel (iptables-like)
    if stream == "kernel":
        if "IPT-IN:" in raw:   return "IPT_IN"
        if "IPT-OUT:" in raw:  return "IPT_OUT"
        if "IPT-DROP:" in raw: return "IPT_DROP"
    # web access (nginx/apache)
    if stream == "web_access":
        if ("HTTP/1." in raw) or ("HTTP/2" in raw):
            return "WEB_ACCESS"
    # app logs (we don't need parsed; treat as generic)
    if stream == "app_json":
        return "APP_EVENT"
    # syslog
    if stream == "syslog":
        return "SYS_EVENT"
    return "OTHER"

@pw.udf
def kv_extract(raw: str, key: str) -> str:
    m = re.search(rf"\b{re.escape(key)}=([^\s]+)", raw)
    return m.group(1) if m else "unknown"

@pw.udf
def extract_user_ip(raw: str) -> Tuple[str, str]:
    u, ip = "unknown", "unknown"
    m = re.search(r"Failed password for (\S+) from ([0-9\.]+)", raw)
    if m:
        return m.group(1), m.group(2)
    m2 = re.search(r"Accepted (?:password|publickey) for (\S+) from ([0-9\.]+)", raw)
    if m2:
        return m2.group(1), m2.group(2)
    return u, ip

@pw.udf
def to_severity(etype: str) -> str:
    if etype in ("SSH_FAIL", "IPT_DROP"):
        return "high"
    if etype in ("IPT_IN", "IPT_OUT"):
        return "medium"
    return "low"

@pw.udf
def format_event_msg(etype: str, user: str, ip: str, src: str, dst: str, dpt: str, path: str) -> str:
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

# ---------- Pipeline ----------
def build_pipeline(infile: str, alerts_out: str, events_out: str, bucket_s: int):
    # 0) Ingest (Pathway ignores extra keys in JSON that are not in the schema)
    stream = pw.io.jsonlines.read(infile, schema=LineSchema, mode="streaming")

    # 1) Base derivations (only from original columns)
    base = stream.select(
        ts       = pw.this.ts,
        path     = pw.this.path,
        raw      = pw.this.raw,
        fmt      = pw.this.fmt,
        stream   = pw.this.stream,
        src_host = pw.this.source_hint,

        bucket   = bucketize(pw.this.ts, bucket_s),
        etype    = classify(pw.this.stream, pw.this.raw),
        user_ip  = extract_user_ip(pw.this.raw),
    )

    # 2) Enrichment
    enriched = base.select(
        ts     = pw.this.ts,
        bucket = pw.this.bucket,
        path   = pw.this.path,
        raw    = pw.this.raw,
        stream = pw.this.stream,
        etype  = pw.this.etype,

        user = pw.apply(lambda t: t[0], pw.this.user_ip),
        ip   = pw.apply(lambda t: t[1], pw.this.user_ip),

        src  = kv_extract(pw.this.raw, "SRC"),
        dst  = kv_extract(pw.this.raw, "DST"),
        dpt  = kv_extract(pw.this.raw, "DPT"),

        severity = to_severity(pw.this.etype),
    )

    # 3) Per-event human messages
    per_event_msgs = enriched.select(
        msg = format_event_msg(
            pw.this.etype, pw.this.user, pw.this.ip,
            pw.this.src, pw.this.dst, pw.this.dpt, pw.this.path
        )
    )

    # 4) Persist normalized events for RAG/LLM
    pw.io.jsonlines.write(enriched, events_out)

    # 5) Per-event alerts (non-empty)
    per_event_alerts = per_event_msgs.select(alert=pw.this.msg).filter(nonempty(pw.this.alert))
    pw.io.jsonlines.write(per_event_alerts.select(alert=pw.this.alert), alerts_out)

    # 6) Aggregated rules in buckets (brute-force, scan, exfil)
    ssh_fails = enriched.filter(pw.this.etype == "SSH_FAIL")
    bf = ssh_fails.groupby(pw.this.user, pw.this.bucket).reduce(
        user   = pw.this.user,
        bucket = pw.this.bucket,
        fails  = RED.count(),
    ).filter(pw.this.fails >= 3).select(
        alert = pw.apply(lambda u,n: f"🚨🚨 Brute-force suspected on user={u} (fails={n} in window)",
                         pw.this.user, pw.this.fails)
    )
    pw.io.jsonlines.write(bf.select(alert=pw.this.alert), alerts_out.replace(".jsonl", "_bf.jsonl"))

    ipt_in_or_drop = enriched.filter((pw.this.etype == "IPT_IN") | (pw.this.etype == "IPT_DROP"))
    scan = ipt_in_or_drop.groupby(pw.this.src, pw.this.bucket).reduce(
        src    = pw.this.src,
        bucket = pw.this.bucket,
        ports  = RED.count_distinct(pw.this.dpt),
    ).filter(pw.this.ports >= 10).select(
        alert = pw.apply(lambda s,c: f"🚨 Port-scan behavior: src={s} touched {c} ports in window",
                         pw.this.src, pw.this.ports)
    )
    pw.io.jsonlines.write(scan.select(alert=pw.this.alert), alerts_out.replace(".jsonl", "_scan.jsonl"))

    ipt_out = enriched.filter(pw.this.etype == "IPT_OUT")
    exfil = ipt_out.groupby(pw.this.src, pw.this.bucket).reduce(
        src    = pw.this.src,
        bucket = pw.this.bucket,
        dsts   = RED.count_distinct(pw.this.dst),
    ).filter(pw.this.dsts >= 20).select(
        alert = pw.apply(lambda s,c: f"🚨 Possible exfiltration: {s} contacted {c} destinations in window",
                         pw.this.src, pw.this.dsts)
    )
    pw.io.jsonlines.write(exfil.select(alert=pw.this.alert), alerts_out.replace(".jsonl", "_exfil.jsonl"))

def main():
    args = parse_args()
    build_pipeline(args.infile, args.alerts, args.events, args.bucket)
    pw.run()

if __name__ == "__main__":
    main()
