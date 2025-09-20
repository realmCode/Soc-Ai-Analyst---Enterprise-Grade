#!/usr/bin/env python3
# Phase 3: Real-time RAG for SOC Copilot
# - Live indexer tailing events_norm.jsonl (+ optional anomalies files)
# - Hybrid retrieval: time/field prefilter + vector similarity
# - Embeddings: Gemini (text-embedding-004) or TF-IDF fallback
# - Explanations: Gemini (gemini-1.5-flash) gated to top findings
#
# Usage:
#   # Live indexer:
#   python phase3_rag.py index --events events_norm.jsonl --persist ./rag --provider gemini
#
#   # Ask questions (with optional explanations):
#   python phase3_rag.py ask "what anomalies in the last 5 mins?" --persist ./rag --minutes 5 --llm
#
# Env:
#   GEMINI_API_KEY         - required if --provider gemini or --llm used
#   GEMINI_EMBED_MODEL     - default: text-embedding-004
#   GEMINI_CHAT_MODEL      - default: gemini-1.5-flash
#
# Files written in --persist:
#   meta.jsonl     - one JSON per event (id, ts, etype, user, ip, src, dst, dpt, severity, text, bucket)
#   vectors.npy    - float32 matrix [N, D]
#   ids.npy        - int64 array [N]
#   state.json     - bookkeeping (file offsets, dims, counts)
#
# Notes:
# - Safe to rerun; indexer resumes tailing from last offsets.
# - TF-IDF provider needs scikit-learn (else it falls back to simple bag-of-words).
# - Retrieval does cosine similarity; we prefilter by time and optional fields first.

import argparse, os, sys, json, time, re, math, threading, glob, io, datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

import numpy as np
from dotenv import load_dotenv
import shutil
def _term_width(default=100):
    try:
        return shutil.get_terminal_size().columns
    except Exception:
        return default

def _clean_sample_text(t: str) -> str:
    # extract human part after raw='...'
    m = re.search(r"raw='([^']+)'", t)
    if m:
        return m.group(1)
    # fall back to full text, collapse spaces
    return re.sub(r"\s+", " ", t).strip()

def pretty_print_response(resp: Dict[str, Any], hide_alerts: bool = False,
                          limit_samples: int = 3, show_raw: bool = False, add_explain: bool = False):
    q = resp.get("query", "")
    flt = resp.get("filters", {})
    width = max(80, _term_width())
    bar = "-" * width
    print(f"\n{bar}")
    print(f"Query: {q}")
    mins = flt.get("minutes")
    since = flt.get("since")
    fbits = []
    if mins: fbits.append(f"last {mins} min")
    if since:
        try:
            dt = datetime.datetime.fromtimestamp(float(since)).isoformat(timespec="seconds")
            fbits.append(f"since {dt}")
        except Exception:
            pass
    for k in ("user","ip","port"):
        if flt.get(k): fbits.append(f"{k}={flt[k]}")
    if flt.get("etype"):
        fbits.append(f"etype={','.join(flt['etype'])}")
    print("Filters:", ", ".join(fbits) if fbits else "(none)")
    print(bar)

    clusters = resp.get("clusters", [])
    if hide_alerts:
        clusters = [c for c in clusters if c.get("etype") != "ALERT"]

    if not clusters:
        print("No matching results."); print(bar); return

    for i, c in enumerate(clusters, 1):
        et, sev, cnt = c.get("etype",""), c.get("severity",""), c.get("count",0)
        src, dst, dpt = c.get("src",""), c.get("dst",""), c.get("dpt","")
        print(f"[{i}] {et:<10}  sev={sev:<6}  hits={cnt:<3}  flow={src}->{dst}:{dpt}")
        print(f"     summary: {c.get('summary','')}")
        if add_explain:
            print(f"     why/what: {explain_cluster_deterministic(c)}")
        # samples
        samples = c.get("samples", [])[:max(0, limit_samples)]
        for s in samples:
            ts = _human_time(s.get("ts",0))
            st = _clean_sample_text(s.get("text","")) if not show_raw else re.sub(r"\s+"," ", s.get("text","")).strip()
            path = s.get("path","")
            print(f"       • {ts}  {st}  ({path})")
        # optional LLM explain (if present)
        if "explanation" in c and c["explanation"]:
            print(f"     llm: {c['explanation']}")
        print("")
    print(bar)

load_dotenv()
###################################3 helpers
def _human_time(ts: float) -> str:
    try:
        return datetime.datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(ts)

def explain_cluster_deterministic(c: dict) -> str:
    et, sev, cnt = c.get("etype",""), c.get("severity",""), int(c.get("count",0))
    src, dst, dpt = c.get("src",""), c.get("dst",""), c.get("dpt","")
    tmax = max((s.get("ts",0) or 0) for s in c.get("samples",[])) if c.get("samples") else 0
    tmin = min((s.get("ts",0) or 0) for s in c.get("samples",[])) if c.get("samples") else 0
    window = f"{_human_time(tmin)} → {_human_time(tmax)}" if tmin and tmax else "recent window"
    # Heuristic next steps per type
    if et == "SSH_FAIL":
        return (f"Multiple SSH failures observed (count={cnt}) within {window}. "
                f"Likely brute-force attempt. Check auth logs for the same source IPs, "
                f"enforce lockout/backoff, and verify MFA on targeted users.")
    if et == "IPT_IN" or et == "IPT_DROP":
        return (f"Inbound port activity from {src} to {dst} across ports (count={cnt}) within {window}. "
                f"Likely port scan. Review firewall/IDS, block or rate-limit the source, and inspect for follow-up attempts.")
    if et == "IPT_OUT":
        return (f"Outbound connections from {src} to {dst}:{dpt} (count={cnt}) within {window}. "
                f"Potential data egress or service misuse. Validate the destination, check transfer volumes, and correlate with process/user.")
    if et == "SSH_OK":
        return (f"Successful SSH logins observed within {window}. Validate legitimacy for recent "
                f"successful logins near failed attempts; consider geo/ASN anomalies and key rotation if suspicious.")
    return (f"{et} activity (count={cnt}) in {window}. Review context and correlate with related streams.")

##################################################
# ---- Optional providers (Gemini)
USE_GEMINI = False
try:
    import google.generativeai as genai
    USE_GEMINI = True
except Exception:
    USE_GEMINI = False

# ---- Optional TF-IDF
HAVE_SK = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity
    HAVE_SK = True
except Exception:
    HAVE_SK = False


# --------------------------
# Utility / IO
# --------------------------
def now_ts() -> float:
    return time.time()

def parse_iso(s: str) -> float:
    # naive ISO (local time); fallback to float
    try:
        return datetime.datetime.fromisoformat(s).timestamp()
    except Exception:
        return float(s)

def load_jsonl(path: Path):
    if not path.exists():
        return []
    out = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out

def append_jsonl(path: Path, obj: Dict[str, Any]):
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False) + "\n")

def read_new_lines(path: Path, start_offset: int) -> Tuple[List[str], int]:
    if not path.exists(): return [], start_offset
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(start_offset)
        data = f.read()
        new_off = f.tell()
    if not data:
        return [], start_offset
    # splitlines(keepends=False)
    lines = [ln for ln in data.splitlines() if ln.strip()]
    return lines, new_off

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

def load_state(persist: Path) -> Dict[str, Any]:
    st = persist / "state.json"
    if not st.exists():
        return {"events_offset": 0, "anoms_offsets": {}, "count": 0, "dim": 0}
    return json.loads(st.read_text())

def save_state(persist: Path, state: Dict[str, Any]):
    (persist / "state.json").write_text(json.dumps(state, indent=2))


# --------------------------
# Text building & parsing
# --------------------------
def build_index_text(ev: Dict[str, Any]) -> str:
    # Expect fields from Phase-2 events_norm.jsonl
    # ts, bucket, path, raw, stream, etype, user, ip, src, dst, dpt, severity
    ts = ev.get("ts", 0)
    dt = datetime.datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    pieces = [
        f"[{ev.get('severity','low')}] {ev.get('etype','OTHER')}",
        f"stream={ev.get('stream','')}",
        f"user={ev.get('user','unknown')}",
        f"ip={ev.get('ip','unknown')}",
        f"{ev.get('src','unknown')}->{ev.get('dst','unknown')}:{ev.get('dpt','')}",
        f"path={ev.get('path','')}",
        f"ts={dt}",
        f"raw='{ev.get('raw','')[:300]}'"  # cap raw preview
    ]
    return " ".join(pieces)

ENTITY_PATTERNS = {
    "ip": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "port": re.compile(r"\b(?:port|dpt|:)\s*(\d{2,5})\b", re.IGNORECASE),
    "user": re.compile(r"\buser[:= ]([A-Za-z0-9._-]+)\b", re.IGNORECASE),
}

def parse_query(q: str) -> Dict[str, Any]:
    # Extract simple signals: minutes window, since time, etype hints, entities
    out = {"minutes": None, "since": None, "etype": set(), "user": None, "ip": None, "port": None, "terms": []}

    # time windows
    mm = re.search(r"last\s+(\d+)\s*m(?:in)?", q, re.IGNORECASE)
    if mm: out["minutes"] = int(mm.group(1))
    hh = re.search(r"last\s+(\d+)\s*h", q, re.IGNORECASE)
    if hh: out["minutes"] = int(hh.group(1)) * 60
    if "today" in q.lower():
        d0 = datetime.datetime.combine(datetime.date.today(), datetime.time.min)
        out["since"] = d0.timestamp()

    ss = re.search(r"since\s+([0-9T:\-]+)", q, re.IGNORECASE)
    if ss:
        out["since"] = parse_iso(ss.group(1))

    # entity extraction
    ipm = ENTITY_PATTERNS["ip"].search(q)
    if ipm: out["ip"] = ipm.group(0)
    pm = ENTITY_PATTERNS["port"].search(q)
    if pm:
        try: out["port"] = int(pm.group(1))
        except: pass
    um = ENTITY_PATTERNS["user"].search(q)
    if um: out["user"] = um.group(1)

    # etype hints
    low = q.lower()
    if any(k in low for k in ["ssh", "login", "brute"]):
        out["etype"].update(["SSH_FAIL", "SSH_OK"])
    if any(k in low for k in ["scan", "nmap", "port-scan"]):
        out["etype"].update(["IPT_IN", "IPT_DROP"])
    if any(k in low for k in ["exfil", "outbound", "data out"]):
        out["etype"].update(["IPT_OUT"])

    # terms (remaining words)
    toks = re.findall(r"[A-Za-z0-9_.:/\-]+", q)
    out["terms"] = [t for t in toks if t.lower() not in {"what","anomalies","in","the","last","mins","min","since","today","on","from","port","scan","ssh","exfil","outbound","data","show","which"}]
    return out


# --------------------------
# Embedding providers
# --------------------------
class Embedder:
    def __init__(self, provider: str, dim_hint: int = 768):
        self.provider = provider.lower()
        self.dim = dim_hint
        self._tfidf = None
        self._tfidf_texts = []
        self._gemini = None
        if self.provider == "gemini":
            api_key = os.getenv("GEMINI_API_KEY")
            if not api_key:
                print("[embed] GEMINI_API_KEY not set; falling back to tfidf", file=sys.stderr)
                self.provider = "tfidf"
            else:
                genai.configure(api_key=api_key)
                self._gemini_model = os.getenv("GEMINI_EMBED_MODEL", "text-embedding-004")
                # we don't know dim ahead of time; will infer after first call
        if self.provider == "tfidf":
            if HAVE_SK:
                self._tfidf = TfidfVectorizer(max_features=4096, ngram_range=(1,2))
            else:
                print("[embed] scikit-learn not available; using simple hashing vectorizer", file=sys.stderr)
                # super-lightweight hashing TF (no sklearn)
                self._tfidf = None

    def _hashing_vec(self, texts: List[str]) -> np.ndarray:
        # super simple hashing trick if sklearn missing
        dim = 2048
        M = np.zeros((len(texts), dim), dtype=np.float32)
        for i, t in enumerate(texts):
            for tok in re.findall(r"[A-Za-z0-9_.:/\-]+", t.lower()):
                h = hash(tok) % dim
                M[i, h] += 1.0
            # normalize
            n = np.linalg.norm(M[i]) + 1e-9
            M[i] /= n
        return M

    def fit_partial(self, new_texts: List[str]) -> np.ndarray:
        if not new_texts:
            return np.zeros((0, self.dim), dtype=np.float32)

        if self.provider == "gemini":
            vecs = []
            for txt in new_texts:
                try:
                    r = genai.embed_content(model=self._gemini_model, content=txt)
                    v = np.array(r["embedding"], dtype=np.float32)
                    vecs.append(v)
                except Exception as e:
                    # degrade to tfidf hashing for this row only
                    vecs.append(self._hashing_vec([txt])[0])
            V = np.vstack(vecs)
            self.dim = V.shape[1]
            return V

        # tfidf
        if HAVE_SK:
            # incremental-ish: refit with all texts (small hack for demo)
            self._tfidf_texts.extend(new_texts)
            X = self._tfidf.fit_transform(self._tfidf_texts)
            # return only the last chunk dense vectors
            last = X[-len(new_texts):].toarray().astype(np.float32)
            self.dim = last.shape[1]
            # L2 normalize
            last /= (np.linalg.norm(last, axis=1, keepdims=True) + 1e-9)
            return last
        else:
            return self._hashing_vec(new_texts)


# --------------------------
# Index store
# --------------------------
class IndexStore:
    def __init__(self, persist: Path):
        ensure_dir(persist)
        self.persist = persist
        self.meta_path = persist / "meta.jsonl"
        self.vectors_path = persist / "vectors.npy"
        self.ids_path = persist / "ids.npy"
        self.state = load_state(persist)
        self._load_arrays()

    def _load_arrays(self):
        if self.vectors_path.exists() and self.ids_path.exists():
            try:
                self.V = np.load(self.vectors_path)
                self.ids = np.load(self.ids_path)
                return
            except Exception:
                pass
        self.V = np.zeros((0, 0), dtype=np.float32)
        self.ids = np.zeros((0,), dtype=np.int64)

    def append(self, new_ids: np.ndarray, new_vecs: np.ndarray, new_meta: List[Dict[str, Any]]):
        if new_vecs.size == 0:
            return
        if self.V.size == 0:
            self.V = new_vecs
            self.ids = new_ids
        else:
            # pad dims if changed
            if new_vecs.shape[1] != self.V.shape[1]:
                d_old, d_new = self.V.shape[1], new_vecs.shape[1]
                d = max(d_old, d_new)
                def pad(M, d):
                    if M.shape[1] == d: return M
                    P = np.zeros((M.shape[0], d), dtype=np.float32)
                    P[:, :M.shape[1]] = M
                    return P
                self.V = pad(self.V, d)
                new_vecs = pad(new_vecs, d)
            self.V = np.vstack([self.V, new_vecs])
            self.ids = np.concatenate([self.ids, new_ids])
        # persist arrays
        np.save(self.vectors_path, self.V)
        np.save(self.ids_path, self.ids)
        # append meta
        for m in new_meta:
            append_jsonl(self.meta_path, m)
        # update count in state
        self.state["count"] = int(self.ids.shape[0])
        save_state(self.persist, self.state)

    def all_meta(self) -> List[Dict[str, Any]]:
        return load_jsonl(self.meta_path)

    def knn(self, qvec: np.ndarray, k: int = 20, mask: Optional[np.ndarray] = None) -> List[int]:
        if self.V.size == 0:
            return []
        Q = qvec.reshape(1, -1)
        # pad dims if mismatch
        d = max(Q.shape[1], self.V.shape[1])
        def pad(M, d):
            if M.shape[1] == d: return M
            P = np.zeros((M.shape[0], d), dtype=np.float32)
            P[:, :M.shape[1]] = M
            return P
        Q = pad(Q, d)
        V = pad(self.V, d)
        # cos sim
        Vn = V / (np.linalg.norm(V, axis=1, keepdims=True) + 1e-9)
        Qn = Q / (np.linalg.norm(Q, axis=1, keepdims=True) + 1e-9)
        sims = (Vn @ Qn.T).ravel()
        if mask is not None:
            sims = np.where(mask, sims, -1e9)
        idx = np.argpartition(-sims, kth=min(k, len(sims)-1))[:k]
        idx = idx[np.argsort(-sims[idx])]
        return idx.tolist()


# --------------------------
# Live indexer (tail files)
# --------------------------
def event_from_phase2_line(line: str) -> Optional[Dict[str, Any]]:
    try:
        ev = json.loads(line)
    except Exception:
        return None
    # ensure minimal keys
    for k in ["ts","etype","severity","stream","user","ip","src","dst","dpt","path","bucket","raw"]:
        ev.setdefault(k, "")
    if isinstance(ev.get("ts",""), (int,float)) is False:
        # try parse
        try:
            ev["ts"] = float(ev["ts"])
        except Exception:
            ev["ts"] = now_ts()
    return ev

def anomalies_to_event(alert_obj: Dict[str, Any]) -> Dict[str, Any]:
    # Convert simple {"alert": "..."} into a synthetic event (low weight)
    txt = alert_obj.get("alert","")
    ts = alert_obj.get("time", now_ts())/1000 if "time" in alert_obj else now_ts()
    return dict(
        ts=ts, etype="ALERT", severity="high" if "🚨" in txt else "medium",
        stream="alert", user="unknown", ip="unknown", src="unknown", dst="unknown", dpt="",
        path="anomalies", bucket=int(ts // 30), raw=txt
    )

def tail_index_loop(events_path: Path, anomalies_glob: Optional[str], store: IndexStore, embedder: Embedder, poll=0.5):
    # resume offsets
    state = store.state
    ev_off = int(state.get("events_offset", 0))
    an_offs: Dict[str, int] = state.get("anoms_offsets", {})

    while True:
        # events
        lines, ev_off = read_new_lines(events_path, ev_off)
        new_meta, new_texts = [], []
        new_ids = []

        for ln in lines:
            ev = event_from_phase2_line(ln)
            if not ev: continue
            text = build_index_text(ev)
            eid = int(ev["ts"]*1e6) ^ hash(text) & 0x7FFFFFFF  # cheap unique-ish id
            new_meta.append({
                "id": eid, "ts": ev["ts"], "bucket": ev.get("bucket",0),
                "etype": ev.get("etype",""), "severity": ev.get("severity",""),
                "stream": ev.get("stream",""), "user": ev.get("user",""),
                "ip": ev.get("ip",""), "src": ev.get("src",""), "dst": ev.get("dst",""),
                "dpt": ev.get("dpt",""), "path": ev.get("path",""), "text": text
            })
            new_texts.append(text)
            new_ids.append(eid)

        # anomalies
        if anomalies_glob:
            for apath in glob.glob(anomalies_glob):
                p = Path(apath)
                off = int(an_offs.get(apath, 0))
                alines, new_off = read_new_lines(p, off)
                an_offs[apath] = new_off
                for ln in alines:
                    try:
                        ao = json.loads(ln)
                    except Exception:
                        continue
                    ev = anomalies_to_event(ao)
                    text = build_index_text(ev)
                    eid = int(ev["ts"]*1e6) ^ hash(text) & 0x7FFFFFFF
                    new_meta.append({
                        "id": eid, "ts": ev["ts"], "bucket": ev.get("bucket",0),
                        "etype": ev.get("etype","ALERT"), "severity": ev.get("severity",""),
                        "stream": ev.get("stream","alert"), "user": ev.get("user",""),
                        "ip": ev.get("ip",""), "src": ev.get("src",""), "dst": ev.get("dst",""),
                        "dpt": ev.get("dpt",""), "path": ev.get("path",""), "text": text
                    })
                    new_texts.append(text)
                    new_ids.append(eid)

        # embed + append
        if new_texts:
            vecs = embedder.fit_partial(new_texts)
            store.append(np.array(new_ids, dtype=np.int64), vecs, new_meta)
            print(f"[index] +{len(new_texts)} (total={store.state['count']})")

        # persist offsets
        state["events_offset"] = ev_off
        state["anoms_offsets"] = an_offs
        save_state(store.persist, state)

        time.sleep(poll)


# --------------------------
# Retrieval
# --------------------------
def prefilter_mask(meta: List[Dict[str,Any]], minutes: Optional[int], since_ts: Optional[float], filters: Dict[str, Any]) -> np.ndarray:
    N = len(meta)
    if N == 0: return np.zeros((0,), dtype=bool)
    t_now = now_ts()
    t0 = 0.0
    if minutes is not None:
        t0 = max(t0, t_now - minutes*60)
    if since_ts is not None:
        t0 = max(t0, since_ts)

    etypes = set(filters.get("etype", [])) if filters.get("etype") else set()
    user = filters.get("user")
    ip = filters.get("ip")
    port = str(filters.get("port")) if filters.get("port") else None

    mask = np.ones((N,), dtype=bool)
    for i, m in enumerate(meta):
        if t0 and float(m.get("ts",0)) < t0:
            mask[i] = False; continue
        if etypes and m.get("etype","") not in etypes:
            mask[i] = False; continue
        if user and m.get("user","") != user:
            mask[i] = False; continue
        if ip and (m.get("ip","") != ip and m.get("src","") != ip and m.get("dst","") != ip):
            mask[i] = False; continue
        if port and (m.get("dpt","") != port):
            mask[i] = False; continue
    return mask

def cluster_hits(meta: List[Dict[str,Any]], idxs: List[int], max_clusters: int = 5) -> List[Dict[str,Any]]:
    # Group by (etype, src, dst, dpt, bucket) → count + samples
    buckets: Dict[Tuple, Dict[str,Any]] = {}
    for i in idxs:
        m = meta[i]
        key = (m.get("etype",""), m.get("src",""), m.get("dst",""), m.get("dpt",""), m.get("bucket",0))
        g = buckets.setdefault(key, {"etype": key[0], "src": key[1], "dst": key[2], "dpt": key[3],
                                     "bucket": key[4], "severity": m.get("severity","low"),
                                     "count": 0, "samples": []})
        g["count"] += 1
        if len(g["samples"]) < 3:
            g["samples"].append({"ts": m.get("ts"), "text": m.get("text"), "path": m.get("path")})
        # track worst severity
        sev_rank = {"low":0,"medium":1,"high":2}
        if sev_rank.get(m.get("severity","low"),0) > sev_rank.get(g["severity"],0):
            g["severity"] = m.get("severity","low")
    # rank clusters by (severity, count, recency)
    def score(c):
        sev_w = {"low":0.2,"medium":0.6,"high":1.0}[c["severity"]]
        rec = max(s["ts"] for s in c["samples"]) if c["samples"] else 0
        return (sev_w*2.0) + (c["count"]*0.05) + (rec*1e-6)
    clusters = sorted(buckets.values(), key=score, reverse=True)[:max_clusters]
    # summaries
    for c in clusters:
        if c["etype"] in ("SSH_FAIL","SSH_OK"):
            c["summary"] = f"{c['etype']} user≈{', '.join(set(_extract_user(s['text']) for s in c['samples']))} from IPs touching bucket {c['bucket']} (count={c['count']})"
        elif c["etype"] in ("IPT_IN","IPT_DROP"):
            c["summary"] = f"Port-scan-ish {c['src']} -> {c['dst']} across ports (count={c['count']})"
        elif c["etype"] == "IPT_OUT":
            c["summary"] = f"Outbound activity {c['src']} contacting {c['dst']}:{c['dpt']} (count={c['count']})"
        else:
            c["summary"] = f"{c['etype']} cluster (count={c['count']})"
    return clusters

def _extract_user(text: str) -> str:
    m = re.search(r"user=([A-Za-z0-9._-]+)", text)
    return m.group(1) if m else "unknown"


# --------------------------
# LLM explanations (Gemini)
# --------------------------
# --------------------------
# LLM explanations (Gemini) — enum safety settings + robust fallback
# --------------------------
# --------------------------
# Gemini LLM explanations (streaming + strict modes)
# --------------------------
def _gemini_text_from_resp(resp) -> str:
    """Works across SDK versions: returns best-effort text."""
    # Newer SDKs: resp.text; Streaming chunks: each ev has .text too
    t = getattr(resp, "text", None)
    if t:
        return t
    # Fallback: try candidates list
    try:
        parts = []
        for c in getattr(resp, "candidates", []) or []:
            for ct in getattr(c, "content", {}).get("parts", []) or []:
                val = getattr(ct, "text", None) or (ct.get("text") if isinstance(ct, dict) else None)
                if val:
                    parts.append(val)
        return "".join(parts)
    except Exception:
        return ""

def _build_gemini_model():
    import google.generativeai as genai
    # Try both locations for the enums
    try:
        from google.generativeai.types import HarmCategory, HarmBlockThreshold
    except Exception:
        from google.generativeai.types.safety_types import HarmCategory, HarmBlockThreshold  # older SDKs

    # Helper to fetch whatever enum name exists on this SDK
    def _enum_attr(E, *candidates):
        for name in candidates:
            if hasattr(E, name):
                return getattr(E, name)
        return None

    # Try a range of names used across releases
    cat_sexual      = _enum_attr(HarmCategory, "HARM_CATEGORY_SEXUAL_CONTENT", "SEXUAL_CONTENT", "SEXUAL")
    cat_hate        = _enum_attr(HarmCategory, "HARM_CATEGORY_HATE_SPEECH", "HATE_SPEECH", "HATE")
    cat_harass      = _enum_attr(HarmCategory, "HARM_CATEGORY_HARASSMENT", "HARASSMENT")
    cat_danger      = _enum_attr(HarmCategory, "HARM_CATEGORY_DANGEROUS_CONTENT", "DANGEROUS_CONTENT", "DANGEROUS")

    block_none      = _enum_attr(HarmBlockThreshold, "BLOCK_NONE", "NONE", "BLOCK_LOW")  # last fallback = permissive-ish

    # Build a dict only with enums that actually exist
    safety_settings = {}
    for c in (cat_sexual, cat_hate, cat_harass, cat_danger):
        if c is not None and block_none is not None:
            safety_settings[c] = block_none

    # Generation config (tolerate dict vs class)
    try:
        from google.generativeai.types import GenerationConfig
        gen_cfg = GenerationConfig(temperature=0.2, top_p=0.9, top_k=40, max_output_tokens=180)
    except Exception:
        gen_cfg = dict(temperature=0.2, top_p=0.9, top_k=40, max_output_tokens=180)

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError("GEMINI_API_KEY not set")
    genai.configure(api_key=api_key)

    model_name = os.getenv("GEMINI_CHAT_MODEL", "gemini-1.5-flash")

    # Some SDKs only accept safety/gen config at call-time
    try:
        model = genai.GenerativeModel(
            model_name,
            safety_settings=safety_settings if safety_settings else None,
            generation_config=gen_cfg,
            system_instruction=(
                "You are a SOC analyst. Be precise, actionable, and avoid hallucinations. "
                "Base your reasoning only on the provided cluster samples and summary."
            ),
        )
    except TypeError:
        model = genai.GenerativeModel(model_name)
        model._soc_safety_settings = safety_settings if safety_settings else None
        model._soc_generation_config = gen_cfg

    return model


def gemini_explain_nonstream(clusters, query, max_items=3):
    import google.generativeai as genai

    model = _build_gemini_model()
    safety = getattr(model, "_soc_safety_settings", None)
    gen_cfg = getattr(model, "_soc_generation_config", None)

    outs = []
    for c in clusters[:max_items]:
        prompt = f"""Explain this cluster briefly (≤120 words). Be actionable and specific.

Query: {query}

Cluster:
- Summary: {c.get('summary')}
- Type: {c.get('etype')}, Severity: {c.get('severity')}, Count: {c.get('count')}, Bucket: {c.get('bucket')}
- Samples (up to 3):
{json.dumps(c.get('samples', []), indent=2)}

Include: likely cause, why it matters, and one recommended next step. Avoid fluff. Don't invent facts beyond samples."""
        kw = {"request_options": {"timeout": 25}}
        if safety is not None:
            kw["safety_settings"] = safety
        if gen_cfg is not None:
            kw["generation_config"] = gen_cfg

        resp = model.generate_content(prompt, **kw)
        txt = _gemini_text_from_resp(resp).strip()
        outs.append(txt or "Explanation unavailable.")
    return outs


def gemini_explain_stream(clusters, query, max_items=3):
    """
    Stream Gemini explanations for top clusters.
    Prints tokens as they arrive: 'llm (cluster i): <stream...>'
    Returns a list of final strings (one per cluster).
    """
    import sys, time
    import google.generativeai as genai

    model = _build_gemini_model()
    safety = getattr(model, "_soc_safety_settings", None)
    gen_cfg = getattr(model, "_soc_generation_config", None)

    finals = []
    for idx, c in enumerate(clusters[:max_items], 1):
        prompt = f"""Explain this cluster briefly (≤120 words). Be actionable and specific.

Query: {query}

Cluster:
- Summary: {c.get('summary')}
- Type: {c.get('etype')}, Severity: {c.get('severity')}, Count: {c.get('count')}, Bucket: {c.get('bucket')}
- Samples (up to 3):
{json.dumps(c.get('samples', []), indent=2)}

Include: likely cause, why it matters, and one recommended next step. Avoid fluff. Don't invent facts beyond samples."""

        # ------ THIS IS THE KW BLOCK YOU ASKED ABOUT ------
        kw = {"request_options": {"timeout": 25}, "stream": True}
        if safety is not None:
            kw["safety_settings"] = safety
        if gen_cfg is not None:
            kw["generation_config"] = gen_cfg
        # ---------------------------------------------------

        # call Gemini with streaming
        stream = model.generate_content(prompt, **kw)

        acc = []
        print(f"     llm (cluster {idx}): ", end="", flush=True)
        for ev in stream:
            token = getattr(ev, "text", None) or _gemini_text_from_resp(ev)
            if token:
                acc.append(token)
                print(token, end="", flush=True)
        print("")  # newline after the stream finishes

        final = "".join(acc).strip()
        if not final:
            final = "Explanation unavailable (empty stream)."
        finals.append(final)
        time.sleep(0.03)  # tiny pacing so stdout renders nicely

    return finals
# --------------------------
# CLI
# --------------------------
def cmd_index(args):
    persist = Path(args.persist)
    store = IndexStore(persist)
    provider = args.provider.lower()
    embedder = Embedder(provider=provider)

    anomalies_glob = None
    if args.anomalies:
        anomalies_glob = args.anomalies

    events_path = Path(args.events)
    ensure_dir(persist)
    print(f"[index] provider={embedder.provider}  events={events_path}  anomalies={anomalies_glob}  persist={persist}")
    try:
        tail_index_loop(events_path, anomalies_glob, store, embedder, poll=args.poll)
    except KeyboardInterrupt:
        print("\n[index] stopped.")

def cmd_ask(args):
    persist = Path(args.persist)
    store = IndexStore(persist)
    meta = store.all_meta()
    if not meta:
        print(json.dumps({"error":"index empty"}, indent=2)); return

    # build query vector using provider (reuse Embedder for dim compat)
    embedder = Embedder(provider=args.provider)
    qvec = embedder.fit_partial([args.query])
    qvec = qvec[0]

    # query parse + prefilter
    parsed = parse_query(args.query)
    parsed["etype"] = sorted(list(parsed.get("etype", [])))   # <-- add this line

    minutes = args.minutes if args.minutes is not None else parsed["minutes"]
    since_ts = parse_iso(args.since) if args.since else parsed["since"]
    filt = {"etype": parsed["etype"], "user": parsed["user"], "ip": parsed["ip"], "port": parsed["port"]}
    mask = prefilter_mask(meta, minutes, since_ts, filt)
    idxs = store.knn(qvec, k=args.k, mask=mask)

    clusters = cluster_hits(meta, idxs, max_clusters=args.max_clusters)

    resp = {
        "query": args.query,
        "parsed": parsed,
        "filters": {"minutes": minutes, "since": since_ts, **filt},
        "clusters": clusters,
    }

    if args.llm:
        mode = getattr(args, "llm_mode", "auto")
        try:
            if mode == "deterministic":
                exps = [explain_cluster_deterministic(c) for c in clusters[:min(3, len(clusters))]]
            else:
                # Try Gemini first
                if args.stream and args.pretty:
                    # live streaming under pretty printing
                    exps = gemini_explain_stream(clusters, args.query, max_items=min(3, len(clusters)))
                else:
                    exps = gemini_explain_nonstream(clusters, args.query, max_items=min(3, len(clusters)))
        except Exception as e:
            if mode == "gemini":
                # Strict: user demanded Gemini only → fail loudly
                raise
            # auto mode: graceful fallback to deterministic
            exps = [explain_cluster_deterministic(c) for c in clusters[:min(3, len(clusters))]]

        # attach explanations
        for i, txt in enumerate(exps):
            if i < len(resp["clusters"]):
                resp["clusters"][i]["explanation"] = txt


    if args.pretty:
        pretty_print_response(resp, hide_alerts=args.no_alerts,
                              limit_samples=args.limit_samples,
                              show_raw=args.show_raw,
                              add_explain=args.explain)
    else:
        print(json.dumps(resp, indent=2))



def build_argparser():
    ap = argparse.ArgumentParser(description="Phase 3: Real-time RAG over SOC events")
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_idx = sub.add_parser("index", help="Run live indexer (tail events + anomalies)")
    ap_idx.add_argument("--events", default="events_norm.jsonl", help="Path to Phase-2 normalized events")
    ap_idx.add_argument("--anomalies", default="anomalies*.jsonl", help="Glob for anomalies files (or empty to disable)")
    ap_idx.add_argument("--persist", default="./rag", help="Directory to store vectors/meta")
    ap_idx.add_argument("--provider", choices=["gemini","tfidf"], default="gemini", help="Embedding provider")
    ap_idx.add_argument("--poll", type=float, default=0.5, help="Polling interval seconds")
    ap_idx.set_defaults(func=cmd_index)

    ap_ask = sub.add_parser("ask", help="Query the index")
    ap_ask.add_argument("query", help="Natural language question")
    ap_ask.add_argument("--persist", default="./rag", help="Index directory")
    ap_ask.add_argument("--provider", choices=["gemini","tfidf"], default="gemini", help="Embedding provider for the query")
    ap_ask.add_argument("--minutes", type=int, help="Time window in minutes (overrides parsed)")
    ap_ask.add_argument("--since", type=str, help="ISO start time (e.g., 2025-09-20T08:00:00)")
    ap_ask.add_argument("--k", type=int, default=50, help="Top-K vectors to fetch before clustering")
    ap_ask.add_argument("--max-clusters", type=int, default=5, help="Clusters to return")
    # ap_ask.add_argument("--llm", action="store_true", help="Ask Gemini to explain top clusters")
    ap_ask.add_argument("--pretty", action="store_true", help="Pretty human-readable output")
    ap_ask.add_argument("--no-alerts", action="store_true", help="Hide synthetic ALERT clusters")
    ap_ask.add_argument("--explain", action="store_true", help="Add deterministic analyst-style explanations")
    ap_ask.add_argument("--limit-samples", type=int, default=3, help="Max sample lines per cluster")
    ap_ask.add_argument("--show-raw", action="store_true", help="Show raw log text in samples")
    # ... inside ap_ask parser definition:
    ap_ask.add_argument("--llm", action="store_true", help="Generate LLM explanations (Gemini if available)")
    ap_ask.add_argument("--stream", action="store_true", help="Stream Gemini output live for explanations")
    ap_ask.add_argument("--llm-mode", choices=["auto","gemini","deterministic"], default="auto",
                        help="Which explainer to use: 'gemini' (require Gemini), 'deterministic' (rule-based), or 'auto' (Gemini then fallback)")   

    ap_ask.set_defaults(func=cmd_ask)

    return ap

def main():
    ap = build_argparser()
    args = ap.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
