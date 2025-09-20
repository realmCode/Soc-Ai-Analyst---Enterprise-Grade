# SOC AI Analyst — Enterprise-Grade (SOC Sorcerer)

> **Blue teams drown in logs. SOC Sorcerer makes them *askable*.**  
> Real-time detections with Pathway + Retrieval-Augmented Generation + LLM summaries.

---

## ✨ What is this?

SOC Sorcerer is a **real-time SOC copilot** that:
- **Ingests** live Linux logs (auth/syslog/kernel/iptables) and app logs.
- **Normalizes & detects** brute-force, port-scan, and exfil patterns *deterministically*.
- **Indexes** everything into a **RAG** store for natural-language questions.
- **Explains** only the top, high-severity clusters with an LLM (Gemini), **cost‑capped**.

**Not "ChatGPT on logs."** This is typed, streaming, on‑prem friendly, and extensible.

---

## 🧱 Architecture (3 Phases)

```
[Phase 1] Tail + Normalize
  • Recursively tails /var/log (or demo producers)
  • Emits normalized JSONL -> unified.jsonl

[Phase 2] Pathway Streaming Detections
  • Reads unified.jsonl, builds events_norm.jsonl
  • Writes anomaly JSONL streams:
      - anomalies.jsonl        (per‑event)
      - anomalies_bf.jsonl     (brute‑force windows)
      - anomalies_scan.jsonl   (port‑scan windows)
      - anomalies_exfil.jsonl  (exfil windows)

[Phase 3] RAG + LLM
  • Builds a local index (TF‑IDF by default; Gemini‑embed optional)
  • Query with NL (“what happened in last 5 mins?”)
  • Clusters + samples returned
  • Optional LLM explanations for top clusters
```

---

## ⚡ Features

- **Live tail** of recursive logs (`/var/log/**/*.log`) or **demo** producers
- Deterministic **detections**: SSH brute‑force, port scans, outbound/exfil spikes
- **Unified event fabric**: `etype / user / ip / src / dst / port / time`
- **RAG**: prefilter by time/fields + semantic KNN
- **LLM in the loop (optional)** for short explanations
- **On‑prem friendly**: TF‑IDF retrieval works offline; redactable; constant cost

---

## 📦 Requirements

- Python 3.10+
- Install deps:
  ```bash
  pip install -r requirements.txt
  ```
- Optional LLM:
  - **Gemini**: `pip install google-generativeai`
  - Set `export GEMINI_API_KEY="..."`

> If scikit‑learn is present, TF‑IDF is used; otherwise a hashing vector fallback is enabled.

---

## 🚀 Quickstart (Local)

### 0) Create venv & install
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 1) Phase 1 — Tail logs → `unified.jsonl`
**Real system logs (recursive):**
```bash
python phase1_tail_logs.py \
  --root /var/log \
  --out unified.jsonl \
  --rescan 3.0
```

**Demo mode (safe, portable):**
```bash
python phase1_tail_logs.py \
  --root ./demo_root \
  --out unified.jsonl \
  --rescan 3.0 \
  --demo --demorate 0.5
```

### 2) Phase 2 — Pathway detections → normalized/events + anomalies
```bash
python phase2_soc_pathway.py \
  --infile unified.jsonl \
  --alerts anomalies.jsonl \
  --events events_norm.jsonl \
  --bucket 30
```

**Outputs generated:**
- `events_norm.jsonl`
- `anomalies.jsonl`
- `anomalies_bf.jsonl`
- `anomalies_scan.jsonl`
- `anomalies_exfil.jsonl`

### 3) Phase 3 — RAG index + ask

**Index (fast, offline TF‑IDF):**
```bash
rm -rf rag
python phase3_rag.py index \
  --events events_norm.jsonl \
  --anomalies "anomalies*.jsonl" \
  --persist ./rag \
  --provider tfidf
```

**Ask with deterministic summaries (no LLM):**
```bash
python phase3_rag.py ask "what anomalies in the last 5 mins?" \
  --persist ./rag \
  --provider tfidf \
  --pretty --no-alerts --explain
```

**Ask with Gemini explanations (LLM summaries):**
```bash
export GEMINI_API_KEY="YOUR_API_KEY"

# Non‑streaming:
python phase3_rag.py ask "brute force on alice today" \
  --persist ./rag \
  --provider tfidf \
  --pretty --no-alerts \
  --llm --llm-mode gemini

# Streaming output (if supported by your build):
python phase3_rag.py ask "what anomalies in the last 5 mins?" \
  --persist ./rag \
  --provider tfidf \
  --pretty --no-alerts \
  --llm --llm-mode gemini --stream
```

> **Recommended demo path:** TF‑IDF for retrieval + Gemini for explanations only.  
> Keeps cost down and latency tight.

---

## 🧩 Environment Variables

```bash
# Required only if you use Gemini for embeds or explanations:
export GEMINI_API_KEY="..."

# Optional overrides:
export GEMINI_EMBED_MODEL="text-embedding-004"
export GEMINI_CHAT_MODEL="gemini-1.5-flash"
```

---

## 🗂️ Repo Layout

```
phase1_tail_logs.py     # Tails logs recursively; optional demo producers
phase2_soc_pathway.py   # Pathway pipeline: normalize + detections
phase3_rag.py           # Indexing + RAG query + optional LLM explanations
requirements.txt
```

---

## 🔧 Extending Inputs

- Add new parsers in **Phase 1** (e.g., Okta, M365, CloudTrail, Nginx).
- Normalize to the core fields:
  - `ts, etype, severity, stream, user, ip, src, dst, dpt, path, bucket, raw`
- Phase 2 & 3 will automatically incorporate the new streams.

---

## 🛡️ Security Notes

- Keep `unified.jsonl` and `events_norm.jsonl` on‑prem or redacted.
- LLM step only sends **cluster summaries + a few sample lines** (configurable).
- Prefer TF‑IDF retrieval for **offline** / air‑gapped setups.

---

## ❓ FAQ

**Q: Can I run Phase 3 with Gemini embeddings and TF‑IDF fallback?**  
A: Yes. Use `--provider gemini` to embed, but we recommend TF‑IDF for fast demos, then `--llm --llm-mode gemini` for explanations.

**Q: Why Pathway?**  
A: Deterministic, low‑latency streaming transformations with **strong typing** and windowed aggregations — perfect for SOC pipelines.

**Q: How do I point to a different log root?**  
A: Use `--root /path/to/logs` in Phase 1. It will recurse `**/*.log`.

---

## 🧪 Troubleshooting

- **No `unified.jsonl`?**  
  Ensure Phase 1 is running and writing to the same path you pass into Phase 2.

- **Pathway typing errors in Phase 2:**  
  We map every field to explicit types; make sure Phase 1 normalization emits valid values. If you added a new parser, conform to the schema.

- **Gemini “Explanation unavailable”:**  
  Check `GEMINI_API_KEY`. If safety errors occur, use the deterministic `--explain` flag or relax safety settings in `phase3_rag.py` (see `_build_gemini_model`).

- **Index reads zero / empty index:**  
  Confirm the `rag/` directory contains `meta.jsonl`, `vectors.npy`, `ids.npy`. Rebuild with `rm -rf rag && python phase3_rag.py index ...`.

---

## 🧭 Roadmap

- Enrichments: GeoIP, ASN, Threat Intel feeds  
- Re‑rank with Gemini embeddings on the top TF‑IDF hits  
- Web UI (dashboards + chat)  
- Connectors: Okta, M365, CloudTrail, S3, GCP/Azure logs  

---

## 🙌 Credits

Special thanks: **Anurag Sinha** (fallback Ubuntu sys)  
Shout‑outs: Pathway & TRAE communities

---

## 📜 License

(see `LICENSE`)
