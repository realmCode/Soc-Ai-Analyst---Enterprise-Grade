#!/usr/bin/env python3
import argparse
import json
import os
import random
import re
import socket
import threading
import time
from pathlib import Path
from typing import Dict, Set, Optional

DEFAULT_ROOT = "/var/log"
DEFAULT_OUT  = "unified.jsonl"

# -----------------------------
# Helpers
# -----------------------------

def now() -> float:
    return time.time()

def hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"

def ensure_dir(p: Path):
    p.parent.mkdir(parents=True, exist_ok=True)

def try_json(s: str) -> Optional[dict]:
    try:
        return json.loads(s)
    except Exception:
        return None

def stream_hint_from_path(p: Path) -> str:
    name = p.name.lower()
    if "auth" in name: return "auth"
    if "kern" in name: return "kernel"
    if "syslog" in name or "messages" in name: return "syslog"
    if "nginx" in name: return "nginx"
    if "apache" in name: return "apache"
    if "access" in name: return "web_access"
    if "app" in name and "json" in name: return "app_json"
    return "other"

# -----------------------------
# DEMO PRODUCERS (activated by --demo)
# They write to <root>/demo/*.log so the tailer will pick them up.
# -----------------------------

def _writable_demo_dir(root: Path) -> Path:
    # try <root>/demo, else ./demo
    d = root / "demo"
    try:
        d.mkdir(parents=True, exist_ok=True)
        (d / ".probe").write_text("ok", encoding="utf-8")
        (d / ".probe").unlink(missing_ok=True)
        return d
    except Exception:
        d = Path.cwd() / "demo"
        d.mkdir(parents=True, exist_ok=True)
        return d

def prod_auth(stop: threading.Event, fpath: Path, rate: float):
    users = ["alice","bob","charlie","root","svc-app"]
    ensure_dir(fpath)
    with open(fpath, "a") as f:
        while not stop.is_set():
            if random.random() < 0.45:
                line = f"{time.ctime()} sshd[1234]: Failed password for {random.choice(users)} from 192.168.1.{random.randint(2,254)} port 22"
            else:
                line = f"{time.ctime()} sshd[5678]: Accepted password for {random.choice(users)} from 10.0.0.{random.randint(2,254)} port 22"
            f.write(line + "\n"); f.flush()
            time.sleep(rate)

def prod_kern(stop: threading.Event, fpath: Path, rate: float):
    # iptables-like IN/OUT/DROP lines with key=val pairs
    ensure_dir(fpath)
    with open(fpath, "a") as f:
        # trickle normal
        while not stop.is_set():
            src = f"10.0.0.{random.randint(2,254)}"
            dst = f"10.0.1.{random.randint(2,254)}"
            spt = random.randint(1024,65535)
            dpt = random.choice([22,80,443,3306,8080,5000,6379,53,25])
            prefix = random.choice(["IPT-IN:","IPT-OUT:"])
            line = f"{time.ctime()} kernel: {prefix} IN=eth0 OUT=eth0 SRC={src} DST={dst} PROTO=TCP SPT={spt} DPT={dpt} SYN"
            f.write(line + "\n"); f.flush()
            if random.random() < 0.08:
                # occasional DROP
                line = f"{time.ctime()} kernel: IPT-DROP: IN=eth0 OUT= SRC={src} DST={dst} PROTO=TCP SPT={spt} DPT={dpt} SYN"
                f.write(line + "\n"); f.flush()
            # short bursts to trigger port-scan/exfil rules later
            if random.random() < 0.15:
                scan_src = f"10.0.0.{random.randint(100,200)}"
                for dpt in range(random.randint(20,30), random.randint(45,60)):
                    if stop.is_set(): break
                    line = f"{time.ctime()} kernel: IPT-IN: IN=eth0 OUT= SRC={scan_src} DST=10.0.1.10 PROTO=TCP SPT=55555 DPT={dpt} SYN"
                    f.write(line + "\n"); f.flush(); time.sleep(0.02)
            if random.random() < 0.12:
                fan_src = f"10.0.5.{random.randint(10,50)}"
                for i in range(15):
                    if stop.is_set(): break
                    line = f"{time.ctime()} kernel: IPT-OUT: IN= OUT=eth0 SRC={fan_src} DST=10.0.7.{100+i} PROTO=TCP SPT=44444 DPT=443"
                    f.write(line + "\n"); f.flush(); time.sleep(0.03)
            time.sleep(rate)

def prod_nginx(stop: threading.Event, fpath: Path, rate: float):
    ensure_dir(fpath)
    methods = ["GET","POST","PUT","DELETE"]
    paths = ["/","/login","/admin","/api/v1/items","/healthz","/download"]
    codes = [200,201,204,302,400,401,403,404,429,500,502]
    with open(fpath, "a") as f:
        while not stop.is_set():
            ip = f"172.17.0.{random.randint(2,254)}"
            m  = random.choice(methods)
            p  = random.choice(paths)
            status = random.choice(codes)
            ua = random.choice(["Mozilla/5.0","curl/7.68.0","python-requests/2.31"])
            line = f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{m} {p} HTTP/1.1" {status} {random.randint(50,5000)} "-" "{ua}"'
            f.write(line + "\n"); f.flush()
            time.sleep(rate)

def prod_apache(stop: threading.Event, fpath: Path, rate: float):
    ensure_dir(fpath)
    with open(fpath, "a") as f:
        while not stop.is_set():
            ip = f"192.168.56.{random.randint(2,254)}"
            method = random.choice(["GET","POST"])
            path = random.choice(["/","/wp-login.php","/xmlrpc.php","/index.php"])
            status = random.choice([200,301,401,403,404,500])
            line = f'{ip} - - [{time.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {random.randint(100,12000)}'
            f.write(line + "\n"); f.flush()
            time.sleep(rate)

def prod_app_json(stop: threading.Event, fpath: Path, rate: float):
    ensure_dir(fpath)
    users = ["svc-app","svc-batch","reporter","etl"]
    lvls = ["INFO","WARN","ERROR","DEBUG"]
    with open(fpath, "a") as f:
        while not stop.is_set():
            rec = {
                "ts": time.time(),
                "level": random.choice(lvls),
                "service": "orders-api",
                "user": random.choice(users),
                "ip": f"10.1.2.{random.randint(2,254)}",
                "msg": random.choice([
                    "created order","updated order","auth failed","db timeout",
                    "cache miss","retrying upstream","payment declined"
                ]),
                "request_id": f"req-{random.randint(100000,999999)}"
            }
            f.write(json.dumps(rec) + "\n"); f.flush()
            time.sleep(rate)

def prod_syslog(stop: threading.Event, fpath: Path, rate: float):
    ensure_dir(fpath)
    procs = ["cron","systemd","dbus-daemon","NetworkManager","kernel","containerd"]
    with open(fpath, "a") as f:
        while not stop.is_set():
            proc = random.choice(procs)
            line = f"{time.ctime()} {hostname()} {proc}[{random.randint(100,999)}]: {random.choice(['started','stopped','reloaded','failed','waiting','heartbeat'])}"
            f.write(line + "\n"); f.flush()
            time.sleep(rate)

def start_demo(root: Path, rate: float) -> Dict[str, threading.Thread]:
    demo_dir = _writable_demo_dir(root)
    threads = {}
    stop = threading.Event()

    items = {
        "auth.log":          prod_auth,
        "kern.log":          prod_kern,
        "nginx_access.log":  prod_nginx,
        "apache_access.log": prod_apache,
        "app_json.log":      prod_app_json,
        "syslog.log":        prod_syslog,
    }
    for name, fn in items.items():
        t = threading.Thread(target=fn, args=(stop, demo_dir / name, rate), daemon=True)
        t.start()
        threads[name] = t

    # return a controller object (stop event + mapping)
    return {"_stop": stop, **threads}

# -----------------------------
# Recursive tailer -> JSONL
# -----------------------------

def discover_logs(root: Path) -> Set[Path]:
    files: Set[Path] = set()
    if root.exists():
        for p in root.rglob("*.log"):
            try:
                if p.is_file() and os.access(p, os.R_OK):
                    files.add(p.resolve())
            except Exception:
                pass
    return files

def tail_file(path: Path, out_path: Path, stop_evt: threading.Event):
    """
    Append each new line as a normalized JSON object:
      {"path": "...", "ts": <epoch>, "raw": "<line>", "fmt": "json"|"text",
       "parsed": {...}|null, "stream": "auth|kernel|...","source_hint":"host"}
    """
    last_inode = None
    fh = None

    def open_file():
        nonlocal fh, last_inode
        if fh:
            try: fh.close()
            except Exception: pass
        fh = open(path, "r", errors="ignore")
        # start at end for continuous mode
        fh.seek(0, os.SEEK_END)
        try:    last_inode = os.fstat(fh.fileno()).st_ino
        except: last_inode = None

    try:
        open_file()
    except FileNotFoundError:
        return

    host = hostname()
    stream_hint = stream_hint_from_path(path)

    while not stop_evt.is_set():
        line = fh.readline()
        if line:
            raw = line.rstrip("\n")
            parsed = try_json(raw)
            rec = {
                "path": str(path),
                "ts": now(),
                "raw": raw,
                "fmt": "json" if parsed is not None else "text",
                "parsed": parsed,
                "stream": stream_hint,
                "source_hint": host,
            }
            try:
                with open(out_path, "a") as out:
                    out.write(json.dumps(rec) + "\n")
            except Exception:
                pass
            continue

        # idle -> handle rotation / recreation
        time.sleep(0.25)
        try:
            cur_inode = os.stat(path).st_ino
            if last_inode is not None and cur_inode != last_inode:
                open_file()
        except FileNotFoundError:
            time.sleep(0.5)
            try:
                open_file()
            except FileNotFoundError:
                pass

def tail_loop(root: Path, out_path: Path, rescan: float):
    stop_evt = threading.Event()
    threads: Dict[str, threading.Thread] = {}
    try:
        while True:
            for f in discover_logs(root):
                key = str(f)
                if key not in threads or not threads[key].is_alive():
                    t = threading.Thread(target=tail_file, args=(f, out_path, stop_evt), daemon=True)
                    t.start()
                    threads[key] = t
            time.sleep(rescan)
    except KeyboardInterrupt:
        pass
    finally:
        stop_evt.set()
        for t in threads.values():
            try: t.join(timeout=0.2)
            except Exception: pass

# -----------------------------
# CLI
# -----------------------------

def main():
    ap = argparse.ArgumentParser(
        description="Phase 1: recursively tail logs -> Pathway-ready JSONL; optional demo producers."
    )
    ap.add_argument("--root", default=DEFAULT_ROOT, help="Root directory to scan (default: /var/log)")
    ap.add_argument("--out",  default=DEFAULT_OUT,  help="Output JSONL file (default: unified.jsonl)")
    ap.add_argument("--rescan", type=float, default=3.0, help="Rescan interval seconds (default: 3.0)")
    ap.add_argument("--demo", action="store_true",
                    help="Start realistic demo producers (auth, kernel/iptables, nginx, apache, app_json, syslog)")
    ap.add_argument("--demorate", type=float, default=0.5,
                    help="Average seconds between demo log lines (default: 0.5)")
    args = ap.parse_args()

    root = Path(args.root)
    out  = Path(args.out)

    controller = None  # <-- ensure defined even if demo isn't started
    print(f"[tail] root={root}  out={out}  rescan={args.rescan}s  demo={args.demo} rate={args.demorate}")

    try:
        # start demo producers if requested
        if args.demo:
            controller = start_demo(root, args.demorate)  # <-- use args.demorate consistently
            print(f"[demo] writing demo logs under {root}/demo (or ./demo fallback)")

        # run tail loop (blocks)
        tail_loop(root, out, args.rescan)

    finally:
        # stop demo threads if running
        if controller is not None:
            controller["_stop"].set()

if __name__ == "__main__":
    main()
