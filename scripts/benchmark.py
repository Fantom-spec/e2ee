"""Relay benchmark: latency (median / P95), delivery success rate, throughput.

Measures the SERVER RELAY only. Envelopes are random bytes, so browser-side
encryption cost is NOT included. Client and server share one clock
(time.perf_counter), so latency = receive time - submit time.

Run the backend first, then:
    python scripts/benchmark.py --count 20          # quick smoke test
    python scripts/benchmark.py --count 100 --repeats 3
"""

import argparse
import asyncio
import base64
import csv
import json
import os
import platform
import secrets
import statistics
import time
import uuid
from datetime import datetime
from pathlib import Path

import httpx
from websockets.asyncio.client import connect

PW = "correct horse battery staple"
OUT_DIR = Path(__file__).resolve().parent.parent / "docs" / "benchmarks"


def percentile(values, pct):
    """Nearest-rank percentile."""
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(pct / 100 * len(s) + 0.5)) - 1))
    return s[k]


def make_account(http, base, name):
    r = http.post(f"{base}/api/auth/register",
                  json={"username": name, "display_name": name.title(), "password": PW})
    r.raise_for_status()
    r = http.post(f"{base}/api/auth/login", json={"username": name, "password": PW})
    r.raise_for_status()
    body = r.json()
    return {"id": body["user"]["id"], "headers": {"Authorization": f"Bearer {body['token']}"}}


def open_ws(http, base, origin, acct):
    ticket = http.post(f"{base}/api/ws/ticket", headers=acct["headers"]).json()["ticket"]
    ws_base = base.replace("https://", "wss://").replace("http://", "ws://")
    return connect(f"{ws_base}/ws?ticket={ticket}", additional_headers={"Origin": origin})


async def run_online(http, base, origin, a, b, size, count, rate, timeout):
    payload = base64.b64encode(os.urandom(size)).decode()
    sent, recv, errors = {}, {}, []

    async with open_ws(http, base, origin, a) as wa, open_ws(http, base, origin, b) as wb:
        await wa.recv()
        await wb.recv()

        async def reader_b():
            async for raw in wb:
                m = json.loads(raw)
                if "envelope" in m and "id" in m:
                    recv.setdefault(m["id"], time.perf_counter())
                    await wb.send(json.dumps({"type": "ack", "id": m["id"], "from": a["id"]}))

        async def reader_a():
            async for raw in wa:
                m = json.loads(raw)
                if m.get("type") == "error":
                    errors.append(m.get("code"))

        tasks = [asyncio.create_task(reader_b()), asyncio.create_task(reader_a())]
        start = time.perf_counter()
        for i in range(count):
            mid = str(uuid.uuid4())
            sent[mid] = time.perf_counter()
            await wa.send(json.dumps({"type": "send", "id": mid, "to": b["id"], "envelope": payload}))
            await asyncio.sleep(max(0, start + (i + 1) / rate - time.perf_counter()))

        deadline = time.perf_counter() + timeout
        while len(recv) + len(errors) < count and time.perf_counter() < deadline:
            await asyncio.sleep(0.05)
        for t in tasks:
            t.cancel()

    lat = [(recv[i] - sent[i]) * 1000 for i in sent if i in recv]
    span = (max(recv.values()) - min(sent.values())) if recv else 0
    return {"lat": lat, "count": count, "errors": errors, "span": span}


async def run_offline(http, base, origin, a, b, size, count, rate, timeout):
    """Queue `count` messages while B is offline, then time how long B takes to drain them."""
    payload = base64.b64encode(os.urandom(size)).decode()
    errors, accepted = [], [0]

    async with open_ws(http, base, origin, a) as wa:
        await wa.recv()

        async def reader_a():
            async for raw in wa:
                m = json.loads(raw)
                if m.get("type") == "accepted":
                    accepted[0] += 1
                elif m.get("type") == "error":
                    errors.append(m.get("code"))

        task = asyncio.create_task(reader_a())
        start = time.perf_counter()
        for i in range(count):
            await wa.send(json.dumps({"type": "send", "id": str(uuid.uuid4()),
                                      "to": b["id"], "envelope": payload}))
            await asyncio.sleep(max(0, start + (i + 1) / rate - time.perf_counter()))
        deadline = time.perf_counter() + timeout
        while accepted[0] + len(errors) < count and time.perf_counter() < deadline:
            await asyncio.sleep(0.05)
        task.cancel()

    queued = accepted[0]
    t0 = time.perf_counter()
    got, last = 0, t0
    async with open_ws(http, base, origin, b) as wb:
        ready = json.loads(await wb.recv())
        deadline = time.perf_counter() + timeout
        while got < queued and time.perf_counter() < deadline:
            try:
                m = json.loads(await asyncio.wait_for(wb.recv(), 1))
            except asyncio.TimeoutError:
                continue
            if "envelope" in m and "id" in m:
                got += 1
                last = time.perf_counter()
                await wb.send(json.dumps({"type": "ack", "id": m["id"], "from": a["id"]}))
    return {"queued": queued, "pending_at_connect": ready.get("pending"),
            "received": got, "drain_seconds": last - t0, "errors": errors}


def summarize(res):
    lat = res["lat"]
    row = {"delivered": len(lat), "sent": res["count"],
           "success_pct": round(100 * len(lat) / res["count"], 2),
           "errors": ",".join(sorted(set(map(str, res["errors"])))) or "-"}
    if lat:
        row.update(median_ms=round(statistics.median(lat), 2),
                   p95_ms=round(percentile(lat, 95), 2),
                   max_ms=round(max(lat), 2),
                   throughput_msg_s=round(len(lat) / res["span"], 2) if res["span"] else 0)
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8000")
    ap.add_argument("--origin", default="http://localhost:5173")
    ap.add_argument("--count", type=int, default=100, help="messages per size per run")
    ap.add_argument("--rate", type=float, default=2.5, help="messages per second")
    ap.add_argument("--cooldown", type=float, default=11,
                    help="seconds to wait between runs (limit is 30 sends per 10 s per user)")
    ap.add_argument("--sizes", default="100,2048,16384,40000", help="raw envelope bytes")
    ap.add_argument("--repeats", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=15)
    args = ap.parse_args()

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    env = (f"{datetime.now().isoformat(timespec='seconds')} | {platform.platform()} | "
           f"Python {platform.python_version()} | CPUs {os.cpu_count()} | "
           f"base={args.base} | count={args.count} rate={args.rate}/s repeats={args.repeats}")
    print(env)

    http = httpx.Client(timeout=30)
    tag = secrets.token_hex(3)
    a = make_account(http, args.base, f"ba{tag}")
    b = make_account(http, args.base, f"bb{tag}")

    rows = []
    first = True
    for size in [int(s) for s in args.sizes.split(",")]:
        for run in range(1, args.repeats + 1):
            if not first:
                time.sleep(args.cooldown)
            first = False
            res = asyncio.run(run_online(http, args.base, args.origin, a, b,
                                         size, args.count, args.rate, args.timeout))
            row = {"scenario": "online", "payload_bytes": size, "run": run, **summarize(res)}
            rows.append(row)
            print(row)

    time.sleep(args.cooldown)
    off = asyncio.run(run_offline(http, args.base, args.origin, a, b, 2048,
                                  min(args.count, 100), args.rate, args.timeout))
    print("offline backlog drain:", off)

    cols = ["scenario", "payload_bytes", "run", "sent", "delivered", "success_pct",
            "median_ms", "p95_ms", "max_ms", "throughput_msg_s", "errors"]
    out = OUT_DIR / f"{stamp}_summary.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)
    (OUT_DIR / f"{stamp}_environment.txt").write_text(
        env + "\n\noffline drain: " + json.dumps(off) + "\n")
    print(f"\nSaved: {out}")


if __name__ == "__main__":
    main()