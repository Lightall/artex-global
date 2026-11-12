#!/usr/bin/env python3
"""Run isolated local acceptance without model credentials or a production DB."""
from __future__ import annotations

import argparse
import atexit
import json
import os
from pathlib import Path
import subprocess
import time
import uuid


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--start-postgres", action="store_true")
    parser.add_argument("--mode", choices=["acceptance", "regression", "race"], default="acceptance")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    args.runtime = args.runtime.resolve()
    args.evidence = args.evidence.resolve()
    args.repo = args.repo.resolve()
    args.evidence.mkdir(parents=True, exist_ok=True)
    go = args.runtime / "go/bin/go"
    pg = args.runtime / "pg-wheel/pgserver/pginstall/bin"
    if args.start_postgres:
        data = args.runtime / "pgdata"
        if not (data / "PG_VERSION").exists():
            raise SystemExit("Expected the task-specific initialized PostgreSQL directory")
        status = subprocess.run([str(pg / "pg_ctl"), "-D", str(data), "status"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if status.returncode:
            subprocess.run([str(pg / "pg_ctl"), "-D", str(data), "-l", str(args.runtime / "postgres.log"), "-o", f"-h 127.0.0.1 -p {args.port}", "-w", "start"], check=True)
            atexit.register(subprocess.run, [str(pg / "pg_ctl"), "-D", str(data), "-m", "fast", "-w", "stop"], check=False)
    env = os.environ.copy()
    for key in ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "ARTEX_LLM_PROVIDER", "ARTEX_LLM_MODEL", "ARTEX_LLM_BASE_URL", "ARTEX_LLM_PROXY", "ARTEX_REVIEW_LIVE_CONFIG"]:
        env.pop(key, None)
    env.update(
        GOPATH=str(args.runtime / "gopath"),
        GOCACHE=str(args.runtime / "gocache"),
        GOTOOLCHAIN="local",
        ARTEX_MVP_EVIDENCE_DIR=str(args.evidence / args.mode),
        ARTEX_NOTIFY_BACKGROUND_DISABLED="1",
    )
    env["PATH"] = str(go.parent) + os.pathsep + env.get("PATH", "")
    packages = ["verification", "server"] if args.mode != "regression" else ["verification", "db", "agent", "evidence", "server"]
    records: list[dict] = []
    for package in packages:
        database = "artex_mvp_check_" + uuid.uuid4().hex[:10] + "_" + package
        pg_args = ["-h", "127.0.0.1", "-p", str(args.port), "-U", "artex"]
        subprocess.run([str(pg / "createdb"), *pg_args, database], check=True)
        env["ARTEX_PG_DSN"] = f"postgres://artex@127.0.0.1:{args.port}/{database}?sslmode=disable"
        command = [str(go), "test", "-json", "-count=1", "-timeout=180s"]
        if args.mode == "race":
            command.append("-race")
        if args.mode != "regression":
            command += ["-run", "^Test(HTTP|Verification)"]
        command.append("./" + package)
        started = time.monotonic()
        try:
            result = subprocess.run(command, cwd=args.repo, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        finally:
            subprocess.run([str(pg / "dropdb"), *pg_args, "--force", database], check=True)
        log = args.evidence / f"{args.mode}-{package}.jsonl"
        log.write_text(result.stdout)
        log.chmod(0o600)
        events = []
        for line in result.stdout.splitlines():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        passed = [x["Test"] for x in events if x.get("Action") == "pass" and x.get("Test")]
        failed = [x["Test"] for x in events if x.get("Action") == "fail" and x.get("Test")]
        skipped = [x["Test"] for x in events if x.get("Action") == "skip" and x.get("Test")]
        record = dict(package=package, returncode=result.returncode, passed=len(passed), failed=failed, skipped=skipped, elapsed_seconds=round(time.monotonic()-started, 2), log=str(log))
        records.append(record)
        print(json.dumps(record), flush=True)
    summary = dict(mode=args.mode, model_http_calls=0, source=str(args.repo), packages=records)
    (args.evidence / f"{args.mode}-summary.json").write_text(json.dumps(summary, indent=2)+"\n")
    return int(any(r["returncode"] or (args.mode != "regression" and r["skipped"]) for r in records))


if __name__ == "__main__":
    raise SystemExit(main())
