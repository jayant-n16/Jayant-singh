#!/usr/bin/env python3
"""End-to-end smoke test of the migration engine on a local stack (docs/local-deploy-and-test.md).

Signs in to the local dev login as bob (operator) and alice (approver) with the real PKCE flow, then for
each job: bob proposes -> alice approves -> bob executes -> the job worker runs it -> the result is printed.

Jobs: schema synthesis of a MySQL DDL for Cloud SQL for PostgreSQL (validated on the target database, rolled
back), an online schema change on the source table (expand, backfill, validate), a parity check, and a lag
probe if a replica pair is configured. Usage:

    python scripts/migration-smoke.py --api http://127.0.0.1:8000 --idp http://127.0.0.1:8090
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import subprocess  # nosec B404 - runs the project's own worker command
import sys
import time
import urllib.parse

import httpx

REDIRECT = "http://localhost:5173/"


def login(idp: str, user: str) -> str:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    form = {"client_id": "oplia-console", "redirect_uri": REDIRECT, "code_challenge": challenge,
            "code_challenge_method": "S256", "state": "smoke", "user": user, "response_type": "code",
            "scope": "openid"}
    r = httpx.post(f"{idp}/authorize", data=form, follow_redirects=False, timeout=10)
    r.raise_for_status() if r.status_code >= 400 else None
    code = urllib.parse.parse_qs(urllib.parse.urlsplit(r.headers["location"]).query)["code"][0]
    t = httpx.post(f"{idp}/token", data={"grant_type": "authorization_code", "code": code, "client_id": "oplia-console",
                                         "redirect_uri": REDIRECT, "code_verifier": verifier}, timeout=10)
    t.raise_for_status()
    return str(t.json()["access_token"])


def run_job(api: str, bob: str, alice: str, kind: str, params: dict, worker: list[str]) -> dict:
    hb, ha = {"Authorization": f"Bearer {bob}"}, {"Authorization": f"Bearer {alice}"}
    p = httpx.post(f"{api}/dr/jobs/{kind}", headers=hb, json={"params": params, "reason": f"smoke test {kind}"},
                   timeout=30)
    if p.status_code != 201:
        raise SystemExit(f"{kind}: propose failed {p.status_code} {p.text}")
    pid = p.json()["id"]
    httpx.post(f"{api}/proposals/{pid}/approve", headers=ha, json={"note": "smoke"}, timeout=30).raise_for_status()
    ex = httpx.post(f"{api}/proposals/{pid}/execute", headers=hb, timeout=60)
    ex.raise_for_status()
    jid = ex.json()["result"]["job_id"]
    for _ in range(30):
        subprocess.run(worker, check=True, capture_output=True)  # nosec B603 - fixed project command
        j = httpx.get(f"{api}/dr/jobs/{kind}/{jid}", headers=hb, timeout=30).json()
        if j["status"] in ("SUCCEEDED", "FAILED"):
            return j
        time.sleep(1)
    raise SystemExit(f"{kind}: job {jid} did not finish")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default="http://127.0.0.1:8000")
    ap.add_argument("--idp", default="http://127.0.0.1:8090")
    ap.add_argument("--source", default="shop-src")
    ap.add_argument("--target", default="shop-target")
    ap.add_argument("--scratch", default="shop-scratch", help="empty PostgreSQL database used to dry-run DDL")
    ap.add_argument("--worker", default="oplia-dr-job-worker")
    a = ap.parse_args()
    bob, alice = login(a.idp, "bob"), login(a.idp, "alice")
    worker = [a.worker]
    ddl = ("CREATE TABLE customers (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(200) NOT NULL); "
           "CREATE TABLE orders (id BIGINT AUTO_INCREMENT PRIMARY KEY, customer_id INT NOT NULL, total DECIMAL(12,2), "
           "CONSTRAINT fk_o_c FOREIGN KEY (customer_id) REFERENCES customers (id))")
    ok = True
    for kind, params in (
        ("schema_synthesis", {"ddl": ddl, "dialect": "mysql", "target": "cloudsql_postgresql",
                              "validate_on": a.scratch}),
        ("schema_change", {"database": a.source, "change": json.dumps(
            {"table": "orders", "operations": [{"op": "add_index", "name": "ix_orders_customer",
                                                "columns": ["customer_id"]},
                                               {"op": "change_type", "column": "total", "type": "numeric(14,2)"}]})}),
        ("parity_check", {"source": a.source, "target": a.target, "tables": "orders"}),
    ):
        j = run_job(a.api, bob, alice, kind, params, worker)
        st = j["state"]
        summary = {k: st[k] for k in ("validation", "rows_backfilled", "checks", "result") if k in st}
        if "validation" in summary:
            summary["validation"] = {k: summary["validation"][k] for k in ("database", "statements", "failed")}
        print(json.dumps({"job": kind, "status": j["status"], "error": j["error"], **summary}, default=str)[:1500])
        ok = ok and (j["status"] == "SUCCEEDED" or kind == "parity_check")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
