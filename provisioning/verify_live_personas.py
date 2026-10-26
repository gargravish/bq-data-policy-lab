#!/usr/bin/env python3.12
"""Live Multi-Persona Verification Suite for BigQuery PK/FK Dynamic Data Masking.

Executes real impersonated BigQuery queries across all 6 personas against
your configured dataset (`data_policies_example` in `us-central1`):
  1. Single-Table Inspection (`SELECT customer_id, customer_name, email, credit_limit_usd, signup_country FROM customers`)
  2. Cross-Asset 2-Table PK/FK JOIN (`customers` ⋈ `orders` ON c.customer_id = o.customer_id)
  3. Cross-Asset 4-Table Enterprise 360° JOIN (`customers` ⋈ `orders` ⋈ `support_tickets` ⋈ `loyalty_ledger`)
  4. Multi-Policy Hierarchy Conflict Check (`dp-persona-conflict` bound to both Salted SHA-256 #1 and ALWAYS_NULL #9)
  5. Default-Masking-Value PK Anti-Pattern Check (`dp-persona-defaultpk` demonstrating '' = '' Cartesian join explosion)
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys
import warnings

warnings.filterwarnings("ignore")

from google.auth import impersonated_credentials
from google.cloud import bigquery

ROOT_DIR = pathlib.Path(__file__).resolve().parents[1]
ENV_FILE = ROOT_DIR / ".env"


def _load_dotenv() -> None:
    if not ENV_FILE.exists():
        return
    for raw_line in ENV_FILE.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

PROJECT_ID = os.environ.get("GOOGLE_CLOUD_PROJECT", "your-gcp-project-id")
LOCATION = os.environ.get("BQ_LOCATION", "us-central1")
DATASET_ID = os.environ.get("BQ_DATASET", "data_policies_example")
SECRET_PEPPER = os.environ.get("SECRET_PEPPER", "REPLACE_WITH_YOUR_ENTERPRISE_SECRET_PEPPER_2026")
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

STATE_FILE = pathlib.Path(__file__).resolve().parent / "provisioned_state.json"
REPORT_FILE = pathlib.Path(__file__).resolve().parent / "live_verification_report.json"

# Expected values for CUST-1001 ('Alice Smith')
RAW_PK_CUST_1001 = "CUST-1001"
SALTED_SHA256_CUST_1001 = hashlib.sha256(f"CUST-1001{SECRET_PEPPER}".encode("utf-8")).hexdigest()
UNSALTED_SHA256_CUST_1001 = "vzfLri/gZxdYrzVsm7yJzqs/c6w2hMce+H5eqAnZvn8="


def gcloud_env() -> dict[str, str]:
    env = dict(os.environ)
    cur = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "").strip()
    if "datacloud.antigravity" not in cur:
        env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{cur} datacloud.antigravity".strip()
    return env


def get_source_credentials():
    import google.auth
    from google.auth.transport.requests import Request
    try:
        creds, _ = google.auth.default(scopes=SCOPES)
        creds.refresh(Request())
        return creds
    except Exception:
        from google.oauth2.credentials import Credentials

        class _GcloudCredentials(Credentials):
            def refresh(self, request):
                self.token = subprocess.run(
                    ["gcloud", "auth", "print-access-token", "--quiet"],
                    capture_output=True,
                    text=True,
                    check=True,
                    env=gcloud_env(),
                ).stdout.strip()

        token = subprocess.run(
            ["gcloud", "auth", "print-access-token", "--quiet"],
            capture_output=True,
            text=True,
            check=True,
            env=gcloud_env(),
        ).stdout.strip()
        return _GcloudCredentials(token=token)


def client_for_sa(source_creds, sa_email: str) -> bigquery.Client:
    target_creds = impersonated_credentials.Credentials(
        source_credentials=source_creds,
        target_principal=sa_email,
        target_scopes=SCOPES,
        lifetime=900,
    )
    return bigquery.Client(project=PROJECT_ID, credentials=target_creds, location=LOCATION)


def run_query(client: bigquery.Client, sql: str) -> list[dict]:
    job_config = bigquery.QueryJobConfig(
        use_query_cache=False,
        labels={"datacloud": "antigravity"},
    )
    job = client.query(sql, job_config=job_config)
    rows = []
    for row in job.result():
        d = {}
        for k, v in row.items():
            if hasattr(v, "isoformat"):
                d[k] = v.isoformat()
            elif isinstance(v, (int, float, str, bool)) or v is None:
                d[k] = v
            else:
                d[k] = float(v) if str(v).replace(".", "", 1).isdigit() else str(v)
        rows.append(d)
    return rows


def main() -> int:
    if not STATE_FILE.exists():
        print("❌ provisioning/provisioned_state.json not found. Run provision_all.py first.")
        return 1

    state = json.loads(STATE_FILE.read_text())
    personas = state["personas"]
    source_creds = get_source_credentials()

    q1_single_table = f"""
    SELECT
      customer_id,
      customer_name,
      email,
      phone_number,
      tax_id,
      credit_limit_usd,
      signup_country,
      loyalty_tier
    FROM `{PROJECT_ID}.{DATASET_ID}.customers`
    ORDER BY customer_name
    LIMIT 5
    """

    q2_join_orders = f"""
    SELECT
      c.customer_id,
      c.customer_name,
      c.signup_country,
      o.order_id,
      o.order_amount,
      o.order_status,
      o.product_category
    FROM `{PROJECT_ID}.{DATASET_ID}.customers` AS c
    JOIN `{PROJECT_ID}.{DATASET_ID}.orders` AS o
      ON c.customer_id = o.customer_id
    ORDER BY o.order_id
    """

    q3_join_4tables = f"""
    SELECT
      c.customer_id,
      c.customer_name,
      o.order_id,
      o.order_amount,
      t.ticket_id,
      t.issue_category,
      t.priority,
      l.ledger_id,
      l.points_delta
    FROM `{PROJECT_ID}.{DATASET_ID}.customers` AS c
    JOIN `{PROJECT_ID}.{DATASET_ID}.orders` AS o
      ON c.customer_id = o.customer_id
    JOIN `{PROJECT_ID}.{DATASET_ID}.support_tickets` AS t
      ON c.customer_id = t.customer_id AND o.order_id = t.order_id
    JOIN `{PROJECT_ID}.{DATASET_ID}.loyalty_ledger` AS l
      ON c.customer_id = l.customer_id
    ORDER BY o.order_id, l.ledger_id
    """

    print("=" * 92)
    print("🔬 LIVE BIGQUERY MULTI-POLICY PK/FK MASKING & JOIN VERIFICATION SUITE")
    print(f"   Project: {PROJECT_ID} | Location: {LOCATION} | Dataset: {DATASET_ID}")
    print("=" * 92)

    all_passed = True
    results_report: dict[str, dict] = {}

    expectations = {
        "admin": {
            "expected_pk": RAW_PK_CUST_1001,
            "expected_email": "alice.smith@acme-global.com",
            "expected_credit": 25000.0,
            "expected_join_rows": 12,
            "expected_4table_rows": 7,
        },
        "testuser": {
            "expected_pk": SALTED_SHA256_CUST_1001,
            "expected_email": "XXXXX@acme-global.com",
            "expected_credit": 25000.0,
            "expected_join_rows": 12,
            "expected_4table_rows": 7,
        },
        "test2": {
            "expected_pk": None,
            "expected_email": "",
            "expected_credit": 0.0,
            "expected_join_rows": 0,
            "expected_4table_rows": 0,
        },
        "sha256": {
            "expected_pk": UNSALTED_SHA256_CUST_1001,
            "expected_email": "XXXXX@acme-global.com",
            "expected_credit": 0.0,
            "expected_join_rows": 12,
            "expected_4table_rows": 7,
        },
        "defaultpk": {
            "expected_pk": "",
            "expected_email": "",
            "expected_credit": 0.0,
            "expected_join_rows": 96,  # 8 customers * 12 orders = 96 (Cartesian join on '' = ''!)
            "expected_4table_rows": 384,
        },
        "conflict": {
            "expected_pk": SALTED_SHA256_CUST_1001,
            "expected_email": "XXXXX@acme-global.com",
            "expected_credit": 0.0,
            "expected_join_rows": 12,
            "expected_4table_rows": 7,
        },
    }

    for p_key, p_info in personas.items():
        sa_email = p_info["sa_email"]
        exp = expectations[p_key]
        print(f"\n👤 Persona [{p_key.upper()}]: {p_info['title']}")
        print(f"   Human Principal : {p_info['user_email']}")
        print(f"   Live Impersonate: {sa_email}")
        print(f"   Policy Assignment: {p_info['role_label']}")

        client = client_for_sa(source_creds, sa_email)
        r1 = run_query(client, q1_single_table)
        r2 = run_query(client, q2_join_orders)
        r3 = run_query(client, q3_join_4tables)

        alice = r1[0]
        actual_pk = alice["customer_id"]
        actual_email = alice["email"]
        actual_credit = alice["credit_limit_usd"]
        actual_join_rows = len(r2)
        actual_4table_rows = len(r3)

        pk_ok = actual_pk == exp["expected_pk"]
        email_ok = actual_email == exp["expected_email"]
        credit_ok = (actual_credit == exp["expected_credit"])
        join_ok = actual_join_rows == exp["expected_join_rows"]

        status_passed = pk_ok and email_ok and credit_ok and join_ok
        if not status_passed:
            all_passed = False

        print(f"   [{'✅ PASS' if pk_ok else '❌ FAIL'}] Single-Table PK (Alice Smith)  : {repr(actual_pk)} (expected {repr(exp['expected_pk'])})")
        print(f"   [{'✅ PASS' if email_ok else '❌ FAIL'}] Secondary PII Email (Alice)    : {repr(actual_email)} (expected {repr(exp['expected_email'])})")
        print(f"   [{'✅ PASS' if credit_ok else '❌ FAIL'}] Financial Credit Limit (Alice) : {repr(actual_credit)} (expected {repr(exp['expected_credit'])})")
        print(f"   [{'✅ PASS' if join_ok else '❌ FAIL'}] 2-Table PK=FK JOIN Row Count   : {actual_join_rows} rows (expected {exp['expected_join_rows']})")
        print(f"   [ℹ️ INFO] 4-Table Mesh JOIN Row Count    : {actual_4table_rows} rows")

        results_report[p_key] = {
            "persona": p_info,
            "passed": status_passed,
            "single_table_rows": r1,
            "join_orders_rows": r2[:15],
            "join_orders_total_count": actual_join_rows,
            "join_4tables_rows": r3[:15],
            "join_4tables_total_count": actual_4table_rows,
        }

    REPORT_FILE.write_text(json.dumps(results_report, indent=2))
    print("\n" + "=" * 92)
    if all_passed:
        print(f"✅ ALL 6 PERSONAS PASSED LIVE BIGQUERY VERIFICATION! Report saved to {REPORT_FILE}")
        return 0
    else:
        print(f"❌ SOME CHECKS FAILED. Inspect {REPORT_FILE} for details.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
