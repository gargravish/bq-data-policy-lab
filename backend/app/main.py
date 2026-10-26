#!/usr/bin/env python3.12
"""FastAPI Backend for BigQuery Multi-Policy PK/FK Dynamic Data Masking Live Demo.

Executes real-time impersonated BigQuery queries across 6 distinct governance personas
against the configured dataset (`data_policies_example` in `us-central1`) to demonstrate:
  1. Authorized Fine-Grained Reader (`admin`) -> Raw PK & Plaintext Joins
  2. Custom Masking Routine – Salted SHA-256 (`testuser`) -> Rainbow-Resistant Deterministic Hash Joins
  3. Nullify Masking (`test2`) -> NULL on PK (`NULL = NULL` -> 0 rows) + Default Masking Value on PII/Financial
  4. Predefined Unsalted SHA-256 (`dp-persona-sha256`) -> Joinable Base64 SHA-256 but Vulnerable to Rainbow Table Reversal
  5. Default Masking Value on PK Anti-Pattern (`dp-persona-defaultpk`) -> Empty String `'' = ''` N×M Cartesian Join Explosion
  6. Multi-Policy Priority Hierarchy Resolution (`dp-persona-conflict`) -> Priority #1 Custom Routine beats Priority #9 Nullify
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import pathlib
import subprocess
import time
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from google.auth import impersonated_credentials
from google.cloud import bigquery
from pydantic import BaseModel, Field

ROOT_DIR = pathlib.Path(__file__).resolve().parents[2]
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
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

STATE_FILE = ROOT_DIR / "provisioning" / "provisioned_state.json"
REPORT_FILE = ROOT_DIR / "provisioning" / "live_verification_report.json"
SQL_SCHEMA_FILE = ROOT_DIR / "provisioning" / "sql" / "01_schema_and_udf.sql"
SQL_VERIFY_FILE = ROOT_DIR / "provisioning" / "sql" / "02_verification_queries.sql"
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"

ALLOWED_PERSONAS = ("admin", "testuser", "test2", "sha256", "defaultpk", "conflict")
ALLOWED_LOYALTY_TIERS = ("ALL", "PLATINUM", "GOLD", "SILVER")

# BigQuery 9-tier masking rule priority hierarchy (from official Google Cloud documentation:
# https://cloud.google.com/bigquery/docs/column-data-masking-intro#masking_rule_hierarchy)
MASKING_RULE_HIERARCHY = [
    {
        "priority": 1,
        "rule": "Custom masking routine",
        "expression": "customMaskingRoutine (e.g., fn_salted_sha256)",
        "used_in_demo": True,
        "demo_policy_id": "dp_customer_pk_salted_sha256",
        "description": "Executes a user-defined SQL function with OPTIONS(data_governance_type='DATA_MASKING'). Highest priority when a principal matches multiple policies.",
    },
    {
        "priority": 2,
        "rule": "Hash (SHA-512)",
        "expression": "SHA512",
        "used_in_demo": False,
        "demo_policy_id": None,
        "description": "Returns Base64-encoded SHA-512 hash of STRING/BYTES column.",
    },
    {
        "priority": 3,
        "rule": "Hash (SHA-256)",
        "expression": "SHA256",
        "used_in_demo": True,
        "demo_policy_id": "dp_customer_pk_sha256",
        "description": "Returns Base64-encoded SHA-256 hash (TO_BASE64(SHA256(val))). Deterministic for joins, but unsalted hashes on predictable keys can be reversed via rainbow tables.",
    },
    {
        "priority": 4,
        "rule": "Email mask",
        "expression": "EMAIL_MASK",
        "used_in_demo": True,
        "demo_policy_id": "dp_pii_email_mask",
        "description": "Replaces username before '@' with 'XXXXX' while preserving the domain (e.g., XXXXX@acme-global.com).",
    },
    {
        "priority": 5,
        "rule": "Last four characters",
        "expression": "LAST_FOUR_CHARACTERS",
        "used_in_demo": False,
        "demo_policy_id": None,
        "description": "Masks all characters with 'X' except the last 4 characters.",
    },
    {
        "priority": 6,
        "rule": "First four characters",
        "expression": "FIRST_FOUR_CHARACTERS",
        "used_in_demo": False,
        "demo_policy_id": None,
        "description": "Masks all characters with 'X' except the first 4 characters.",
    },
    {
        "priority": 7,
        "rule": "Date year mask",
        "expression": "DATE_YEAR_MASK",
        "used_in_demo": False,
        "demo_policy_id": None,
        "description": "Truncates DATE/DATETIME/TIMESTAMP values to YYYY-01-01 while preserving the year.",
    },
    {
        "priority": 8,
        "rule": "Default masking value",
        "expression": "DEFAULT_MASKING_VALUE",
        "used_in_demo": True,
        "demo_policy_id": "dp_pii_default_mask / dp_fin_default_mask / dp_customer_pk_default",
        "description": "Replaces values with type-specific defaults ('' for STRING, 0 / 0.0 for numbers, 1970-01-01 for DATE). Dangerous on PK/FK join columns because '' = '' matches every row pair!",
    },
    {
        "priority": 9,
        "rule": "Nullify",
        "expression": "ALWAYS_NULL",
        "used_in_demo": True,
        "demo_policy_id": "dp_customer_pk_null",
        "description": "Replaces the column value with NULL regardless of data type. Safe join blocker on PK/FK columns because NULL = NULL evaluates to UNKNOWN (0 rows).",
    },
]

# Pre-registered, parameterized GoogleSQL query templates (no arbitrary SQL strings accepted)
QUERY_CATALOG: dict[str, dict[str, Any]] = {
    "single_table_customers": {
        "id": "single_table_customers",
        "title": "1. Single-Table Customer Inspection (PK + PII + Financial)",
        "category": "Single-Table Masking",
        "subtitle": "Inspects how `customers.customer_id` (PK), `email`/`phone_number`/`tax_id` (PII), and `credit_limit_usd` (Financial) dynamically transform per persona.",
        "supports_tier_filter": True,
        "sql": f"""SELECT
  customer_id,
  customer_name,
  email,
  phone_number,
  tax_id,
  signup_country,
  loyalty_tier,
  credit_limit_usd,
  signup_date
FROM `{PROJECT_ID}.{DATASET_ID}.customers`
WHERE (@loyalty_tier = 'ALL' OR loyalty_tier = @loyalty_tier)
ORDER BY customer_name""",
        "expected_insight": "Admin sees raw 'CUST-1001' + full PII; TestUser sees Salted SHA-256 hex '9e8efd65...' + masked email 'XXXXX@acme-global.com'; Test2 sees NULL on PK, '' on String PII, and 0.0 on credit_limit_usd.",
    },
    "join_customers_orders": {
        "id": "join_customers_orders",
        "title": "2. Cross-Table PK = FK INNER JOIN (customers ⋈ orders)",
        "category": "Relational PK=FK Join",
        "subtitle": "Tests relational equality `ON c.customer_id = o.customer_id` when both Primary Key and Foreign Key share the `Customer_PK_Tag` policy tag.",
        "supports_tier_filter": True,
        "sql": f"""SELECT
  o.order_id,
  c.customer_id AS customer_pk,
  o.customer_id AS order_fk,
  c.customer_name,
  c.email,
  c.loyalty_tier,
  c.credit_limit_usd,
  o.product_category,
  o.order_amount,
  o.order_status
FROM `{PROJECT_ID}.{DATASET_ID}.customers` AS c
INNER JOIN `{PROJECT_ID}.{DATASET_ID}.orders` AS o
  ON c.customer_id = o.customer_id
WHERE (@loyalty_tier = 'ALL' OR c.loyalty_tier = @loyalty_tier)
ORDER BY o.order_id""",
        "expected_insight": "Admin (12 rows, plaintext join) and TestUser (12 rows, deterministic Salted SHA-256 join) preserve exact relational integrity. Test2 (ALWAYS_NULL) safely returns 0 rows because NULL = NULL is UNKNOWN. DefaultPK ('') triggers a 96-row Cartesian explosion!",
    },
    "join_4table_mesh": {
        "id": "join_4table_mesh",
        "title": "3. Four-Table Enterprise 360° Mesh JOIN (customers ⋈ orders ⋈ tickets ⋈ loyalty)",
        "category": "Multi-Hop Mesh Join",
        "subtitle": "Joins four tables across `customer_id` (`customers`, `orders`, `support_tickets`, `loyalty_ledger`) to prove deterministic salted hashing scales across complex star/snowflake schemas.",
        "supports_tier_filter": True,
        "sql": f"""SELECT
  c.customer_id,
  c.customer_name,
  c.email,
  c.loyalty_tier,
  c.credit_limit_usd,
  o.order_id,
  o.order_amount,
  t.ticket_id,
  t.issue_category,
  t.priority,
  l.ledger_id,
  l.points_delta,
  l.partner_program
FROM `{PROJECT_ID}.{DATASET_ID}.customers` AS c
INNER JOIN `{PROJECT_ID}.{DATASET_ID}.orders` AS o
  ON c.customer_id = o.customer_id
INNER JOIN `{PROJECT_ID}.{DATASET_ID}.support_tickets` AS t
  ON c.customer_id = t.customer_id AND o.order_id = t.order_id
INNER JOIN `{PROJECT_ID}.{DATASET_ID}.loyalty_ledger` AS l
  ON c.customer_id = l.customer_id
WHERE (@loyalty_tier = 'ALL' OR c.loyalty_tier = @loyalty_tier)
ORDER BY o.order_id, l.ledger_id""",
        "expected_insight": "Both Admin and TestUser return the exact 7 correlated enterprise events across all 4 tables without exposing raw customer IDs to TestUser. DefaultPK explodes to 384 false-positive rows.",
    },
    "agg_spend_by_customer": {
        "id": "agg_spend_by_customer",
        "title": "4. Customer Spend & Credit Aggregation (GROUP BY Masked PK)",
        "category": "Analytics & GROUP BY",
        "subtitle": "Groups order spend by `c.customer_id` after joining `customers` and `orders`. Demonstrates per-customer analytical grouping under pseudonymous Salted SHA-256.",
        "supports_tier_filter": True,
        "sql": f"""SELECT
  c.customer_id,
  c.signup_country,
  c.loyalty_tier,
  COUNT(DISTINCT o.order_id) AS total_orders,
  SUM(o.order_amount) AS total_spend_usd,
  MAX(c.credit_limit_usd) AS visible_credit_limit
FROM `{PROJECT_ID}.{DATASET_ID}.customers` AS c
INNER JOIN `{PROJECT_ID}.{DATASET_ID}.orders` AS o
  ON c.customer_id = o.customer_id
WHERE (@loyalty_tier = 'ALL' OR c.loyalty_tier = @loyalty_tier)
GROUP BY c.customer_id, c.signup_country, c.loyalty_tier
ORDER BY total_spend_usd DESC""",
        "expected_insight": "TestUser computes exact per-customer order counts and total spend (8 customer groups) using Salted SHA-256 keys without ever seeing 'CUST-1001'.",
    },
    "rainbow_attack_lab": {
        "id": "rainbow_attack_lab",
        "title": "5. Cryptographic Attack Lab: Unsalted SHA-256 Rainbow Lookup vs. Salted UDF",
        "category": "Cryptographic Security",
        "subtitle": "Attempts to reverse masked `customer_id` values by joining against an 8-row dictionary of `TO_BASE64(SHA256('CUST-1001'..'CUST-1008'))`.",
        "supports_tier_filter": False,
        "sql": f"""WITH rainbow_table AS (
  SELECT
    candidate_id,
    TO_BASE64(SHA256(candidate_id)) AS unsalted_b64_hash,
    TO_HEX(SHA256(candidate_id)) AS unsalted_hex_hash
  FROM UNNEST([
    'CUST-1001', 'CUST-1002', 'CUST-1003', 'CUST-1004',
    'CUST-1005', 'CUST-1006', 'CUST-1007', 'CUST-1008'
  ]) AS candidate_id
)
SELECT
  c.customer_name,
  c.customer_id AS what_caller_sees_on_pk,
  r.candidate_id AS rainbow_table_reversed_id,
  CASE
    WHEN c.customer_id IS NULL THEN 'PROTECTED (NULL - Joins Blocked)'
    WHEN c.customer_id = '' THEN 'BROKEN_JOINS (Empty String Default)'
    WHEN c.customer_id LIKE 'CUST-%' THEN 'RAW_PLAINTEXT (Authorized Fine-Grained Reader)'
    WHEN r.candidate_id IS NOT NULL THEN 'VULNERABLE! Reversed via Unsalted SHA-256 Rainbow Lookup'
    ELSE 'SECURE! Salted SHA-256 Defeats Rainbow Table & Preserves Joins'
  END AS cryptographic_verdict
FROM `{PROJECT_ID}.{DATASET_ID}.customers` AS c
LEFT JOIN rainbow_table AS r
  ON c.customer_id IN (r.unsalted_b64_hash, r.unsalted_hex_hash)
ORDER BY c.customer_name""",
        "expected_insight": "Proves why Predefined SHA256 (`sha256` persona) is 100% reversed back to 'CUST-1001'..'CUST-1008' by a trivial dictionary join, while `testuser` (`fn_salted_sha256` with secret pepper) returns NULL for `rainbow_table_reversed_id`!",
    },
    "single_table_orders": {
        "id": "single_table_orders",
        "title": "6. Foreign Key Inspection on Child Table (`orders`)",
        "category": "Single-Table Masking",
        "subtitle": "Inspects `orders.customer_id` (Foreign Key) to verify that the exact same policy tag (`Customer_PK_Tag`) enforces identical persona-specific transformations on child tables.",
        "supports_tier_filter": False,
        "sql": f"""SELECT
  order_id,
  customer_id AS foreign_key_customer_id,
  order_date,
  product_category,
  order_amount,
  order_status,
  payment_channel
FROM `{PROJECT_ID}.{DATASET_ID}.orders`
ORDER BY order_id""",
        "expected_insight": "Demonstrates why tagging both PK and FK columns with `Customer_PK_Tag` guarantees symmetric transformation across every table in the dataset.",
    },
}


def gcloud_env() -> dict[str, str]:
    env = dict(os.environ)
    cur = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "").strip()
    if "datacloud.antigravity" not in cur:
        env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{cur} datacloud.antigravity".strip()
    return env


def get_source_credentials():
    import google.auth
    from google.auth.transport.requests import Request as GoogleAuthRequest

    try:
        creds, _ = google.auth.default(scopes=SCOPES)
        creds.refresh(GoogleAuthRequest())
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


def load_provisioned_state() -> dict[str, Any]:
    if not STATE_FILE.exists():
        raise HTTPException(
            status_code=500,
            detail="Provisioned state file not found. Run provisioning/provision_all.py first.",
        )
    return json.loads(STATE_FILE.read_text())


def load_verification_report() -> dict[str, Any]:
    if REPORT_FILE.exists():
        return json.loads(REPORT_FILE.read_text())
    return {}


def execute_impersonated_query(
    persona_id: str,
    query_id: str,
    loyalty_tier: str = "ALL",
) -> dict[str, Any]:
    if persona_id not in ALLOWED_PERSONAS:
        raise HTTPException(status_code=400, detail=f"Invalid persona_id: {persona_id}")
    if query_id not in QUERY_CATALOG:
        raise HTTPException(status_code=400, detail=f"Invalid query_id: {query_id}")
    if loyalty_tier not in ALLOWED_LOYALTY_TIERS:
        raise HTTPException(status_code=400, detail=f"Invalid loyalty_tier: {loyalty_tier}")

    state = load_provisioned_state()
    persona_meta = state["personas"][persona_id]
    sa_email = persona_meta["sa_email"]
    q_meta = QUERY_CATALOG[query_id]

    source_creds = get_source_credentials()
    target_creds = impersonated_credentials.Credentials(
        source_credentials=source_creds,
        target_principal=sa_email,
        target_scopes=SCOPES,
        lifetime=900,
    )
    bq_client = bigquery.Client(
        project=PROJECT_ID,
        credentials=target_creds,
        location=LOCATION,
    )

    query_params = []
    if q_meta.get("supports_tier_filter"):
        query_params.append(
            bigquery.ScalarQueryParameter("loyalty_tier", "STRING", loyalty_tier)
        )

    job_config = bigquery.QueryJobConfig(
        use_query_cache=False,
        query_parameters=query_params,
        labels={"datacloud": "antigravity", "persona": persona_id},
    )

    t0 = time.perf_counter()
    job = bq_client.query(q_meta["sql"], job_config=job_config)
    result_iter = job.result()
    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    rows: list[dict[str, Any]] = []
    columns: list[str] = [field.name for field in result_iter.schema]
    for row in result_iter:
        item: dict[str, Any] = {}
        for k, v in row.items():
            if hasattr(v, "isoformat"):
                item[k] = v.isoformat()
            elif isinstance(v, (int, float, str, bool)) or v is None:
                item[k] = v
            else:
                item[k] = float(v) if str(v).replace(".", "", 1).isdigit() else str(v)
        rows.append(item)

    # Extract sample PK value from first row if available
    sample_pk = None
    if rows:
        for pk_col in ("customer_id", "customer_pk", "what_caller_sees_on_pk", "foreign_key_customer_id"):
            if pk_col in rows[0]:
                sample_pk = rows[0][pk_col]
                break

    return {
        "persona_id": persona_id,
        "persona": persona_meta,
        "query_id": query_id,
        "query_title": q_meta["title"],
        "loyalty_tier_filter": loyalty_tier,
        "sql_executed": q_meta["sql"],
        "job_id": job.job_id,
        "location": job.location,
        "elapsed_ms": elapsed_ms,
        "row_count": len(rows),
        "columns": columns,
        "rows": rows,
        "sample_pk_seen": sample_pk,
    }


class QueryRequest(BaseModel):
    persona_id: Literal["admin", "testuser", "test2", "sha256", "defaultpk", "conflict"] = Field(
        default="admin",
        description="Allow-listed governance persona ID to impersonate in BigQuery",
    )
    query_id: Literal[
        "single_table_customers",
        "join_customers_orders",
        "join_4table_mesh",
        "agg_spend_by_customer",
        "rainbow_attack_lab",
        "single_table_orders",
    ] = Field(
        default="join_customers_orders",
        description="Allow-listed pre-registered GoogleSQL query template ID",
    )
    loyalty_tier: Literal["ALL", "PLATINUM", "GOLD", "SILVER"] = Field(
        default="ALL",
        description="Optional parameterized filter on customer loyalty tier",
    )


class CompareRequest(BaseModel):
    query_id: Literal[
        "single_table_customers",
        "join_customers_orders",
        "join_4table_mesh",
        "agg_spend_by_customer",
        "rainbow_attack_lab",
        "single_table_orders",
    ] = Field(
        default="join_customers_orders",
        description="Allow-listed pre-registered GoogleSQL query template ID to compare across personas",
    )
    persona_ids: list[Literal["admin", "testuser", "test2", "sha256", "defaultpk", "conflict"]] = Field(
        default=["admin", "testuser", "test2", "sha256", "defaultpk", "conflict"],
        description="List of personas to execute in parallel against live BigQuery",
    )
    loyalty_tier: Literal["ALL", "PLATINUM", "GOLD", "SILVER"] = Field(
        default="ALL",
        description="Optional parameterized filter on customer loyalty tier",
    )


app = FastAPI(
    title="BigQuery Multi-Policy PK/FK Dynamic Data Masking Live Demo",
    version="1.0.0",
    description="Executive live demonstration of multiple BigQuery Data Policies on a Primary/Foreign Key Policy Tag.",
)

# TODO(security): Enterprise OAuth/OIDC session authentication, MFA, and CSRF tokens are
# intentionally omitted because this local Proof-of-Value backend binds strictly to 127.0.0.1
# and executes read-only, pre-registered BigQuery SELECT templates via local ADC impersonation.
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5178",
        "http://localhost:5178",
        "http://127.0.0.1:8088",
        "http://localhost:8088",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next) -> Response:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' http://127.0.0.1:8088 http://localhost:8088; "
        "frame-src 'self'; "
        "frame-ancestors 'self';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/api/health")
def get_health() -> dict[str, Any]:
    return {
        "status": "ok",
        "project_id": PROJECT_ID,
        "location": LOCATION,
        "dataset_id": DATASET_ID,
    }


@app.get("/api/overview")
def get_overview() -> dict[str, Any]:
    state = load_provisioned_state()
    verification = load_verification_report()
    taxonomy_id = state["taxonomy"]["id"]

    console_links = {
        "bigquery_dataset": f"https://console.cloud.google.com/bigquery?project={PROJECT_ID}&ws=!1m4!1m3!3m2!1s{PROJECT_ID}!2s{DATASET_ID}",
        "table_customers": f"https://console.cloud.google.com/bigquery?project={PROJECT_ID}&ws=!1m5!1m4!4m3!1s{PROJECT_ID}!2s{DATASET_ID}!3scustomers",
        "table_orders": f"https://console.cloud.google.com/bigquery?project={PROJECT_ID}&ws=!1m5!1m4!4m3!1s{PROJECT_ID}!2s{DATASET_ID}!3sorders",
        "table_support_tickets": f"https://console.cloud.google.com/bigquery?project={PROJECT_ID}&ws=!1m5!1m4!4m3!1s{PROJECT_ID}!2s{DATASET_ID}!3ssupport_tickets",
        "table_loyalty_ledger": f"https://console.cloud.google.com/bigquery?project={PROJECT_ID}&ws=!1m5!1m4!4m3!1s{PROJECT_ID}!2s{DATASET_ID}!3sloyalty_ledger",
        "routine_salted_sha256": f"https://console.cloud.google.com/bigquery?project={PROJECT_ID}&ws=!1m5!1m4!6m3!1s{PROJECT_ID}!2s{DATASET_ID}!3sfn_salted_sha256",
        "policy_tag_taxonomy": f"https://console.cloud.google.com/dataplex/taxonomies/{taxonomy_id}?project={PROJECT_ID}&location={LOCATION}",
        "docs_column_masking": "https://cloud.google.com/bigquery/docs/column-data-masking-intro",
    }

    sql_schema = SQL_SCHEMA_FILE.read_text() if SQL_SCHEMA_FILE.exists() else ""
    sql_verify = SQL_VERIFY_FILE.read_text() if SQL_VERIFY_FILE.exists() else ""

    return {
        "state": state,
        "verification_report": verification,
        "masking_hierarchy": MASKING_RULE_HIERARCHY,
        "queries": list(QUERY_CATALOG.values()),
        "console_links": console_links,
        "sql_scripts": {
            "schema_and_udf": sql_schema,
            "verification_queries": sql_verify,
        },
    }


@app.post("/api/query")
def post_query(req: QueryRequest) -> dict[str, Any]:
    return execute_impersonated_query(
        persona_id=req.persona_id,
        query_id=req.query_id,
        loyalty_tier=req.loyalty_tier,
    )


@app.post("/api/compare")
def post_compare(req: CompareRequest) -> dict[str, Any]:
    t0 = time.perf_counter()
    results_by_persona: dict[str, Any] = {}

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = {
            p_id: pool.submit(
                execute_impersonated_query,
                persona_id=p_id,
                query_id=req.query_id,
                loyalty_tier=req.loyalty_tier,
            )
            for p_id in req.persona_ids
        }
        for p_id, fut in futures.items():
            results_by_persona[p_id] = fut.result()

    total_elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)
    q_meta = QUERY_CATALOG[req.query_id]

    return {
        "query_id": req.query_id,
        "query_title": q_meta["title"],
        "query_subtitle": q_meta["subtitle"],
        "expected_insight": q_meta["expected_insight"],
        "sql_executed": q_meta["sql"],
        "loyalty_tier_filter": req.loyalty_tier,
        "total_wall_ms": total_elapsed_ms,
        "results": [results_by_persona[p_id] for p_id in req.persona_ids],
    }


if FRONTEND_DIST.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIST), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    # Bind strictly to 127.0.0.1 per mandatory-secure-web-skills
    uvicorn.run(app, host="127.0.0.1", port=8088)
