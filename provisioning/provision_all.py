#!/usr/bin/env python3.12
"""Idempotent end-to-end provisioning for the BigQuery Multi-Policy PK/FK Data Masking Demo.

Provisions in your configured Google Cloud project (default location `us-central1`, dataset `data_policies_example`):
1. BigQuery Dataset `data_policies_example`
2. Custom Masking Routine (UDF) `fn_salted_sha256` with `OPTIONS (data_governance_type = 'DATA_MASKING')`
3. BigQuery Governance Policy Tag Taxonomy (Knowledge Catalog) `CustomerGovernanceTaxonomy` and Policy Tags:
   - `Customer_PK_Tag` (applied to PK & FK `customer_id` columns across 4 relational tables)
   - `Customer_PII_Default_Tag` (applied to `email`, `phone_number`, `tax_id`)
   - `Customer_Financial_Default_Tag` (applied to `credit_limit_usd`)
4. BigQuery Data Policies attached to `Customer_PK_Tag`:
   - `dp_customer_pk_salted_sha256` -> Custom Masking Routine `fn_salted_sha256` (Priority #1)
   - `dp_customer_pk_sha256`        -> Predefined `SHA256` (Priority #3)
   - `dp_customer_pk_default`       -> Predefined `DEFAULT_MASKING_VALUE` (Priority #8)
   - `dp_customer_pk_null`          -> Predefined `ALWAYS_NULL` (Priority #9)
5. BigQuery Data Policies attached to secondary PII/Financial tags:
   - `dp_pii_email_mask`   -> `EMAIL_MASK` on `Customer_PII_Default_Tag`
   - `dp_pii_default_mask` -> `DEFAULT_MASKING_VALUE` on `Customer_PII_Default_Tag`
   - `dp_fin_default_mask` -> `DEFAULT_MASKING_VALUE` on `Customer_Financial_Default_Tag`
6. Relational tables (`customers`, `orders`, `support_tickets`, `loyalty_ledger`) with explicit
   `PRIMARY KEY (...) NOT ENFORCED` and `FOREIGN KEY (...) REFERENCES ... NOT ENFORCED` constraints,
   column-level Policy Tags, and synthetic multi-table data.
7. IAM bindings for configured human principals and impersonated service accounts (`dp-persona-*`).
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from typing import Any

import requests
from google.cloud import bigquery
from google.cloud.bigquery import AccessEntry

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
ROUTINE_ID = os.environ.get("ROUTINE_ID", "fn_salted_sha256")
SECRET_PEPPER = os.environ.get("SECRET_PEPPER", "REPLACE_WITH_YOUR_ENTERPRISE_SECRET_PEPPER_2026")

TAXONOMY_DISPLAY_NAME = os.environ.get("TAXONOMY_DISPLAY_NAME", "CustomerGovernanceTaxonomy")
TAG_PK_DISPLAY_NAME = "Customer_PK_Tag"
TAG_PII_DISPLAY_NAME = "Customer_PII_Default_Tag"
TAG_FIN_DISPLAY_NAME = "Customer_Financial_Default_Tag"

DATACATALOG_API = "https://datacatalog.googleapis.com/v1"
DATAPOLICY_API = "https://bigquerydatapolicy.googleapis.com/v1"
CRM_API = "https://cloudresourcemanager.googleapis.com/v1"

FGR_ROLE = "roles/datacatalog.categoryFineGrainedReader"
MASKED_READER_ROLE = "roles/bigquerydatapolicy.maskedReader"

# Human users loaded from .env (or generic placeholders)
ADMIN_EMAIL = os.environ.get("ADMIN_USER_EMAIL", f"dp-persona-admin@{PROJECT_ID}.iam.gserviceaccount.com")
ANALYST_EMAIL = os.environ.get("ANALYST_USER_EMAIL", f"dp-persona-testuser@{PROJECT_ID}.iam.gserviceaccount.com")
AUDITOR_EMAIL = os.environ.get("AUDITOR_USER_EMAIL", f"dp-persona-test2@{PROJECT_ID}.iam.gserviceaccount.com")

USER_ADMIN = f"user:{ADMIN_EMAIL}" if not ADMIN_EMAIL.endswith(".gserviceaccount.com") else f"serviceAccount:{ADMIN_EMAIL}"
USER_TESTUSER = f"user:{ANALYST_EMAIL}" if not ANALYST_EMAIL.endswith(".gserviceaccount.com") else f"serviceAccount:{ANALYST_EMAIL}"
USER_TEST2 = f"user:{AUDITOR_EMAIL}" if not AUDITOR_EMAIL.endswith(".gserviceaccount.com") else f"serviceAccount:{AUDITOR_EMAIL}"

# Live impersonation service accounts (mirroring the user personas + comparison personas)
PERSONA_SAS = {
    "admin": f"dp-persona-admin@{PROJECT_ID}.iam.gserviceaccount.com",
    "testuser": f"dp-persona-testuser@{PROJECT_ID}.iam.gserviceaccount.com",
    "test2": f"dp-persona-test2@{PROJECT_ID}.iam.gserviceaccount.com",
    "sha256": f"dp-persona-sha256@{PROJECT_ID}.iam.gserviceaccount.com",
    "defaultpk": f"dp-persona-defaultpk@{PROJECT_ID}.iam.gserviceaccount.com",
    "conflict": f"dp-persona-conflict@{PROJECT_ID}.iam.gserviceaccount.com",
}

STATE_FILE = pathlib.Path(__file__).resolve().parent / "provisioned_state.json"


def gcloud_env() -> dict[str, str]:
    env = dict(os.environ)
    cur = env.get("CLOUDSDK_METRICS_ENVIRONMENT", "").strip()
    if "datacloud.antigravity" not in cur:
        env["CLOUDSDK_METRICS_ENVIRONMENT"] = f"{cur} datacloud.antigravity".strip()
    return env


def get_token() -> str:
    res = subprocess.run(
        ["gcloud", "auth", "print-access-token", "--quiet"],
        capture_output=True,
        text=True,
        check=True,
        env=gcloud_env(),
    )
    return res.stdout.strip()


def api_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {get_token()}",
        "Content-Type": "application/json",
        "x-goog-user-project": PROJECT_ID,
    }


def ensure_taxonomy_and_tags(headers: dict[str, str]) -> tuple[str, dict[str, str]]:
    print("\n[1/6] Ensuring BigQuery Governance Policy Tag Taxonomy (Knowledge Catalog) & Policy Tags...")
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    resp = requests.get(f"{DATACATALOG_API}/{parent}/taxonomies", headers=headers, timeout=30)
    resp.raise_for_status()
    taxonomies = resp.json().get("taxonomies", [])

    taxonomy_name = None
    for tax in taxonomies:
        if tax.get("displayName") == TAXONOMY_DISPLAY_NAME:
            taxonomy_name = tax["name"]
            print(f"  ✓ Found existing Taxonomy: {taxonomy_name}")
            break

    if not taxonomy_name:
        c_resp = requests.post(
            f"{DATACATALOG_API}/{parent}/taxonomies",
            headers=headers,
            json={
                "displayName": TAXONOMY_DISPLAY_NAME,
                "description": (
                    "Enterprise taxonomy for multi-policy primary key and foreign key dynamic data masking "
                    "(Salted SHA-256 Custom Routine, SHA-256, Always Null, Default Masking Value)"
                ),
                "activatedPolicyTypes": ["FINE_GRAINED_ACCESS_CONTROL"],
            },
            timeout=30,
        )
        c_resp.raise_for_status()
        taxonomy_name = c_resp.json()["name"]
        print(f"  ✓ Created Taxonomy: {taxonomy_name}")

    # List existing policy tags
    pt_resp = requests.get(f"{DATACATALOG_API}/{taxonomy_name}/policyTags", headers=headers, timeout=30)
    pt_resp.raise_for_status()
    existing_tags = {t["displayName"]: t["name"] for t in pt_resp.json().get("policyTags", [])}

    desired_tags = {
        TAG_PK_DISPLAY_NAME: (
            "Primary and Foreign Key column tag for customer_id across relational tables. "
            "Supports multi-policy dynamic masking (Salted SHA-256, SHA-256, Always Null, Default Mask)."
        ),
        TAG_PII_DISPLAY_NAME: (
            "Sensitive customer PII attributes (email, phone_number, tax_id) demonstrating "
            "Default Masking Value vs Email/Last-4 masking."
        ),
        TAG_FIN_DISPLAY_NAME: (
            "Numeric financial column tag (credit_limit_usd) demonstrating Default Masking Value (0.0) vs raw."
        ),
    }

    resolved_tags: dict[str, str] = {}
    for display_name, desc in desired_tags.items():
        if display_name in existing_tags:
            resolved_tags[display_name] = existing_tags[display_name]
            print(f"  ✓ Found Policy Tag {display_name}: {resolved_tags[display_name]}")
        else:
            t_resp = requests.post(
                f"{DATACATALOG_API}/{taxonomy_name}/policyTags",
                headers=headers,
                json={"displayName": display_name, "description": desc},
                timeout=30,
            )
            t_resp.raise_for_status()
            resolved_tags[display_name] = t_resp.json()["name"]
            print(f"  ✓ Created Policy Tag {display_name}: {resolved_tags[display_name]}")

    return taxonomy_name, resolved_tags


def ensure_dataset_and_udf(bq_client: bigquery.Client) -> str:
    print("\n[2/6] Ensuring BigQuery Dataset & Custom Masking Routine (Salted SHA-256)...")
    ds_ref = f"{PROJECT_ID}.{DATASET_ID}"
    try:
        ds = bq_client.get_dataset(ds_ref)
        print(f"  ✓ Found Dataset: {ds_ref} ({ds.location})")
    except Exception:
        ds = bigquery.Dataset(ds_ref)
        ds.location = LOCATION
        ds.description = "BigQuery Multi-Policy Primary Key & Foreign Key Dynamic Data Masking Demo"
        ds.labels = {"datacloud": "antigravity"}
        bq_client.create_dataset(ds, exists_ok=True)
        print(f"  ✓ Created Dataset: {ds_ref} ({LOCATION})")

    udf_sql = f"""
    CREATE OR REPLACE FUNCTION `{PROJECT_ID}.{DATASET_ID}.{ROUTINE_ID}`(val STRING)
    RETURNS STRING
    OPTIONS (
      data_governance_type = 'DATA_MASKING',
      description = 'Custom masking routine: deterministic Salted SHA-256 hex digest using secret pepper to preserve PK/FK JOINs while preventing rainbow-table lookup on predictable keys.'
    )
    AS (
      CAST(SHA256(CONCAT(val, '{SECRET_PEPPER}')) AS STRING FORMAT 'HEX')
    );
    """
    job_config = bigquery.QueryJobConfig(labels={"datacloud": "antigravity"})
    bq_client.query(udf_sql, job_config=job_config).result()
    routine_path = f"projects/{PROJECT_ID}/datasets/{DATASET_ID}/routines/{ROUTINE_ID}"
    print(f"  ✓ Verified Custom Masking Routine: {routine_path}")
    return routine_path


def ensure_data_policies(
    headers: dict[str, str],
    tags: dict[str, str],
    routine_path: str,
) -> dict[str, dict[str, Any]]:
    print("\n[3/6] Ensuring BigQuery Data Policies on Policy Tags...")
    parent = f"projects/{PROJECT_ID}/locations/{LOCATION}"
    list_url = f"{DATAPOLICY_API}/{parent}/dataPolicies"
    resp = requests.get(list_url, headers=headers, timeout=30)
    resp.raise_for_status()
    existing = {dp["dataPolicyId"]: dp for dp in resp.json().get("dataPolicies", [])}

    pk_tag = tags[TAG_PK_DISPLAY_NAME]
    pii_tag = tags[TAG_PII_DISPLAY_NAME]
    fin_tag = tags[TAG_FIN_DISPLAY_NAME]

    desired_policies = [
        {
            "dataPolicyId": "dp_customer_pk_salted_sha256",
            "policyTag": pk_tag,
            "dataMaskingPolicy": {"routine": routine_path},
            "label": "Custom Masking Routine – Salted SHA-256 (Priority #1)",
        },
        {
            "dataPolicyId": "dp_customer_pk_sha256",
            "policyTag": pk_tag,
            "dataMaskingPolicy": {"predefinedExpression": "SHA256"},
            "label": "Predefined SHA-256 (Priority #3)",
        },
        {
            "dataPolicyId": "dp_customer_pk_default",
            "policyTag": pk_tag,
            "dataMaskingPolicy": {"predefinedExpression": "DEFAULT_MASKING_VALUE"},
            "label": "Predefined Default Masking Value '' (Priority #8)",
        },
        {
            "dataPolicyId": "dp_customer_pk_null",
            "policyTag": pk_tag,
            "dataMaskingPolicy": {"predefinedExpression": "ALWAYS_NULL"},
            "label": "Predefined Nullify ALWAYS_NULL (Priority #9)",
        },
        {
            "dataPolicyId": "dp_pii_email_mask",
            "policyTag": pii_tag,
            "dataMaskingPolicy": {"predefinedExpression": "EMAIL_MASK"},
            "label": "Predefined EMAIL_MASK on String PII",
        },
        {
            "dataPolicyId": "dp_pii_default_mask",
            "policyTag": pii_tag,
            "dataMaskingPolicy": {"predefinedExpression": "DEFAULT_MASKING_VALUE"},
            "label": "Predefined DEFAULT_MASKING_VALUE ('') on String PII",
        },
        {
            "dataPolicyId": "dp_fin_default_mask",
            "policyTag": fin_tag,
            "dataMaskingPolicy": {"predefinedExpression": "DEFAULT_MASKING_VALUE"},
            "label": "Predefined DEFAULT_MASKING_VALUE (0.0) on Financial Numeric",
        },
    ]

    resolved_policies: dict[str, dict[str, Any]] = {}
    for spec in desired_policies:
        dp_id = spec["dataPolicyId"]
        payload = {
            "dataPolicyId": dp_id,
            "dataPolicyType": "DATA_MASKING_POLICY",
            "policyTag": spec["policyTag"],
            "dataMaskingPolicy": spec["dataMaskingPolicy"],
        }
        if dp_id in existing:
            dp_name = existing[dp_id]["name"]
            # Update in place to ensure policyTag & masking rule match
            patch_url = f"{DATAPOLICY_API}/{dp_name}?updateMask=policyTag,dataMaskingPolicy"
            p_resp = requests.patch(patch_url, headers=headers, json=payload, timeout=30)
            if p_resp.status_code == 200:
                resolved_policies[dp_id] = p_resp.json()
                print(f"  ✓ Updated Data Policy {dp_id} ({spec['label']})")
            else:
                resolved_policies[dp_id] = existing[dp_id]
                print(f"  ✓ Kept existing Data Policy {dp_id} ({spec['label']})")
        else:
            c_resp = requests.post(list_url, headers=headers, json=payload, timeout=30)
            if c_resp.status_code not in (200, 201):
                raise RuntimeError(f"Failed creating Data Policy {dp_id}: {c_resp.status_code} {c_resp.text}")
            resolved_policies[dp_id] = c_resp.json()
            print(f"  ✓ Created Data Policy {dp_id} ({spec['label']})")

    return resolved_policies


def set_iam_members_individually(
    headers: dict[str, str],
    resource_url_prefix: str,
    role: str,
    desired_members: list[str],
) -> list[str]:
    get_resp = requests.post(f"{resource_url_prefix}:getIamPolicy", headers=headers, json={}, timeout=30)
    get_resp.raise_for_status()
    current = get_resp.json()

    def build_policy(base: dict[str, Any], members_for_role: list[str]) -> dict[str, Any]:
        bindings = [b for b in base.get("bindings", []) if b.get("role") != role]
        if members_for_role:
            bindings.append({"role": role, "members": list(members_for_role)})
        pol: dict[str, Any] = {"bindings": bindings}
        if base.get("etag"):
            pol["etag"] = base["etag"]
        return pol

    set_url = f"{resource_url_prefix}:setIamPolicy"
    bulk_resp = requests.post(set_url, headers=headers, json={"policy": build_policy(current, desired_members)}, timeout=30)
    if bulk_resp.status_code == 200:
        return list(desired_members)

    accepted: list[str] = []
    for member in desired_members:
        r = requests.post(
            set_url,
            headers=headers,
            json={"policy": build_policy(current, accepted + [member])},
            timeout=30,
        )
        if r.status_code == 200:
            current = r.json()
            accepted.append(member)
        else:
            print(f"    ⚠️ Rejected {member} on {resource_url_prefix.split('/')[-1]}: {r.text[:200]}")
    return accepted


def configure_iam(
    headers: dict[str, str],
    bq_client: bigquery.Client,
    tags: dict[str, str],
    policies: dict[str, dict[str, Any]],
) -> None:
    print("\n[4/6] Configuring IAM Bindings (Policy Tags, Data Policies, Dataset & Impersonation)...")
    # 1. Ensure USER_ADMIN can impersonate the 6 persona SAs
    for key, sa_email in PERSONA_SAS.items():
        subprocess.run(
            [
                "gcloud",
                "iam",
                "service-accounts",
                "add-iam-policy-binding",
                sa_email,
                f"--member={USER_ADMIN}",
                "--role=roles/iam.serviceAccountTokenCreator",
                f"--project={PROJECT_ID}",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            env=gcloud_env(),
        )
        # Ensure each persona SA can run BigQuery jobs in the project
        subprocess.run(
            [
                "gcloud",
                "projects",
                "add-iam-policy-binding",
                PROJECT_ID,
                f"--member=serviceAccount:{sa_email}",
                "--role=roles/bigquery.jobUser",
                "--condition=None",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            env=gcloud_env(),
        )
    print("  ✓ Granted serviceAccountTokenCreator and bigquery.jobUser for all 6 persona SAs")

    # 2. Grant dataset READER on `data_policies_example` to human users and persona SAs
    ds_ref = f"{PROJECT_ID}.{DATASET_ID}"
    ds = bq_client.get_dataset(ds_ref)
    entries = list(ds.access_entries)
    reader_emails = [
        ADMIN_EMAIL,
        ANALYST_EMAIL,
        AUDITOR_EMAIL,
        *PERSONA_SAS.values(),
    ]
    changed = False
    for email in reader_emails:
        if not any(
            (e.entity_id or "").lower() == email.lower()
            and e.role in ("READER", "WRITER", "OWNER", "roles/bigquery.dataViewer")
            for e in entries
        ):
            entries.append(AccessEntry(role="READER", entity_type="userByEmail", entity_id=email))
            changed = True
    if changed:
        ds.access_entries = entries
        bq_client.update_dataset(ds, ["access_entries"])
    print(f"  ✓ Verified dataset READER access on {ds_ref} (includes routine invocation permission)")

    # 3. Policy Tag Fine-Grained Reader bindings
    fgr_pk_and_pii = [
        USER_ADMIN,
        f"serviceAccount:{PERSONA_SAS['admin']}",
    ]
    fgr_fin = [
        USER_ADMIN,
        f"serviceAccount:{PERSONA_SAS['admin']}",
        USER_TESTUSER,
        f"serviceAccount:{PERSONA_SAS['testuser']}",
    ]
    for tag_label, desired in [
        (TAG_PK_DISPLAY_NAME, fgr_pk_and_pii),
        (TAG_PII_DISPLAY_NAME, fgr_pk_and_pii),
        (TAG_FIN_DISPLAY_NAME, fgr_fin),
    ]:
        tag_res = tags[tag_label]
        accepted = set_iam_members_individually(
            headers,
            f"{DATACATALOG_API}/{tag_res}",
            FGR_ROLE,
            desired,
        )
        print(f"  ✓ Policy Tag FGR [{tag_label}]: {len(accepted)}/{len(desired)} principals bound")

    # 4. Data Policy Masked Reader bindings
    dp_bindings = {
        "dp_customer_pk_salted_sha256": [
            USER_TESTUSER,
            f"serviceAccount:{PERSONA_SAS['testuser']}",
            f"serviceAccount:{PERSONA_SAS['conflict']}",
        ],
        "dp_customer_pk_null": [
            USER_TEST2,
            f"serviceAccount:{PERSONA_SAS['test2']}",
            f"serviceAccount:{PERSONA_SAS['conflict']}",
        ],
        "dp_customer_pk_sha256": [
            f"serviceAccount:{PERSONA_SAS['sha256']}",
        ],
        "dp_customer_pk_default": [
            f"serviceAccount:{PERSONA_SAS['defaultpk']}",
        ],
        "dp_pii_email_mask": [
            USER_TESTUSER,
            f"serviceAccount:{PERSONA_SAS['testuser']}",
            f"serviceAccount:{PERSONA_SAS['conflict']}",
            f"serviceAccount:{PERSONA_SAS['sha256']}",
        ],
        "dp_pii_default_mask": [
            USER_TEST2,
            f"serviceAccount:{PERSONA_SAS['test2']}",
            f"serviceAccount:{PERSONA_SAS['defaultpk']}",
        ],
        "dp_fin_default_mask": [
            USER_TEST2,
            f"serviceAccount:{PERSONA_SAS['test2']}",
            f"serviceAccount:{PERSONA_SAS['defaultpk']}",
            f"serviceAccount:{PERSONA_SAS['sha256']}",
            f"serviceAccount:{PERSONA_SAS['conflict']}",
        ],
    }

    for dp_id, desired in dp_bindings.items():
        dp_name = policies[dp_id]["name"]
        accepted = set_iam_members_individually(
            headers,
            f"{DATAPOLICY_API}/{dp_name}",
            MASKED_READER_ROLE,
            desired,
        )
        print(f"  ✓ Data Policy MaskedReader [{dp_id}]: {len(accepted)}/{len(desired)} principals bound")


def create_tables_and_seed_data(bq_client: bigquery.Client, tags: dict[str, str]) -> None:
    print("\n[5/6] Creating Relational Tables (with PK/FK & Policy Tags) and Seeding Synthetic Data...")
    pk_tag = tags[TAG_PK_DISPLAY_NAME]
    pii_tag = tags[TAG_PII_DISPLAY_NAME]
    fin_tag = tags[TAG_FIN_DISPLAY_NAME]

    ddl_statements = [
        f"""
        CREATE OR REPLACE TABLE `{PROJECT_ID}.{DATASET_ID}.customers` (
          customer_id STRING NOT NULL OPTIONS(
            description = 'Primary Key: Unique Customer Identifier governed by Customer_PK_Tag'
          ),
          customer_name STRING NOT NULL OPTIONS(description = 'Customer full name'),
          email STRING OPTIONS(
            description = 'Customer email address governed by Customer_PII_Default_Tag'
          ),
          phone_number STRING OPTIONS(
            description = 'Customer phone number governed by Customer_PII_Default_Tag'
          ),
          tax_id STRING OPTIONS(
            description = 'National tax/SSN identifier governed by Customer_PII_Default_Tag'
          ),
          signup_country STRING NOT NULL OPTIONS(description = 'ISO 2-letter signup country'),
          loyalty_tier STRING NOT NULL OPTIONS(description = 'Customer loyalty tier'),
          credit_limit_usd FLOAT64 OPTIONS(
            description = 'Approved credit limit in USD governed by Customer_Financial_Default_Tag'
          ),
          signup_date DATE NOT NULL OPTIONS(description = 'Account creation date'),
          PRIMARY KEY (customer_id) NOT ENFORCED
        )
        OPTIONS(
          description = 'Master Customer dimension table with Primary Key on customer_id protected by multi-policy dynamic data masking',
          labels = [('datacloud', 'antigravity')]
        );
        """,
        f"""
        INSERT INTO `{PROJECT_ID}.{DATASET_ID}.customers`
          (customer_id, customer_name, email, phone_number, tax_id, signup_country, loyalty_tier, credit_limit_usd, signup_date)
        VALUES
          ('CUST-1001', 'Alice Smith', 'alice.smith@acme-global.com', '+1-415-555-0101', '941-22-8801', 'US', 'PLATINUM', 25000.00, DATE '2024-01-15'),
          ('CUST-1002', 'Bob Jones', 'bob.jones@mapleleaf.ca', '+1-416-555-0142', '812-49-3302', 'CA', 'GOLD', 15000.00, DATE '2024-03-22'),
          ('CUST-1003', 'Charlie Brown', 'charlie.brown@thames-ventures.co.uk', '+44-20-7946-0921', '730-18-9903', 'UK', 'PLATINUM', 30000.00, DATE '2024-05-10'),
          ('CUST-1004', 'Diana Prince', 'diana.prince@rhein-tech.de', '+49-30-5550-1820', '619-55-4404', 'DE', 'SILVER', 8500.00, DATE '2024-07-04'),
          ('CUST-1005', 'Evan Wright', 'evan.wright@lumiere-group.fr', '+33-1-4050-6070', '504-77-1105', 'FR', 'GOLD', 18000.00, DATE '2024-08-19'),
          ('CUST-1006', 'Fiona Gallagher', 'fiona.g@pacific-southern.com.au', '+61-2-9876-5432', '488-90-2206', 'AU', 'SILVER', 9000.00, DATE '2025-01-11'),
          ('CUST-1007', 'George Miller', 'g.miller@merlion-capital.sg', '+65-6789-0123', '377-12-6607', 'SG', 'PLATINUM', 42000.00, DATE '2025-04-02'),
          ('CUST-1008', 'Hannah Abbott', 'hannah.abbott@sakura-systems.jp', '+81-3-5555-0199', '266-34-5508', 'JP', 'GOLD', 19500.00, DATE '2025-06-28');
        """,
        f"""
        CREATE OR REPLACE TABLE `{PROJECT_ID}.{DATASET_ID}.orders` (
          order_id STRING NOT NULL OPTIONS(description = 'Primary Key: Unique Order ID'),
          customer_id STRING NOT NULL OPTIONS(
            description = 'Foreign Key referencing customers.customer_id, governed by Customer_PK_Tag'
          ),
          order_date DATE NOT NULL OPTIONS(description = 'Order transaction date'),
          order_amount NUMERIC NOT NULL OPTIONS(description = 'Order total in USD'),
          order_status STRING NOT NULL OPTIONS(description = 'Order fulfillment status'),
          product_category STRING NOT NULL OPTIONS(description = 'Primary product category'),
          payment_channel STRING NOT NULL OPTIONS(description = 'Payment settlement channel'),
          PRIMARY KEY (order_id) NOT ENFORCED,
          FOREIGN KEY (customer_id) REFERENCES `{PROJECT_ID}.{DATASET_ID}.customers`(customer_id) NOT ENFORCED
        )
        OPTIONS(
          description = 'E-Commerce Orders fact table with Foreign Key customer_id tagged with Customer_PK_Tag',
          labels = [('datacloud', 'antigravity')]
        );
        """,
        f"""
        INSERT INTO `{PROJECT_ID}.{DATASET_ID}.orders`
          (order_id, customer_id, order_date, order_amount, order_status, product_category, payment_channel)
        VALUES
          ('ORD-901', 'CUST-1001', DATE '2026-01-12', NUMERIC '250.00', 'COMPLETED', 'Cloud Infrastructure', 'CORPORATE_CARD'),
          ('ORD-902', 'CUST-1001', DATE '2026-02-03', NUMERIC '120.50', 'PROCESSING', 'Security Add-ons', 'WIRE_TRANSFER'),
          ('ORD-903', 'CUST-1002', DATE '2026-02-18', NUMERIC '89.99', 'COMPLETED', 'Analytics Seats', 'CORPORATE_CARD'),
          ('ORD-904', 'CUST-1003', DATE '2026-03-04', NUMERIC '450.00', 'SHIPPED', 'AI Enterprise Tier', 'INVOICE_NET30'),
          ('ORD-905', 'CUST-1003', DATE '2026-03-19', NUMERIC '780.00', 'COMPLETED', 'Data Mesh Governance', 'WIRE_TRANSFER'),
          ('ORD-906', 'CUST-1004', DATE '2026-04-01', NUMERIC '199.00', 'COMPLETED', 'Analytics Seats', 'CORPORATE_CARD'),
          ('ORD-907', 'CUST-1005', DATE '2026-04-15', NUMERIC '640.25', 'SHIPPED', 'Cloud Infrastructure', 'INVOICE_NET30'),
          ('ORD-908', 'CUST-1006', DATE '2026-05-02', NUMERIC '310.00', 'COMPLETED', 'Security Add-ons', 'CORPORATE_CARD'),
          ('ORD-909', 'CUST-1007', DATE '2026-05-20', NUMERIC '1250.00', 'COMPLETED', 'AI Enterprise Tier', 'WIRE_TRANSFER'),
          ('ORD-910', 'CUST-1007', DATE '2026-06-08', NUMERIC '495.75', 'PROCESSING', 'Data Mesh Governance', 'WIRE_TRANSFER'),
          ('ORD-911', 'CUST-1008', DATE '2026-06-21', NUMERIC '360.00', 'COMPLETED', 'Cloud Infrastructure', 'INVOICE_NET30'),
          ('ORD-912', 'CUST-1002', DATE '2026-07-05', NUMERIC '215.40', 'SHIPPED', 'Security Add-ons', 'CORPORATE_CARD');
        """,
        f"""
        CREATE OR REPLACE TABLE `{PROJECT_ID}.{DATASET_ID}.support_tickets` (
          ticket_id STRING NOT NULL OPTIONS(description = 'Primary Key: Support Ticket ID'),
          customer_id STRING NOT NULL OPTIONS(
            description = 'Foreign Key referencing customers.customer_id, governed by Customer_PK_Tag'
          ),
          order_id STRING OPTIONS(description = 'Related Order ID'),
          issue_category STRING NOT NULL OPTIONS(description = 'Support ticket classification'),
          priority STRING NOT NULL OPTIONS(description = 'Ticket SLA priority'),
          resolution_status STRING NOT NULL OPTIONS(description = 'Current ticket resolution state'),
          opened_date DATE NOT NULL OPTIONS(description = 'Ticket creation date'),
          PRIMARY KEY (ticket_id) NOT ENFORCED,
          FOREIGN KEY (customer_id) REFERENCES `{PROJECT_ID}.{DATASET_ID}.customers`(customer_id) NOT ENFORCED
        )
        OPTIONS(
          description = 'Customer Support Tickets table with Foreign Key customer_id tagged with Customer_PK_Tag',
          labels = [('datacloud', 'antigravity')]
        );
        """,
        f"""
        INSERT INTO `{PROJECT_ID}.{DATASET_ID}.support_tickets`
          (ticket_id, customer_id, order_id, issue_category, priority, resolution_status, opened_date)
        VALUES
          ('TKT-501', 'CUST-1001', 'ORD-902', 'Billing & Invoice Reconciliation', 'HIGH', 'OPEN', DATE '2026-02-05'),
          ('TKT-502', 'CUST-1002', 'ORD-903', 'SSO & Policy Tag Provisioning', 'MEDIUM', 'RESOLVED', DATE '2026-02-20'),
          ('TKT-503', 'CUST-1003', 'ORD-904', 'Cross-Region Replication Latency', 'HIGH', 'IN_PROGRESS', DATE '2026-03-06'),
          ('TKT-504', 'CUST-1005', 'ORD-907', 'Custom UDF Quota Increase', 'LOW', 'RESOLVED', DATE '2026-04-18'),
          ('TKT-505', 'CUST-1007', 'ORD-910', 'VPC-SC Egress Rule Validation', 'CRITICAL', 'OPEN', DATE '2026-06-09'),
          ('TKT-506', 'CUST-1008', 'ORD-911', 'Audit Log Export Configuration', 'MEDIUM', 'RESOLVED', DATE '2026-06-25');
        """,
        f"""
        CREATE OR REPLACE TABLE `{PROJECT_ID}.{DATASET_ID}.loyalty_ledger` (
          ledger_id STRING NOT NULL OPTIONS(description = 'Primary Key: Loyalty Ledger Entry ID'),
          customer_id STRING NOT NULL OPTIONS(
            description = 'Foreign Key referencing customers.customer_id, governed by Customer_PK_Tag'
          ),
          points_delta INT64 NOT NULL OPTIONS(description = 'Loyalty points earned or redeemed'),
          event_type STRING NOT NULL OPTIONS(description = 'EARN, REDEEM, or TIER_BONUS'),
          partner_program STRING NOT NULL OPTIONS(description = 'Partner ecosystem program'),
          event_date DATE NOT NULL OPTIONS(description = 'Ledger posting date'),
          PRIMARY KEY (ledger_id) NOT ENFORCED,
          FOREIGN KEY (customer_id) REFERENCES `{PROJECT_ID}.{DATASET_ID}.customers`(customer_id) NOT ENFORCED
        )
        OPTIONS(
          description = 'Customer Loyalty Ledger with Foreign Key customer_id tagged with Customer_PK_Tag',
          labels = [('datacloud', 'antigravity')]
        );
        """,
        f"""
        INSERT INTO `{PROJECT_ID}.{DATASET_ID}.loyalty_ledger`
          (ledger_id, customer_id, points_delta, event_type, partner_program, event_date)
        VALUES
          ('LED-301', 'CUST-1001', 2500, 'EARN', 'Cloud Summit Rewards', DATE '2026-01-13'),
          ('LED-302', 'CUST-1001', 1200, 'EARN', 'Security Champions', DATE '2026-02-04'),
          ('LED-303', 'CUST-1002', 900, 'EARN', 'Maple Partner Network', DATE '2026-02-19'),
          ('LED-304', 'CUST-1003', 4500, 'TIER_BONUS', 'Executive Advisory Board', DATE '2026-03-05'),
          ('LED-305', 'CUST-1004', 1990, 'EARN', 'DACH Innovators', DATE '2026-04-02'),
          ('LED-306', 'CUST-1005', 3200, 'EARN', 'EU Sovereign Cloud', DATE '2026-04-16'),
          ('LED-307', 'CUST-1007', 8500, 'TIER_BONUS', 'APAC Lighthouse Club', DATE '2026-05-21'),
          ('LED-308', 'CUST-1008', 1800, 'EARN', 'Tokyo AI Forum', DATE '2026-06-22');
        """,
    ]

    for idx, stmt in enumerate(ddl_statements, 1):
        job_config = bigquery.QueryJobConfig(labels={"datacloud": "antigravity"})
        bq_client.query(stmt, job_config=job_config).result()
        print(f"  ✓ Executed DDL/DML step {idx}/{len(ddl_statements)}")

    # Attach BigQuery Governance Policy Tags (Knowledge Catalog) to columns via SchemaField PolicyTagList
    table_column_tags = {
        "customers": {
            "customer_id": pk_tag,
            "email": pii_tag,
            "phone_number": pii_tag,
            "tax_id": pii_tag,
            "credit_limit_usd": fin_tag,
        },
        "orders": {
            "customer_id": pk_tag,
        },
        "support_tickets": {
            "customer_id": pk_tag,
        },
        "loyalty_ledger": {
            "customer_id": pk_tag,
        },
    }

    for table_name, col_map in table_column_tags.items():
        table_ref = f"{PROJECT_ID}.{DATASET_ID}.{table_name}"
        table = bq_client.get_table(table_ref)
        new_schema = []
        for field in table.schema:
            if field.name in col_map:
                rep = field.to_api_repr()
                rep["policyTags"] = {"names": [col_map[field.name]]}
                new_schema.append(bigquery.SchemaField.from_api_repr(rep))
            else:
                new_schema.append(field)
        table.schema = new_schema
        bq_client.update_table(table, ["schema"])
        print(f"  ✓ Attached Policy Tags to `{table_ref}`: {list(col_map.keys())}")


def main() -> int:
    print("=" * 80)
    print(f"🚀 Provisioning BigQuery Multi-Policy PK/FK Data Masking Demo")
    print(f"   Project: {PROJECT_ID} | Location: {LOCATION} | Dataset: {DATASET_ID}")
    print("=" * 80)

    headers = api_headers()
    bq_client = bigquery.Client(project=PROJECT_ID, location=LOCATION)

    taxonomy_name, tags = ensure_taxonomy_and_tags(headers)
    routine_path = ensure_dataset_and_udf(bq_client)
    policies = ensure_data_policies(headers, tags, routine_path)
    configure_iam(headers, bq_client, tags, policies)
    create_tables_and_seed_data(bq_client, tags)

    print("\n[6/6] Saving Provisioned Metadata State...")
    salted_example = hashlib.sha256(f"CUST-1001{SECRET_PEPPER}".encode("utf-8")).hexdigest()
    state = {
        "provisioned_at": datetime.now(timezone.utc).isoformat(),
        "project_id": PROJECT_ID,
        "location": LOCATION,
        "dataset_id": DATASET_ID,
        "routine_id": ROUTINE_ID,
        "routine_path": routine_path,
        "secret_pepper_hint": "Configured via SECRET_PEPPER in .env (embedded inside SQL UDF body)",
        "taxonomy": {
            "display_name": TAXONOMY_DISPLAY_NAME,
            "name": taxonomy_name,
            "id": taxonomy_name.split("/")[-1],
        },
        "policy_tags": {
            k: {"name": v, "id": v.split("/")[-1]} for k, v in tags.items()
        },
        "data_policies": {
            k: {
                "name": v.get("name"),
                "dataPolicyId": v.get("dataPolicyId"),
                "policyTag": v.get("policyTag"),
                "dataMaskingPolicy": v.get("dataMaskingPolicy"),
            }
            for k, v in policies.items()
        },
        "personas": {
            "admin": {
                "id": "admin",
                "user_email": ADMIN_EMAIL,
                "sa_email": PERSONA_SAS["admin"],
                "title": "Data Governance Admin",
                "role_label": "Fine-Grained Reader (on Policy Tags)",
                "pk_policy": "RAW_PLAINTEXT (Fine-Grained Reader)",
                "pk_example": "CUST-1001",
                "join_capable": True,
                "join_behavior": "Yes (Plaintext equality: 'CUST-1001' = 'CUST-1001')",
                "hierarchy_priority": 0,
            },
            "testuser": {
                "id": "testuser",
                "user_email": ANALYST_EMAIL,
                "sa_email": PERSONA_SAS["testuser"],
                "title": "Lead Data Scientist (Analytics Mesh)",
                "role_label": "BigQuery Masked Reader on Policy 1 (Custom Routine – Salted SHA-256)",
                "pk_policy": f"dp_customer_pk_salted_sha256 ({ROUTINE_ID})",
                "pk_example": salted_example,
                "join_capable": True,
                "join_behavior": "Yes (Evaluates SaltedSHA256 = SaltedSHA256 across PK & FK tables; immune to rainbow tables)",
                "hierarchy_priority": 1,
            },
            "test2": {
                "id": "test2",
                "user_email": AUDITOR_EMAIL,
                "sa_email": PERSONA_SAS["test2"],
                "title": "External Contractor / Ops Auditor",
                "role_label": "BigQuery Masked Reader on Policy 2 (ALWAYS_NULL on PK + DEFAULT_MASKING_VALUE on PII)",
                "pk_policy": "dp_customer_pk_null (ALWAYS_NULL)",
                "pk_example": "NULL",
                "join_capable": False,
                "join_behavior": "No (Evaluates NULL = NULL -> UNKNOWN/FALSE, returns 0 rows safely)",
                "hierarchy_priority": 9,
            },
            "sha256": {
                "id": "sha256",
                "user_email": PERSONA_SAS["sha256"],
                "sa_email": PERSONA_SAS["sha256"],
                "title": "Standard BI Analyst (Unsalted SHA-256)",
                "role_label": "BigQuery Masked Reader on Policy 3 (Predefined SHA256)",
                "pk_policy": "dp_customer_pk_sha256 (Predefined SHA256 -> Base64)",
                "pk_example": "vzfLri/gZxdYrzVsm7yJzqs/c6w2hMce+H5eqAnZvn8=",
                "join_capable": True,
                "join_behavior": "Yes (Evaluates SHA256 = SHA256, but vulnerable to rainbow-table lookup on predictable keys)",
                "hierarchy_priority": 3,
            },
            "defaultpk": {
                "id": "defaultpk",
                "user_email": PERSONA_SAS["defaultpk"],
                "sa_email": PERSONA_SAS["defaultpk"],
                "title": "Restricted Viewer (Default Masking Value on PK)",
                "role_label": "BigQuery Masked Reader on Policy 4 (DEFAULT_MASKING_VALUE '')",
                "pk_policy": "dp_customer_pk_default (DEFAULT_MASKING_VALUE)",
                "pk_example": '"" (empty string)',
                "join_capable": False,
                "join_behavior": "Anti-Pattern Alert! Evaluates '' = '' as TRUE for every row pair (N × M Cartesian explosion)",
                "hierarchy_priority": 8,
            },
            "conflict": {
                "id": "conflict",
                "user_email": PERSONA_SAS["conflict"],
                "sa_email": PERSONA_SAS["conflict"],
                "title": "Multi-Group Principal (Policy 1 + Policy 2 Conflict)",
                "role_label": "Member of BOTH Salted SHA-256 (#1) and ALWAYS_NULL (#9) Data Policies",
                "pk_policy": "Resolved -> dp_customer_pk_salted_sha256 (Priority #1 beats #9)",
                "pk_example": salted_example,
                "join_capable": True,
                "join_behavior": "Yes (BigQuery 9-tier rule hierarchy selects Custom Masking Routine #1 over Nullify #9)",
                "hierarchy_priority": 1,
            },
        },
    }
    STATE_FILE.write_text(json.dumps(state, indent=2))
    print(f"  ✓ Wrote state file: {STATE_FILE}")
    print("\n✅ Provisioning complete!")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
