-- =============================================================================
-- 02_verification_queries.sql
-- Multi-Persona Dynamic Data Masking Verification Queries
-- Run these as:
--   1. Data Governance Admin (Fine-Grained Reader -> Raw 'CUST-1001', Join Succeeds)
--   2. Lead Data Scientist   (Salted SHA-256 Masked Reader -> Salted Hex, Join Succeeds)
--   3. External Auditor      (ALWAYS_NULL on PK + DEFAULT_MASKING_VALUE -> NULL, Join Fails with 0 rows)
-- =============================================================================

-- Query 1: Single-Table Customer Inspection (PK + PII + Financial Columns)
SELECT
  customer_id,
  customer_name,
  email,
  phone_number,
  tax_id,
  signup_country,
  loyalty_tier,
  credit_limit_usd
FROM `YOUR_PROJECT_ID.data_policies_example.customers`
ORDER BY customer_name;

-- Query 2: Two-Table PK=FK Join (customers JOIN orders ON customer_id)
-- Demonstrates:
--   - admin:     'CUST-1001' = 'CUST-1001' (12 rows returned)
--   - testuser:  SaltedSHA256('CUST-1001') = SaltedSHA256('CUST-1001') (12 rows returned)
--   - test2:     NULL = NULL evaluates to UNKNOWN (0 rows returned)
--   - defaultpk: '' = '' evaluates to TRUE for all pairs (96 rows Cartesian explosion!)
SELECT
  o.order_id,
  c.customer_id AS customer_pk,
  o.customer_id AS order_fk,
  c.customer_name,
  c.email,
  c.credit_limit_usd,
  o.product_category,
  o.order_amount,
  o.order_status
FROM `YOUR_PROJECT_ID.data_policies_example.customers` AS c
INNER JOIN `YOUR_PROJECT_ID.data_policies_example.orders` AS o
  ON c.customer_id = o.customer_id
ORDER BY o.order_id;

-- Query 3: Four-Table Enterprise 360° Mesh Join (customers + orders + support_tickets + loyalty_ledger)
SELECT
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
FROM `YOUR_PROJECT_ID.data_policies_example.customers` AS c
INNER JOIN `YOUR_PROJECT_ID.data_policies_example.orders` AS o
  ON c.customer_id = o.customer_id
INNER JOIN `YOUR_PROJECT_ID.data_policies_example.support_tickets` AS t
  ON c.customer_id = t.customer_id AND o.order_id = t.order_id
INNER JOIN `YOUR_PROJECT_ID.data_policies_example.loyalty_ledger` AS l
  ON c.customer_id = l.customer_id
ORDER BY o.order_id, l.ledger_id;

-- Query 4: Customer Spend & Loyalty Aggregation across PK=FK Join
SELECT
  c.customer_id,
  c.signup_country,
  c.loyalty_tier,
  COUNT(DISTINCT o.order_id) AS total_orders,
  SUM(o.order_amount) AS total_spend_usd,
  MAX(c.credit_limit_usd) AS visible_credit_limit
FROM `YOUR_PROJECT_ID.data_policies_example.customers` AS c
INNER JOIN `YOUR_PROJECT_ID.data_policies_example.orders` AS o
  ON c.customer_id = o.customer_id
GROUP BY c.customer_id, c.signup_country, c.loyalty_tier
ORDER BY total_spend_usd DESC;

-- Query 5: Cryptographic Lab — Unsalted SHA-256 Rainbow Vulnerability vs. Salted SHA-256 UDF
-- Demonstrates why sequential IDs ('CUST-1001') masked with raw SHA256 can be reversed
-- by an 8-row dictionary table, whereas fn_salted_sha256 resists dictionary matching.
WITH rainbow_table AS (
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
    WHEN c.customer_id IS NULL THEN 'PROTECTED (NULL)'
    WHEN c.customer_id = '' THEN 'PROTECTED_BUT_BROKEN_JOINS (EMPTY_STRING)'
    WHEN c.customer_id LIKE 'CUST-%' THEN 'RAW_PLAINTEXT (Authorized Admin)'
    WHEN r.candidate_id IS NOT NULL THEN 'VULNERABLE! Reversed via Unsalted SHA-256 Rainbow Lookup'
    ELSE 'SECURE! Salted SHA-256 Defeats Rainbow Table while Preserving Joins'
  END AS cryptographic_verdict
FROM `YOUR_PROJECT_ID.data_policies_example.customers` AS c
LEFT JOIN rainbow_table AS r
  ON c.customer_id IN (r.unsalted_b64_hash, r.unsalted_hex_hash)
ORDER BY c.customer_name;
