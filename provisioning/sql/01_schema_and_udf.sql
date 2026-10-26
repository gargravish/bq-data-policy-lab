-- =============================================================================
-- 01_schema_and_udf.sql
-- Self-Contained DDL & Synthetic Data for BigQuery Column-Level Dynamic Masking
-- Replace YOUR_PROJECT_ID with your Google Cloud Project ID (or run provision_all.py)
-- Reference: https://cloud.google.com/bigquery/docs/column-data-masking-intro
-- =============================================================================

-- 1. Create Dataset in us-central1 (matching Data Catalog Taxonomy region)
CREATE SCHEMA IF NOT EXISTS `YOUR_PROJECT_ID.data_policies_example`
OPTIONS (
  location = 'us-central1',
  description = 'Live Demo: Multiple Dynamic Data Masking Policies on Primary & Foreign Keys in BigQuery'
);

-- 2. Create Custom Masking Routine (Salted SHA-256)
-- Priority #1 in BigQuery's 9-tier masking rule hierarchy.
-- Prevents rainbow-table reversals on low-entropy keys like 'CUST-1001'
-- while preserving deterministic equality (SaltedHash(PK) = SaltedHash(FK)) across JOINs.
CREATE OR REPLACE FUNCTION `YOUR_PROJECT_ID.data_policies_example.fn_salted_sha256`(val STRING)
RETURNS STRING
OPTIONS (data_governance_type = 'DATA_MASKING') AS (
  CAST(SHA256(CONCAT(val, 'REPLACE_WITH_YOUR_ENTERPRISE_SECRET_PEPPER_2026')) AS STRING FORMAT 'HEX')
);

-- 3. Create Primary Table: customers (PK: customer_id)
CREATE OR REPLACE TABLE `YOUR_PROJECT_ID.data_policies_example.customers` (
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
  description = 'Master Customer dimension table with Primary Key on customer_id protected by multi-policy dynamic data masking'
);

INSERT INTO `YOUR_PROJECT_ID.data_policies_example.customers`
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

-- 4. Create Child Table 1: orders (FK: customer_id -> customers.customer_id)
CREATE OR REPLACE TABLE `YOUR_PROJECT_ID.data_policies_example.orders` (
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
  FOREIGN KEY (customer_id) REFERENCES `YOUR_PROJECT_ID.data_policies_example.customers`(customer_id) NOT ENFORCED
)
OPTIONS(
  description = 'E-Commerce Orders fact table with Foreign Key customer_id tagged with Customer_PK_Tag'
);

INSERT INTO `YOUR_PROJECT_ID.data_policies_example.orders`
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

-- 5. Create Child Table 2: support_tickets (FK: customer_id -> customers.customer_id)
CREATE OR REPLACE TABLE `YOUR_PROJECT_ID.data_policies_example.support_tickets` (
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
  FOREIGN KEY (customer_id) REFERENCES `YOUR_PROJECT_ID.data_policies_example.customers`(customer_id) NOT ENFORCED
)
OPTIONS(
  description = 'Customer Support Tickets table with Foreign Key customer_id tagged with Customer_PK_Tag'
);

INSERT INTO `YOUR_PROJECT_ID.data_policies_example.support_tickets`
  (ticket_id, customer_id, order_id, issue_category, priority, resolution_status, opened_date)
VALUES
  ('TKT-501', 'CUST-1001', 'ORD-902', 'Billing & Invoice Reconciliation', 'HIGH', 'OPEN', DATE '2026-02-05'),
  ('TKT-502', 'CUST-1002', 'ORD-903', 'SSO & Policy Tag Provisioning', 'MEDIUM', 'RESOLVED', DATE '2026-02-20'),
  ('TKT-503', 'CUST-1003', 'ORD-904', 'Cross-Region Replication Latency', 'HIGH', 'IN_PROGRESS', DATE '2026-03-06'),
  ('TKT-504', 'CUST-1005', 'ORD-907', 'Custom UDF Quota Increase', 'LOW', 'RESOLVED', DATE '2026-04-18'),
  ('TKT-505', 'CUST-1007', 'ORD-910', 'VPC-SC Egress Rule Validation', 'CRITICAL', 'OPEN', DATE '2026-06-09'),
  ('TKT-506', 'CUST-1008', 'ORD-911', 'Audit Log Export Configuration', 'MEDIUM', 'RESOLVED', DATE '2026-06-25');

-- 6. Create Child Table 3: loyalty_ledger (FK: customer_id -> customers.customer_id)
CREATE OR REPLACE TABLE `YOUR_PROJECT_ID.data_policies_example.loyalty_ledger` (
  ledger_id STRING NOT NULL OPTIONS(description = 'Primary Key: Loyalty Ledger Entry ID'),
  customer_id STRING NOT NULL OPTIONS(
    description = 'Foreign Key referencing customers.customer_id, governed by Customer_PK_Tag'
  ),
  points_delta INT64 NOT NULL OPTIONS(description = 'Loyalty points earned or redeemed'),
  event_type STRING NOT NULL OPTIONS(description = 'EARN, REDEEM, or TIER_BONUS'),
  partner_program STRING NOT NULL OPTIONS(description = 'Partner ecosystem program'),
  event_date DATE NOT NULL OPTIONS(description = 'Ledger posting date'),
  PRIMARY KEY (ledger_id) NOT ENFORCED,
  FOREIGN KEY (customer_id) REFERENCES `YOUR_PROJECT_ID.data_policies_example.customers`(customer_id) NOT ENFORCED
)
OPTIONS(
  description = 'Customer Loyalty Ledger with Foreign Key customer_id tagged with Customer_PK_Tag'
);

INSERT INTO `YOUR_PROJECT_ID.data_policies_example.loyalty_ledger`
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
