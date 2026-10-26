// BigQuery Multi-Policy PK/FK Dynamic Data Masking Workbench Client
// Uses strict DOM construction (document.createElement + textContent) with zero innerHTML.

let overviewData = null;

function el(tag, className = "", text = "") {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== "" && text !== null && text !== undefined) {
    node.textContent = String(text);
  }
  return node;
}

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function createSafeExternalLink(href, label, className = "rail-link") {
  const a = el("a", className, label);
  try {
    const parsed = new URL(href);
    if (
      parsed.protocol === "https:" &&
      (parsed.hostname === "console.cloud.google.com" ||
        parsed.hostname === "cloud.google.com" ||
        parsed.hostname.endsWith(".google.com"))
    ) {
      a.href = parsed.href;
      a.target = "_blank";
      a.rel = "noopener noreferrer";
      return a;
    }
  } catch (_err) {
    // Fallback to inert span if URL fails validation
  }
  return el("span", className, label);
}

function formatCellValue(colName, val) {
  if (val === null || val === undefined) {
    return { text: "NULL", css: "cell-null" };
  }
  if (val === "") {
    return { text: '"" (empty string)', css: "cell-default-mask" };
  }
  const str = String(val);
  const isPkCol =
    colName === "customer_id" ||
    colName === "customer_pk" ||
    colName === "order_fk" ||
    colName === "what_caller_sees_on_pk" ||
    colName === "foreign_key_customer_id";

  if (isPkCol) {
    if (str.startsWith("CUST-")) {
      return { text: str, css: "cell-plaintext" };
    }
    if (str.length === 64 && /^[0-9a-f]+$/i.test(str)) {
      return { text: str.slice(0, 18) + "…" + str.slice(-6), full: str, css: "cell-salted-hash" };
    }
    if (str.endsWith("=")) {
      return { text: str, css: "cell-unsalted-hash" };
    }
  }
  if (colName === "email" && str.startsWith("XXXXX@")) {
    return { text: str, css: "cell-default-mask" };
  }
  if (colName === "credit_limit_usd" || colName === "visible_credit_limit") {
    const num = Number(val);
    if (num === 0) {
      return { text: "0.0 (Default Mask)", css: "cell-default-mask" };
    }
    return { text: "$" + num.toLocaleString("en-US", { minimumFractionDigits: 2 }), css: "" };
  }
  return { text: str, css: "" };
}

function renderResultTable(columns, rows) {
  if (!rows || rows.length === 0) {
    return el(
      "div",
      "empty-join-banner",
      "0 rows returned — SQL JOIN condition evaluated to UNKNOWN (NULL = NULL under ALWAYS_NULL policy on customer_id). Cross-table correlation is completely blocked."
    );
  }

  const scrollWrap = el("div", "table-scroll-container");
  const table = el("table", "data-table");
  const thead = el("thead");
  const headRow = el("tr");
  for (const col of columns) {
    headRow.appendChild(el("th", "", col));
  }
  thead.appendChild(headRow);
  table.appendChild(thead);

  const tbody = el("tbody");
  const displayRows = rows.slice(0, 25);
  for (const row of displayRows) {
    const tr = el("tr");
    for (const col of columns) {
      const formatted = formatCellValue(col, row[col]);
      const td = el("td", formatted.css, formatted.text);
      if (formatted.full) {
        td.title = formatted.full;
      }
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  scrollWrap.appendChild(table);
  return scrollWrap;
}

function buildPersonaResultCard(res) {
  const card = el("div", "persona-result-card");
  const p = res.persona;

  const header = el("div", "persona-card-header");
  const left = el("div");
  left.appendChild(el("h3", "persona-title", `${p.title} (${p.id.toUpperCase()})`));
  left.appendChild(el("div", "persona-principal", `Principal: ${p.user_email}`));
  left.appendChild(el("div", "persona-policy-line", p.role_label));

  let badgeClass = "chip chip-emerald";
  let badgeText = `${res.row_count} Rows`;
  if (res.row_count === 0) {
    badgeClass = "chip chip-rose";
    badgeText = "0 Rows (JOIN Blocked)";
  } else if (res.row_count > 20) {
    badgeClass = "chip chip-amber";
    badgeText = `${res.row_count} Rows (Cartesian Explosion!)`;
  }
  const rightBadge = el("span", badgeClass, badgeText);
  header.appendChild(left);
  header.appendChild(rightBadge);
  card.appendChild(header);

  const telemetry = el("div", "job-telemetry-strip");
  telemetry.appendChild(el("span", "telemetry-pill", `Job: ${res.job_id}`));
  telemetry.appendChild(el("span", "telemetry-pill", `Region: ${res.location}`));
  telemetry.appendChild(el("span", "telemetry-pill", `Latency: ${res.elapsed_ms} ms`));
  telemetry.appendChild(
    el(
      "span",
      "telemetry-pill",
      `PK Seen: ${res.sample_pk_seen === null ? "NULL" : res.sample_pk_seen === "" ? '""' : String(res.sample_pk_seen).slice(0, 22)}`
    )
  );
  card.appendChild(telemetry);

  card.appendChild(renderResultTable(res.columns, res.rows));
  return card;
}

function populateAccessMatrix(state, verification) {
  const tbody = document.getElementById("personaMatrixBody");
  clearChildren(tbody);

  const secondaryMap = {
    admin: "Unmasked ('alice.smith@acme-global.com', $25,000.00)",
    testuser: "EMAIL_MASK ('XXXXX@acme-global.com'), Unmasked Credit ($25,000.00)",
    test2: "DEFAULT_MASKING_VALUE ('' on String PII, 0.0 on Credit Limit)",
    sha256: "EMAIL_MASK ('XXXXX@acme-global.com'), DEFAULT_MASKING_VALUE (0.0)",
    defaultpk: "DEFAULT_MASKING_VALUE ('' on String PII, 0.0 on Credit Limit)",
    conflict: "EMAIL_MASK ('XXXXX@acme-global.com'), DEFAULT_MASKING_VALUE (0.0)",
  };

  const personas = Object.values(state.personas);
  for (const p of personas) {
    const tr = el("tr");

    const tdId = el("td");
    tdId.appendChild(el("div", "resource-name", p.user_email));
    tdId.appendChild(el("div", "resource-id", `${p.title} (${p.sa_email})`));
    tr.appendChild(tdId);

    tr.appendChild(el("td", "", p.role_label));

    const tdPk = el("td");
    const pkSample = p.pk_example;
    let pkClass = "cell-plaintext";
    if (p.id === "testuser" || p.id === "conflict") pkClass = "cell-salted-hash";
    else if (p.id === "sha256") pkClass = "cell-unsalted-hash";
    else if (p.id === "test2") pkClass = "cell-null";
    else if (p.id === "defaultpk") pkClass = "cell-default-mask";
    tdPk.appendChild(el("div", pkClass, pkSample));
    tdPk.appendChild(el("div", "resource-id", p.pk_policy));
    tr.appendChild(tdPk);

    tr.appendChild(el("td", "", secondaryMap[p.id] || ""));
    tr.appendChild(el("td", "", p.join_behavior));

    const vInfo = verification && verification.personas ? verification.personas[p.id] : null;
    const joinCount = vInfo ? `${vInfo.join_2table_row_count} rows` : p.join_capable ? "12 rows" : "0 rows";
    tr.appendChild(el("td", "mono", joinCount));

    tbody.appendChild(tr);
  }
}

function populateHierarchyTable(hierarchy) {
  const tbody = document.getElementById("hierarchyTableBody");
  clearChildren(tbody);

  for (const item of hierarchy) {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", `#${item.priority}`));
    tr.appendChild(el("td", "resource-name", item.rule));
    tr.appendChild(el("td", "mono", item.expression));

    const statusTd = el("td");
    if (item.used_in_demo) {
      statusTd.appendChild(el("span", "chip chip-emerald", `ACTIVE: ${item.demo_policy_id}`));
    } else {
      statusTd.appendChild(el("span", "chip chip-blue", "Reference Tier"));
    }
    tr.appendChild(statusTd);
    tr.appendChild(el("td", "", item.description));
    tbody.appendChild(tr);
  }
}

function populateResourcesList(state, links) {
  const container = document.getElementById("provisionedResourcesList");
  clearChildren(container);

  const items = [
    {
      name: `BigQuery Dataset: ${state.project_id}.${state.dataset_id}`,
      id: `Region: ${state.location} | 4 PK/FK Tables + 1 Custom Masking UDF`,
      url: links.bigquery_dataset,
    },
    {
      name: "Data Catalog Taxonomy: CustomerGovernanceTaxonomy",
      id: state.taxonomy.name,
      url: links.policy_tag_taxonomy,
    },
    {
      name: "Custom Masking Routine: fn_salted_sha256",
      id: state.routine_path,
      url: links.routine_salted_sha256,
    },
    {
      name: "Primary Table: customers (PK: customer_id)",
      id: "Tagged: customer_id (PK_Tag), email/phone/tax_id (PII_Tag), credit_limit_usd (Fin_Tag)",
      url: links.table_customers,
    },
    {
      name: "Child Fact Table: orders (FK: customer_id)",
      id: "Tagged: customer_id (Customer_PK_Tag)",
      url: links.table_orders,
    },
    {
      name: "Child Table: support_tickets (FK: customer_id)",
      id: "Tagged: customer_id (Customer_PK_Tag)",
      url: links.table_support_tickets,
    },
    {
      name: "Child Table: loyalty_ledger (FK: customer_id)",
      id: "Tagged: customer_id (Customer_PK_Tag)",
      url: links.table_loyalty_ledger,
    },
  ];

  for (const item of items) {
    const row = el("div", "resource-item");
    const left = el("div");
    left.appendChild(el("div", "resource-name", item.name));
    left.appendChild(el("div", "resource-id", item.id));
    row.appendChild(left);
    row.appendChild(createSafeExternalLink(item.url, "Open in Cloud Console ↗", "btn btn-secondary"));
    container.appendChild(row);
  }
}

function populateImplementationGuide(state, sqlScripts) {
  const container = document.getElementById("implementationGuideContainer");
  clearChildren(container);

  const adminEmail = state.personas?.admin?.user_email || "admin@your-company.com";
  const analystEmail = state.personas?.testuser?.user_email || "analyst@your-company.com";
  const auditorEmail = state.personas?.test2?.user_email || "auditor@your-company.com";

  const steps = [
    {
      title: `Part 1: Provision Data Catalog Taxonomy & Policy Tags (${state.location})`,
      desc: "Create the fine-grained access control taxonomy CustomerGovernanceTaxonomy and the Customer_PK_Tag policy tag attached to both Primary Key and Foreign Key columns.",
      code: `cp .env.example .env
# Edit .env with GOOGLE_CLOUD_PROJECT="${state.project_id}" and your persona principals

# Automated idempotent provisioning script (creates Taxonomy, 3 Policy Tags, 7 Data Policies, UDF, 4 Tables, and IAM bindings):
CLOUDSDK_METRICS_ENVIRONMENT="datacloud.antigravity" python3.12 provisioning/provision_all.py`,
    },
    {
      title: "Part 2: Create Custom Masking Routine (fn_salted_sha256) & Relational PK/FK Schema",
      desc: "Define the GoogleSQL custom masking UDF with OPTIONS (data_governance_type = 'DATA_MASKING') and create the 4 relational tables (customers, orders, support_tickets, loyalty_ledger).",
      code: sqlScripts.schema_and_udf || "",
    },
    {
      title: "Part 3: Attach Multiple Data Policies to Customer_PK_Tag & Bind Persona IAM Roles",
      desc: `Bind ${adminEmail} as Fine-Grained Reader, ${analystEmail} as Masked Reader on Policy 1 (Salted SHA-256), and ${auditorEmail} as Masked Reader on Policy 2 (ALWAYS_NULL).`,
      code: `# Policy 1: Custom Masking Routine (Salted SHA-256) -> Priority #1
# Attached to Customer_PK_Tag for ${analystEmail}
{
  "dataPolicyId": "dp_customer_pk_salted_sha256",
  "dataPolicyType": "DATA_MASKING_POLICY",
  "policyTag": "${state.policy_tags.Customer_PK_Tag.name}",
  "dataMaskingPolicy": {
    "routine": "${state.routine_path}"
  }
}

# Policy 2: Nullify (ALWAYS_NULL) -> Priority #9
# Attached to Customer_PK_Tag for ${auditorEmail}
{
  "dataPolicyId": "dp_customer_pk_null",
  "dataPolicyType": "DATA_MASKING_POLICY",
  "policyTag": "${state.policy_tags.Customer_PK_Tag.name}",
  "dataMaskingPolicy": {
    "predefinedExpression": "ALWAYS_NULL"
  }
}`,
    },
    {
      title: "Part 4: Run Live Multi-Persona Verification Queries",
      desc: "Execute identical single-table and multi-table JOIN queries across all personas to verify plaintext joins, deterministic Salted SHA-256 joins, and NULL = NULL join blocking.",
      code: sqlScripts.verification_queries || "",
    },
  ];

  for (const s of steps) {
    const box = el("div", "guide-step");
    box.appendChild(el("h3", "guide-step-title", s.title));
    box.appendChild(el("p", "section-desc", s.desc));
    box.appendChild(el("pre", "code-block", s.code));
    container.appendChild(box);
  }
}

function updateSelectedQueryPreview() {
  if (!overviewData) return;
  const queryId = document.getElementById("querySelect").value;
  const q = overviewData.queries.find((item) => item.id === queryId);
  if (!q) return;

  document.getElementById("activeSqlCode").textContent = q.sql;
  document.getElementById("queryInsightBanner").textContent = `Architectural Insight: ${q.expected_insight}`;
  document.getElementById("tierSelect").disabled = !q.supports_tier_filter;
}

async function runSinglePersonaQuery() {
  const btn = document.getElementById("runSingleBtn");
  const container = document.getElementById("workbenchResultsContainer");
  const queryId = document.getElementById("querySelect").value;
  const personaId = document.getElementById("personaSelect").value;
  const loyaltyTier = document.getElementById("tierSelect").value;

  btn.disabled = true;
  btn.textContent = "Executing Live in BigQuery…";
  clearChildren(container);
  container.appendChild(el("div", "card", `Running live BigQuery job as ${personaId.toUpperCase()}…`));

  try {
    const resp = await fetch("/api/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        persona_id: personaId,
        query_id: queryId,
        loyalty_tier: loyaltyTier,
      }),
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const data = await resp.json();
    clearChildren(container);
    container.appendChild(buildPersonaResultCard(data));
  } catch (err) {
    clearChildren(container);
    container.appendChild(el("div", "empty-join-banner", `Query execution error: ${err.message}`));
  } finally {
    btn.disabled = false;
    btn.textContent = "Run as Selected Persona";
  }
}

async function runComparePersonas(queryIdOverride = null, targetContainerId = "workbenchResultsContainer", personaList = null) {
  const btn = document.getElementById("runCompareAllBtn");
  const container = document.getElementById(targetContainerId);
  const queryId = queryIdOverride || document.getElementById("querySelect").value;
  const loyaltyTier = document.getElementById("tierSelect").value;
  const personasToRun = personaList || ["admin", "testuser", "test2", "sha256", "defaultpk", "conflict"];

  btn.disabled = true;
  clearChildren(container);
  container.appendChild(
    el("div", "card", `Executing ${personasToRun.length} concurrent impersonated BigQuery jobs in us-central1…`)
  );

  try {
    const resp = await fetch("/api/compare", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query_id: queryId,
        persona_ids: personasToRun,
        loyalty_tier: loyaltyTier,
      }),
    });
    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}`);
    }
    const data = await resp.json();
    clearChildren(container);

    const grid = el("div", "compare-grid");
    for (const res of data.results) {
      grid.appendChild(buildPersonaResultCard(res));
    }
    container.appendChild(grid);
  } catch (err) {
    clearChildren(container);
    container.appendChild(el("div", "empty-join-banner", `Comparison error: ${err.message}`));
  } finally {
    btn.disabled = false;
  }
}

async function initApp() {
  // Navigation tabs
  const navButtons = document.querySelectorAll(".nav-item");
  navButtons.forEach((btn) => {
    btn.addEventListener("click", () => {
      navButtons.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      const tabId = btn.getAttribute("data-tab");
      document.querySelectorAll(".tab-panel").forEach((panel) => {
        panel.classList.toggle("active", panel.id === `tab-${tabId}`);
      });
    });
  });

  // Rail collapse
  document.getElementById("railToggleBtn").addEventListener("click", () => {
    document.getElementById("appShell").classList.toggle("rail-collapsed");
  });

  // Theme toggle
  document.getElementById("themeToggleBtn").addEventListener("click", () => {
    const html = document.documentElement;
    const current = html.getAttribute("data-theme") || "dark";
    html.setAttribute("data-theme", current === "dark" ? "light" : "dark");
  });

  // SQL modal
  const sqlModal = document.getElementById("sqlModal");
  document.getElementById("openSqlModalBtn").addEventListener("click", () => {
    sqlModal.showModal();
  });
  document.getElementById("closeSqlModalBtn").addEventListener("click", () => {
    sqlModal.close();
  });

  // Fetch live overview metadata
  const resp = await fetch("/api/overview");
  overviewData = await resp.json();

  const { state, verification_report, masking_hierarchy, queries, console_links, sql_scripts } = overviewData;

  document.getElementById("railProject").textContent = state.project_id;
  document.getElementById("railDataset").textContent = `${state.dataset_id} (${state.location})`;
  const matrixDs = document.getElementById("matrixDatasetLabel");
  if (matrixDs) matrixDs.textContent = `${state.project_id}.${state.dataset_id}`;
  const resProj = document.getElementById("resourcesProjectLabel");
  if (resProj) resProj.textContent = `${state.project_id} (${state.location})`;
  const cryptoUdf = document.getElementById("cryptoUdfCode");
  if (cryptoUdf) {
    cryptoUdf.textContent = `CREATE OR REPLACE FUNCTION \`${state.project_id}.${state.dataset_id}.${state.routine_id}\`(val STRING)\nRETURNS STRING\nOPTIONS (data_governance_type = 'DATA_MASKING') AS (\n  CAST(SHA256(CONCAT(val, '<ENTERPRISE_SECRET_PEPPER>')) AS STRING FORMAT 'HEX')\n);`;
  }

  // Populate rail console links
  const railLinks = document.getElementById("railConsoleLinks");
  clearChildren(railLinks);
  railLinks.appendChild(createSafeExternalLink(console_links.bigquery_dataset, "↗ BigQuery Dataset"));
  railLinks.appendChild(createSafeExternalLink(console_links.policy_tag_taxonomy, "↗ Policy Tag Taxonomy"));
  railLinks.appendChild(createSafeExternalLink(console_links.routine_salted_sha256, "↗ UDF fn_salted_sha256"));
  railLinks.appendChild(createSafeExternalLink(console_links.docs_column_masking, "↗ Official BQ Masking Docs"));

  // Populate Query Select
  const querySelect = document.getElementById("querySelect");
  clearChildren(querySelect);
  for (const q of queries) {
    const opt = el("option", "", q.title);
    opt.value = q.id;
    if (q.id === "join_customers_orders") opt.selected = true;
    querySelect.appendChild(opt);
  }
  querySelect.addEventListener("change", updateSelectedQueryPreview);

  // Populate Persona Select
  const personaSelect = document.getElementById("personaSelect");
  clearChildren(personaSelect);
  for (const p of Object.values(state.personas)) {
    const opt = el("option", "", `${p.user_email} — ${p.title}`);
    opt.value = p.id;
    if (p.id === "testuser") opt.selected = true;
    personaSelect.appendChild(opt);
  }

  // Modal SQL scripts
  document.getElementById("modalSchemaSql").textContent = sql_scripts.schema_and_udf || "";
  document.getElementById("modalVerifySql").textContent = sql_scripts.verification_queries || "";

  // Populate Tab 2 & Tab 5
  populateAccessMatrix(state, verification_report);
  populateHierarchyTable(masking_hierarchy);
  populateResourcesList(state, console_links);
  populateImplementationGuide(state, sql_scripts);

  updateSelectedQueryPreview();

  // Wire Workbench buttons
  document.getElementById("runSingleBtn").addEventListener("click", runSinglePersonaQuery);
  document.getElementById("runCompareAllBtn").addEventListener("click", () => {
    runComparePersonas(null, "workbenchResultsContainer", ["admin", "testuser", "test2", "sha256", "defaultpk", "conflict"]);
  });

  // Wire Tab 3 Cryptographic Lab buttons
  document.getElementById("runRainbowLabBtn").addEventListener("click", () => {
    runComparePersonas("rainbow_attack_lab", "cryptoLabResults", ["testuser", "sha256", "admin", "test2"]);
  });
  document.getElementById("runCartesianLabBtn").addEventListener("click", () => {
    runComparePersonas("join_customers_orders", "cryptoLabResults", ["test2", "defaultpk", "testuser"]);
  });

  // Automatically execute initial side-by-side comparison for the 3 primary personas + defaultpk/sha256/conflict
  runComparePersonas("join_customers_orders", "workbenchResultsContainer", [
    "admin",
    "testuser",
    "test2",
    "sha256",
    "defaultpk",
    "conflict",
  ]);
}

window.addEventListener("DOMContentLoaded", initApp);
