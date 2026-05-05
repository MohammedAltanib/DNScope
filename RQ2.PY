import duckdb
import pandas as pd
import matplotlib.pyplot as plt

# Change this only if your file path is different
src = "e3_merged.parquet"

con = duckdb.connect()

QTYPE_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
    255: "ANY",
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    9: "NOTAUTH",
    10: "NOTZONE",
}

def q(col):
    return '"' + col.replace('"', '""') + '"'

def pick_col(cols, candidates):
    for c in candidates:
        if c in cols:
            return c
    return None

def rcode_label(x):
    x = int(x)
    return RCODE_NAMES.get(x, f"Other ({x})")

# Read schema
cols = con.execute(f"""
    DESCRIBE SELECT * FROM read_parquet('{src}')
""").df()["column_name"].astype(str).tolist()

qtype_col = pick_col(cols, ["qtype", "dns.qry.type", "dns_qry_type"])
rcode_col = pick_col(cols, ["rcode", "dns.flags.rcode", "dns_flags_rcode"])
resp_col  = pick_col(cols, ["is_resp", "dns.flags.response", "dns_flags_response"])
etld_col  = pick_col(cols, ["etld1", "eTLD+1", "etld_1"])

if not qtype_col:
    raise ValueError("Missing QTYPE column")
if not resp_col:
    raise ValueError("Missing response flag column")
if not rcode_col:
    raise ValueError("Missing RCODE column")
if not etld_col:
    raise ValueError("Missing eTLD+1 column")

qtype_expr = f"TRY_CAST({q(qtype_col)} AS INTEGER)"
rcode_expr = f"TRY_CAST({q(rcode_col)} AS INTEGER)"
resp_expr = f"LOWER(CAST({q(resp_col)} AS VARCHAR)) IN ('1','true','t','yes','response')"

# =========================
# QTYPE
# =========================
qtype_dist = con.execute(f"""
    SELECT
        {qtype_expr} AS qtype,
        COUNT(*) AS cnt,
        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 4) AS pct
    FROM read_parquet('{src}')
    WHERE {qtype_expr} IS NOT NULL
    GROUP BY qtype
    ORDER BY cnt DESC
""").df()

qtype_dist["qtype_name"] = (
    qtype_dist["qtype"]
    .map(QTYPE_NAMES)
    .fillna(qtype_dist["qtype"].astype(str))
)

# =========================
# Queries vs Responses
# =========================
qr_counts = con.execute(f"""
    SELECT
        SUM(CASE WHEN {resp_expr} THEN 1 ELSE 0 END) AS responses,
        SUM(CASE WHEN {resp_expr} THEN 0 ELSE 1 END) AS queries
    FROM read_parquet('{src}')
""").df()

# =========================
# RCODE - responses only
# =========================
rcode_dist_resp = con.execute(f"""
    SELECT
        {rcode_expr} AS rcode,
        COUNT(*) AS cnt,
        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 4) AS pct
    FROM read_parquet('{src}')
    WHERE {rcode_expr} IS NOT NULL
      AND {resp_expr}
    GROUP BY rcode
    ORDER BY cnt DESC
""").df()

rcode_dist_resp["rcode_name"] = rcode_dist_resp["rcode"].apply(rcode_label)

# =========================
# eTLD+1
# =========================
top_etld1 = con.execute(f"""
    SELECT
        CAST({q(etld_col)} AS VARCHAR) AS etld1,
        COUNT(*) AS cnt
    FROM read_parquet('{src}')
    WHERE {q(etld_col)} IS NOT NULL
    GROUP BY etld1
    ORDER BY cnt DESC
""").df()

# ======================================================
# Plots
# ======================================================

# eTLD
bad = {'nan', '<Root>', '<Unknown extended label>', 'BIND', 'bind'}
et = top_etld1.copy()

et = et[~et['etld1'].isin(bad)]
et = et[et['etld1'].str.len() <= 60]
et = et[et['etld1'].str.contains(r'\.', regex=True, na=False)]
et = et.head(20)

plt.figure(figsize=(10,5))
plt.bar(et['etld1'], et['cnt'])
plt.ylabel('Count')
plt.xlabel('eTLD+1')
plt.title('Top eTLD+1 Domains in DNS IBR (Filtered)')
plt.xticks(rotation=60, ha='right')
plt.tight_layout()
plt.show()

# RCODE
top_rc = rcode_dist_resp.sort_values('cnt', ascending=False).head(10)

plt.figure(figsize=(6,4))
plt.bar(top_rc['rcode_name'], top_rc['cnt'])
plt.ylabel('Count')
plt.xlabel('RCODE')
plt.title('DNS Response Codes (RCODE) in Responses Only')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# QTYPE Known vs Other
known = {'A', 'AAAA', 'NS', 'CNAME', 'SOA', 'PTR', 'MX', 'TXT', 'SRV', 'ANY'}

tmp = qtype_dist.copy()
tmp['label'] = tmp['qtype_name'].where(tmp['qtype_name'].isin(known), 'Other')

qtype_grouped = (
    tmp.groupby('label', as_index=False)
       .agg(cnt=('cnt', 'sum'), pct=('pct', 'sum'))
       .sort_values('pct', ascending=False)
)

plt.figure(figsize=(9,4))
plt.bar(qtype_grouped['label'], qtype_grouped['pct'])
plt.ylabel('Percentage (%)')
plt.xlabel('QTYPE')
plt.title('DNS Query Types (Known vs Other)')
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# Queries vs Responses
resp = float(qr_counts.loc[0, 'responses'])
qry  = float(qr_counts.loc[0, 'queries'])

plt.figure(figsize=(3,4))
plt.bar(['Responses', 'Queries'], [resp, qry])
plt.yscale('log')
plt.ylabel('Count (log scale)')
plt.title('Queries vs Responses (Log Scale)')
plt.tight_layout()
plt.show()
