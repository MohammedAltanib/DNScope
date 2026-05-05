import duckdb
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Change this only if your file path is different
src = "e3_merged.parquet"

# If True, count only DNS queries. If False, count all DNS packets.
ONLY_QUERIES = False

con = duckdb.connect()

def q(col):
    return '"' + col.replace('"', '""') + '"'

def pick_col(cols, candidates):
    for c in candidates:
        if c in cols:
            return c
    return None

# Read schema
cols = con.execute(f"""
    DESCRIBE SELECT * FROM read_parquet('{src}')
""").df()["column_name"].astype(str).tolist()

src24_col = pick_col(cols, [
    "src_/24", "src_24", "src24", "source_/24", "source_24",
    "src_prefix24", "ip.src_/24", "ip_src_24"
])

src_ip_col = pick_col(cols, [
    "ip.src", "src_ip", "source_ip", "ip_src", "src"
])

country_col = pick_col(cols, [
    "country", "src_country", "source_country", "country_code",
    "src_country_code", "geoip_country", "mmdb_country", "src_cc", "cc"
])

resp_col = pick_col(cols, [
    "is_resp", "dns.flags.response", "dns_flags_response"
])

if not src24_col and not src_ip_col:
    raise ValueError("Missing source column. Expected src_/24 or ip.src")

# Response filter, optional
base_filter = "TRUE"

if ONLY_QUERIES and resp_col:
    resp_expr = f"LOWER(CAST({q(resp_col)} AS VARCHAR)) IN ('1','true','t','yes','response')"
    base_filter = f"NOT ({resp_expr})"

# Source /24 expression
if src24_col:
    src24_expr = f"CAST({q(src24_col)} AS VARCHAR)"
else:
    src_ip_expr = f"CAST({q(src_ip_col)} AS VARCHAR)"
    src24_expr = f"""
        CASE
            WHEN regexp_matches({src_ip_expr}, '^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$')
            THEN split_part({src_ip_expr}, '.', 1) || '.' ||
                 split_part({src_ip_expr}, '.', 2) || '.' ||
                 split_part({src_ip_expr}, '.', 3) || '.0/24'
            ELSE NULL
        END
    """

# =========================
# Top /24 prefixes
# =========================
top_src24 = con.execute(f"""
    SELECT
        {src24_expr} AS src_24,
        COUNT(*) AS cnt,
        ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 4) AS pct
    FROM read_parquet('{src}')
    WHERE {base_filter}
      AND {src24_expr} IS NOT NULL
      AND {src24_expr} != ''
    GROUP BY src_24
    ORDER BY cnt DESC
""").df()

# =========================
# Source concentration
# =========================
src24_concentration = top_src24.copy().reset_index(drop=True)
src24_concentration["rank"] = src24_concentration.index + 1
src24_concentration["cum_cnt"] = src24_concentration["cnt"].cumsum()
src24_concentration["cum_pct"] = (
    100.0 * src24_concentration["cum_cnt"] / src24_concentration["cnt"].sum()
)

# =========================
# Top countries
# =========================
if country_col:
    top_countries = con.execute(f"""
        SELECT
            CAST({q(country_col)} AS VARCHAR) AS country,
            COUNT(*) AS cnt,
            ROUND(100.0 * COUNT(*) / SUM(COUNT(*)) OVER (), 4) AS pct
        FROM read_parquet('{src}')
        WHERE {base_filter}
          AND {q(country_col)} IS NOT NULL
        GROUP BY country
        ORDER BY cnt DESC
    """).df()

    bad_countries = {"", "nan", "none", "null", "unknown", "<na>"}
    top_countries = top_countries[
        ~top_countries["country"].astype(str).str.lower().isin(bad_countries)
    ]

else:
    top_countries = pd.DataFrame(columns=["country", "cnt", "pct"])
    print("No country column found. Country plot skipped.")

# Alias names, in case you want shorter names
top_country = top_countries

# ======================================================
# Plots
# ======================================================

# Top source countries
if not top_countries.empty:
    tc = top_countries.head(15)

    plt.figure(figsize=(9,5))
    plt.bar(tc["country"], tc["cnt"])
    plt.ylabel("Count")
    plt.xlabel("Country")
    plt.title("Top Source Countries in DNS IBR")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

# Top /24 prefixes
ts = top_src24.head(20)

plt.figure(figsize=(10,5))
plt.bar(ts["src_24"], ts["cnt"])
plt.ylabel("Count")
plt.xlabel("Source /24 Prefix")
plt.title("Top Source /24 Prefixes in DNS IBR")
plt.xticks(rotation=60, ha="right")
plt.tight_layout()
plt.show()

# Top /24 prefixes percentage
ts_pct = top_src24.head(20)

plt.figure(figsize=(10,5))
plt.bar(ts_pct["src_24"], ts_pct["pct"])
plt.ylabel("Percentage (%)")
plt.xlabel("Source /24 Prefix")
plt.title("Top Source /24 Prefixes by Share")
plt.xticks(rotation=60, ha="right")
plt.tight_layout()
plt.show()
