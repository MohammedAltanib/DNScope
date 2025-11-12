#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNScope++ Mini (with Figures)
Author: Mohammed Altanib — Noroff UC (2025)

Purpose:
  Minimal, fast analytics over DNS-in-IBR Parquet (DuckDB-powered)
  to cover RQ1–RQ3 and emit clean CSVs + PNG figures.

Assumptions:
  • Input is a Parquet file (or a folder of Parquets) created from your pipeline.
  • Columns may contain special names like "frame.time_epoch" and "eTLD+1".

Outputs (under --out):
  ├─ tables/
  │   ├─ daily_global.csv
  │   ├─ qtype_rcode.csv
  │   ├─ top_src24.csv
  │   ├─ top_etld1.csv
  │   ├─ daily_any.csv
  │   └─ regional_daily.csv (if region available)
  └─ figs/
      ├─ daily_dns.png (RQ1-zaman)
      ├─ daily_any_pct.png (RQ2-amplification)
      ├─ top_src24.png (RQ3-sources)
      ├─ top_etld1.png (RQ3-domains)
      ├─ qtype_rcode_heatmap.png (RQ2)
      └─ regional_daily.png (RQ1-makan; if region exists)

Usage:
  python dnscope_mini_figs.py /path/to/e3_merged.parquet --out run --top-n 20
"""

import os
import sys
import re
import argparse
from pathlib import Path

import duckdb
import pandas as pd
import matplotlib.pyplot as plt

# --------------------------- Banner ---------------------------
BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║  DNScope++ Mini — RQ1·RQ2·RQ3  |  Author: Mohammed Altanib  ║
╚══════════════════════════════════════════════════════════════╝
"""

# ------------------------ Small helpers -----------------------

def ensure_dirs(out_dir: str):
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    Path(os.path.join(out_dir, 'tables')).mkdir(parents=True, exist_ok=True)
    Path(os.path.join(out_dir, 'figs')).mkdir(parents=True, exist_ok=True)


def connect_duck():
    con = duckdb.connect()
    try:
        con.execute("PRAGMA threads=auto;")
    except Exception:
        pass
    return con


def col_exists(con: duckdb.DuckDBPyConnection, src: str, col: str) -> bool:
    try:
        df = con.execute(f"PRAGMA table_info(read_parquet('{src}'))").df()
        return any(df['name'].astype(str) == col)
    except Exception:
        return False


def pick_etld_col(con, src):
    # prefer etld1, else "eTLD+1"
    if col_exists(con, src, 'etld1'):
        return 'etld1'
    if col_exists(con, src, 'eTLD+1'):
        return '"eTLD+1"'
    return None


# --------------------------- Plots ----------------------------

def save_line(df, x, y, path, title, xlabel, ylabel):
    if df.empty:
        return
    plt.figure()
    plt.plot(df[x], df[y])
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def save_bar(df, x, y, path, title, xlabel, ylabel):
    if df.empty:
        return
    plt.figure()
    plt.bar(df[x].astype(str), df[y])
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=75, ha='right')
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def save_heatmap(pivot_df, path, title):
    if pivot_df.empty:
        return
    plt.figure()
    data = pivot_df.set_index(['qtype','rcode'])['cnt'].unstack(fill_value=0)
    plt.imshow(data, aspect='auto')
    plt.title(title)
    plt.yticks(range(len(data.index)), [str(i) for i in data.index])
    plt.xticks(range(len(data.columns)), [str(c) for c in data.columns], rotation=45, ha='right')
    plt.colorbar()
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


# ------------------------- Core logic -------------------------

def run(src: str, out: str, topn: int):
    print(BANNER)
    ensure_dirs(out)

    con = connect_duck()

    # Basic sanity — count + time range
    basic = con.execute(f"""
        SELECT COUNT(*) AS rows,
               MIN("frame.time_epoch") AS min_ts,
               MAX("frame.time_epoch") AS max_ts
        FROM read_parquet('{src}')
    """).df()
    print(basic)

    # ==== RQ1 (temporal share inside DNS): daily counts ====
    daily = con.execute(f"""
        SELECT date_trunc('day', to_timestamp(CAST("frame.time_epoch" AS DOUBLE))) AS day,
               COUNT(*) AS dns_events
        FROM read_parquet('{src}')
        WHERE "frame.time_epoch" IS NOT NULL
        GROUP BY day
        ORDER BY day
    """).df()
    daily.to_csv(os.path.join(out, 'tables', 'daily_global.csv'), index=False)
    save_line(daily, 'day', 'dns_events', os.path.join(out, 'figs', 'daily_dns.png'),
              'DNS events per day', 'Day', 'Events')

    # optional regional daily if region column exists
    regional_daily = pd.DataFrame()
    if col_exists(con, src, 'region'):
        regional_daily = con.execute(f"""
            SELECT region,
                   date_trunc('day', to_timestamp(CAST("frame.time_epoch" AS DOUBLE))) AS day,
                   COUNT(*) AS dns_events
            FROM read_parquet('{src}')
            WHERE "frame.time_epoch" IS NOT NULL AND region IS NOT NULL
            GROUP BY region, day
            ORDER BY day, region
        """).df()
        regional_daily.to_csv(os.path.join(out, 'tables', 'regional_daily.csv'), index=False)
        # simple total per day (stacked feel via many lines)
        for reg, sub in regional_daily.groupby('region'):
            save_line(sub.sort_values('day'), 'day', 'dns_events',
                      os.path.join(out, 'figs', f'regional_daily_{re.sub(r"[^a-zA-Z0-9_-]","_",str(reg))}.png'),
                      f'DNS per day — {reg}', 'Day', 'Events')

    # ==== RQ2 (types, rcodes, amplification proxy: ANY) ====
    qrc = con.execute(f"""
        SELECT CAST("dns.qry.type" AS INT) AS qtype,
               CAST("dns.flags.rcode" AS INT) AS rcode,
               COUNT(*) AS cnt
        FROM read_parquet('{src}')
        WHERE "dns.qry.type" IS NOT NULL
        GROUP BY qtype, rcode
        ORDER BY cnt DESC
    """).df()
    qrc.to_csv(os.path.join(out, 'tables', 'qtype_rcode.csv'), index=False)
    save_heatmap(qrc, os.path.join(out, 'figs', 'qtype_rcode_heatmap.png'), 'QTYPE×RCODE (counts)')

    daily_any = con.execute(f"""
        WITH events AS (
          SELECT date_trunc('day', to_timestamp(CAST("frame.time_epoch" AS DOUBLE))) AS day,
                 CAST("dns.qry.type" AS INT) AS qtype
          FROM read_parquet('{src}')
          WHERE "frame.time_epoch" IS NOT NULL
        )
        SELECT day,
               COUNT(*) AS total,
               SUM(CASE WHEN qtype=255 THEN 1 ELSE 0 END) AS any_count,
               100.0*SUM(CASE WHEN qtype=255 THEN 1 ELSE 0 END)/NULLIF(COUNT(*),0) AS any_pct
        FROM events
        GROUP BY day
        ORDER BY day
    """).df()
    daily_any.to_csv(os.path.join(out, 'tables', 'daily_any.csv'), index=False)
    save_line(daily_any, 'day', 'any_pct', os.path.join(out, 'figs', 'daily_any_pct.png'),
              'ANY share per day (%)', 'Day', 'ANY %')

    # ==== RQ3 (sources: /24 and domains) ====
    top_src24 = con.execute(f"""
        SELECT src_24, COUNT(*) AS hits
        FROM read_parquet('{src}')
        GROUP BY src_24
        ORDER BY hits DESC
        LIMIT {topn}
    """).df()
    top_src24.to_csv(os.path.join(out, 'tables', 'top_src24.csv'), index=False)
    save_bar(top_src24, 'src_24', 'hits', os.path.join(out, 'figs', 'top_src24.png'),
             f'Top {topn} /24 sources', '/24', 'Hits')

    etld_col = pick_etld_col(con, src)
    if etld_col:
        top_etld1 = con.execute(f"""
            WITH norm AS (
              SELECT lower(NULLIF(TRIM({etld_col}), '')) AS etld1
              FROM read_parquet('{src}')
            )
            SELECT etld1, COUNT(*) AS hits
            FROM norm
            WHERE etld1 IS NOT NULL
              AND etld1 NOT IN ('null','nan','<unknown extended label>','bind','local','stage','')
            GROUP BY etld1
            ORDER BY hits DESC
            LIMIT {topn}
        """).df()
        top_etld1.to_csv(os.path.join(out, 'tables', 'top_etld1.csv'), index=False)
        save_bar(top_etld1, 'etld1', 'hits', os.path.join(out, 'figs', 'top_etld1.png'),
                 f'Top {topn} eTLD+1', 'eTLD+1', 'Hits')

    con.close()

    # Final summary to console
    print("\nSummary:")
    print(f"  Tables: {os.path.join(out, 'tables')}")
    print(f"  Figures: {os.path.join(out, 'figs')}")
    print("  RQ1: daily_dns.png (+ regional_* if region present)")
    print("  RQ2: daily_any_pct.png, qtype_rcode_heatmap.png")
    print("  RQ3: top_src24.png, top_etld1.png (if etld1 available)")


# ----------------------------- CLI ----------------------------

def parse_args():
    ap = argparse.ArgumentParser(description='DNScope++ Mini (with Figures) — Mohammed Altanib')
    ap.add_argument('src', help='Parquet file, or glob to Parquet files')
    ap.add_argument('--out', default='run_out', help='Output directory')
    ap.add_argument('--top-n', type=int, default=20, help='Top-N for /24 and eTLD+1')
    return ap.parse_args()


def main():
    args = parse_args()
    run(args.src, args.out, args.top_n)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print(BANNER)
        print("Usage: python dnscope_mini_figs.py <parquet|glob> [--out run --top-n 20]")
        sys.exit(1)
    main()
