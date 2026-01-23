#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import duckdb
from collections import defaultdict
import matplotlib.pyplot as plt


PARQUET = "rq1_all_regions.parquet"


def main():
    con = duckdb.connect()

    # -------------------------------
    # Figure 1: Time series of dns_share for top-N regions by traffic volume
    # -------------------------------
    TOP_N = 8

    top_regions = [r[0] for r in con.execute(f"""
        SELECT region
        FROM read_parquet('{PARQUET}')
        GROUP BY region
        ORDER BY SUM(total_pkts) DESC
        LIMIT {TOP_N}
    """).fetchall()]

    if not top_regions:
        raise SystemExit("No regions found in Parquet.")

    # Fetch time series for those regions
    region_filter = ",".join([f"'{r}'" for r in top_regions])

    rows = con.execute(f"""
        SELECT region, bin_ts, dns_share
        FROM read_parquet('{PARQUET}')
        WHERE region IN ({region_filter})
        ORDER BY region, bin_ts
    """).fetchall()

    series = defaultdict(lambda: {"x": [], "y": []})
    for region, bin_ts, dns_share in rows:
        series[region]["x"].append(bin_ts)
        series[region]["y"].append(float(dns_share) if dns_share is not None else 0.0)

    plt.figure(figsize=(12, 6))
    for region in top_regions:
        plt.plot(series[region]["x"], series[region]["y"], label=region)
    plt.title(f"RQ1: DNS Share over Time (Top {TOP_N} regions by total traffic)")
    plt.xlabel("Time (bin_ts)")
    plt.ylabel("DNS Share (dns_pkts / total_pkts)")
    plt.xticks(rotation=45)
    plt.legend(ncol=2, fontsize=9)
    plt.tight_layout()
    out1 = "Figure_RQ1_1_timeseries_top_regions.png"
    plt.savefig(out1, dpi=200)
    plt.close()

    # -------------------------------
    # Figure 2: Bar chart of overall (weighted) dns_share per region (top 15)
    # -------------------------------
    TOP_K = 15
    MIN_TOTAL = 1_000_000

    rows2 = con.execute(f"""
        SELECT region,
               SUM(dns_pkts) AS dns_pkts,
               SUM(total_pkts) AS total_pkts,
               (SUM(dns_pkts)::DOUBLE / NULLIF(SUM(total_pkts),0)) AS dns_share_overall
        FROM read_parquet('{PARQUET}')
        GROUP BY region
        HAVING SUM(total_pkts) >= {MIN_TOTAL}
        ORDER BY dns_share_overall DESC
        LIMIT {TOP_K}
    """).fetchall()

    regions = [r[0] for r in rows2]
    shares = [float(r[3]) for r in rows2]

    plt.figure(figsize=(12, 6))
    plt.bar(regions, shares)
    plt.title(f"RQ1: Overall DNS Share by Region (Top {TOP_K}, total_pkts ≥ {MIN_TOTAL:,})")
    plt.xlabel("Region")
    plt.ylabel("Overall DNS Share (SUM(dns_pkts) / SUM(total_pkts))")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    out2 = "Figure_RQ1_2_bar_overall_share_top15.png"
    plt.savefig(out2, dpi=200)
    plt.close()

    con.close()

    print("✅ Wrote figures:")
    print(" -", out1)
    print(" -", out2)


if __name__ == "__main__":
    main()
