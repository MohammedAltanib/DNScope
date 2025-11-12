#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fast DNS Extractor — PCAP → Parquet (DNS-only, privacy-aware)
Implements the same pipeline described in Methodology:
  Stage 1: DNS extraction via tshark
  Stage 2: Structuring and Parquet conversion
  Stage 3: Privacy-preserving aggregation (/24 + eTLD+1)
Author: Mohammed Altanib (2025)
"""

import os, sys, subprocess, tempfile, shlex, argparse, datetime
import duckdb

def run(cmd):
    print("+", cmd)
    subprocess.check_call(cmd, shell=True)

def main():
    ap = argparse.ArgumentParser(description="Fast extract DNS from PCAP→Parquet via tshark+DuckDB")
    ap.add_argument('inputs', nargs='+', help='PCAP/PCAPNG files (supports .pcap or .pcap.gz)')
    ap.add_argument('--out-parquet', required=True, help='Output Parquet path (e.g., dataset3_parquet/e3/week51.parquet)')
    ap.add_argument('--region', default='unknown', help='Region tag (e.g., eu-north-1a)')
    ap.add_argument('--week-id', default=None, help='Week identifier (e.g., 2023W51)')
    ap.add_argument('--bin-minutes', type=int, default=60, help='Bin duration in minutes (default=60)')
    args = ap.parse_args()

    # Week ID if not supplied
    week_id = args.week_id or f"{datetime.date.today().isocalendar()[0]}W{datetime.date.today().isocalendar()[1]:02d}"

    tmpdir = tempfile.mkdtemp(prefix="dns_fast_")
    csv_paths = []

    # ------------------------------------------------------------
    # 1) Extract DNS packets → CSV using tshark
    # ------------------------------------------------------------
    for i, path in enumerate(args.inputs, 1):
        csv_out = os.path.join(tmpdir, f"dns_{i}.csv")
        cmd = (
            f'tshark -r {shlex.quote(path)} -Y "dns" -T fields -E header=y -E separator=, -n '
            f'-e frame.time_epoch -e ip.src -e ipv6.src -e dns.qry.name -e dns.flags.response '
            f'-e dns.qry.type -e dns.flags.rcode > {shlex.quote(csv_out)}'
        )
        run(cmd)
        csv_paths.append(csv_out)

    # ------------------------------------------------------------
    # 2) Merge CSVs and convert to Parquet (DNScope++ schema)
    # ------------------------------------------------------------
    outp = args.out_parquet
    os.makedirs(os.path.dirname(outp) or ".", exist_ok=True)
    con = duckdb.connect()
    con.execute(f"PRAGMA threads={os.cpu_count()};")


    # Build unified table from all CSVs
    union_sql = " UNION ALL ".join(
        [f"SELECT * FROM read_csv_auto('{p}', header=TRUE)" for p in csv_paths]
    )

    bin_secs = args.bin_minutes * 60

    # ------------------------------------------------------------
    # 3) SQL transformation — privacy & analysis fields
    # ------------------------------------------------------------
    sql = f"""
    COPY (
      SELECT
        to_timestamp(CAST(frame_time_epoch AS DOUBLE))::TIMESTAMP AS ts,
        to_timestamp(CAST(floor(CAST(frame_time_epoch AS DOUBLE) / {bin_secs}) * {bin_secs} AS DOUBLE))::TIMESTAMP AS bin_ts,
        '{args.region}'::VARCHAR AS region,
        '{week_id}'::VARCHAR AS week_id,

        -- source IP handling (IPv4 or IPv6)
        COALESCE(ip_src, ipv6_src)::VARCHAR AS src_ip,

        -- privacy-preserving /24 aggregation (IPv4 only)
        REGEXP_REPLACE(COALESCE(ip_src,''), '([0-9]+\\.[0-9]+\\.[0-9]+)\\.[0-9]+', '\\1.0/24') AS src_24,

        ''::VARCHAR AS country,
        TRUE AS dns,
        CAST(COALESCE(dns_flags_response,0) AS BOOLEAN) AS is_resp,

        LOWER(REPLACE(COALESCE(dns_qry_name,''), ' ', ''))::VARCHAR AS qname,

        -- eTLD+1 extraction (simplified via regex)
        REGEXP_REPLACE(LOWER(REPLACE(COALESCE(dns_qry_name,''), ' ', '')),
                       '^.*?([a-z0-9-]+\\.[a-z]+)$', '\\1') AS etld1,

        CAST(NULLIF(dns_qry_type,'') AS INTEGER) AS qtype,
        CASE WHEN NULLIF(dns_qry_type,'') IS NULL THEN NULL
             WHEN dns_qry_type='1' THEN 'A'
             WHEN dns_qry_type='28' THEN 'AAAA'
             WHEN dns_qry_type='12' THEN 'PTR'
             WHEN dns_qry_type='5' THEN 'CNAME'
             WHEN dns_qry_type='15' THEN 'MX'
             WHEN dns_qry_type='16' THEN 'TXT'
             WHEN dns_qry_type='65' THEN 'HTTPS'
             ELSE dns_qry_type END AS qtype_name,

        CAST(NULLIF(dns_flags_rcode,'') AS INTEGER) AS rcode,
        CASE WHEN NULLIF(dns_flags_rcode,'') IS NULL THEN NULL
             WHEN dns_flags_rcode='0' THEN 'NOERROR'
             WHEN dns_flags_rcode='3' THEN 'NXDOMAIN'
             WHEN dns_flags_rcode='2' THEN 'SERVFAIL'
             WHEN dns_flags_rcode='5' THEN 'REFUSED'
             ELSE dns_flags_rcode END AS rcode_name,

        'unknown'::VARCHAR AS classification
      FROM (
        {union_sql}
      )
      WHERE COALESCE(dns_qry_name,'') <> ''
    )
    TO '{outp}' (FORMAT PARQUET, COMPRESSION ZSTD);
    """

    con.execute(sql)
    con.close()
    print(f"\n✅ Wrote Parquet: {outp}\nTemporary CSVs stored in: {tmpdir}")

if __name__ == "__main__":
    main()
