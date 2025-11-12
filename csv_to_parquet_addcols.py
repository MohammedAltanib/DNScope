#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
csv_to_parquet_addcols.py
Requirements:
  pip install pandas pyarrow tldextract

What it does:
 - Reads CSV in chunks (chunksize)
 - Adds src_24 column (IPv4 aggregation to /24) and eTLD+1 column (using tldextract)
 - Converts frame.time_epoch to numeric (float)
 - Writes to Parquet file efficiently via pyarrow.ParquetWriter (append per chunk)
 - Simple logging for progress and errors
"""
from pathlib import Path
import argparse
import logging
import sys

import pandas as pd
import tldextract
import pyarrow as pa
import pyarrow.parquet as pq


def setup_logger():
    log = logging.getLogger("csv2parquet")
    fmt = "%(asctime)s %(levelname)s: %(message)s"
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(fmt))
    log.addHandler(handler)
    log.setLevel(logging.INFO)
    return log


log = setup_logger()


def to_src24(ip_str: str):
    """Convert IPv4 string to simple /24 form, else return None."""
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    # quick IPv4 check (no heavy ipaddress module to stay fast)
    parts = ip_str.split('.')
    if len(parts) != 4:
        return None
    try:
        # validate numeric octets 0-255
        for p in parts:
            if not p.isdigit():
                return None
            n = int(p)
            if n < 0 or n > 255:
                return None
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return None


def etld1(qname):
    """Return eTLD+1 using tldextract or None on failure/empty."""
    try:
        if pd.isna(qname):
            return None
        q = qname.strip()
        if q == "":
            return None
        te = tldextract.extract(q)
        if te.domain == "":
            return None
        if te.suffix:
            return te.domain + "." + te.suffix
        return te.domain
    except Exception:
        return None


def process_chunk(chunk: pd.DataFrame):
    # normalize possible column names (common variants)
    # The user earlier assumed columns like: frame.time_epoch, ip.src, ip.dst, dns.qry.name, dns.qry.type
    # If different, user can map before calling script or we keep flexible:
    colmap = {}
    if 'ip.src' in chunk.columns:
        src_col = 'ip.src'
    elif 'ip_src' in chunk.columns:
        src_col = 'ip_src'
    else:
        src_col = None

    # dns qname name column
    if 'dns.qry.name' in chunk.columns:
        qname_col = 'dns.qry.name'
    elif 'dns_qry_name' in chunk.columns:
        qname_col = 'dns_qry_name'
    else:
        qname_col = None

    # frame.time_epoch
    time_col = 'frame.time_epoch' if 'frame.time_epoch' in chunk.columns else ('frame_time_epoch' if 'frame_time_epoch' in chunk.columns else None)

    # compute src_24
    if src_col:
        chunk['src_24'] = chunk[src_col].fillna('').astype(str).apply(lambda x: to_src24(x) if x else None)
    else:
        chunk['src_24'] = None

    # compute eTLD+1
    if qname_col:
        # apply in vectorized-friendly way
        chunk['eTLD+1'] = chunk[qname_col].astype(str).apply(etld1)
    else:
        chunk['eTLD+1'] = None

    # cast timestamp if present
    if time_col:
        chunk[time_col] = pd.to_numeric(chunk[time_col], errors='coerce')

    return chunk


def main():
    ap = argparse.ArgumentParser(description="CSV -> Parquet with src_24 and eTLD+1")
    ap.add_argument("csv", type=Path, help="Input CSV path")
    ap.add_argument("parquet", type=Path, help="Output Parquet path (will be created/overwritten)")
    ap.add_argument("--chunksize", type=int, default=200_000, help="rows per chunk (default 200000)")
    ap.add_argument("--dtype-str", action='store_true', help="read CSV columns as str (safer for mixed types)")
    ap.add_argument("--on-bad-lines", choices=['skip', 'warn', 'raise'], default='skip', help="behavior for bad CSV lines")
    args = ap.parse_args()

    csv_path: Path = args.csv
    out_parquet: Path = args.parquet

    if not csv_path.exists():
        log.error("Input CSV not found: %s", csv_path)
        sys.exit(2)

    out_parquet.parent.mkdir(parents=True, exist_ok=True)
    # ensure tldextract has its suffix list cached (first run may download, but usually it's fast)
    tldextract.TLDExtract(cache_dir=str(Path.home() / ".tldextract_suffix_cache"))

    read_csv_kwargs = {'chunksize': args.chunksize}
    if args.dtype_str:
        read_csv_kwargs['dtype'] = str
    # pandas arg name recent: on_bad_lines
    read_csv_kwargs['on_bad_lines'] = args.on_bad_lines

    writer = None
    rows_written = 0
    chunk_no = 0

    try:
        for chunk in pd.read_csv(csv_path, **read_csv_kwargs):
            chunk_no += 1
            log.info("Processing chunk #%d (rows=%d)", chunk_no, len(chunk))
            chunk = process_chunk(chunk)

            # convert to pyarrow table (preserve dtypes reasonably)
            table = pa.Table.from_pandas(chunk, preserve_index=False)

            if writer is None:
                # create writer with the first chunk's schema; choose snappy compression (fast + common)
                writer = pq.ParquetWriter(str(out_parquet), table.schema, compression='snappy')
                log.info("Created ParquetWriter -> %s", out_parquet)

            writer.write_table(table)
            rows_written += table.num_rows
            log.info("Wrote %d rows (total %d)", table.num_rows, rows_written)
    except pd.errors.EmptyDataError:
        log.error("Empty CSV or unreadable: %s", csv_path)
        sys.exit(3)
    except Exception as e:
        log.exception("Unexpected error while processing: %s", e)
        if writer:
            writer.close()
        sys.exit(4)
    finally:
        if writer:
            writer.close()

    log.info("Done. Total rows written: %d -> %s", rows_written, out_parquet)


if __name__ == "__main__":
    main()
