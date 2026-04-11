import os
import re
from pathlib import Path
from typing import Union, List, Dict, Optional

import duckdb
import pandas as pd
import matplotlib.pyplot as plt


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║  DNScope++ Mini — RQ1·RQ2·RQ3  |  Author: Mohammed Altanib  ║
╚══════════════════════════════════════════════════════════════╝
"""


# ------------------------ Notebook helpers ------------------------

def _duckdb_path(p: Union[str, Path]) -> str:
    """
    DuckDB works best with forward slashes.
    Also handles Windows paths safely.
    """
    return str(Path(p).expanduser().resolve()).replace("\\", "/")


def ensure_dirs(out_dir: Union[str, Path]) -> Dict[str, Path]:
    out_dir = Path(out_dir)
    tables = out_dir / "tables"
    figs = out_dir / "figs"
    out_dir.mkdir(parents=True, exist_ok=True)
    tables.mkdir(parents=True, exist_ok=True)
    figs.mkdir(parents=True, exist_ok=True)
    return {"out": out_dir, "tables": tables, "figs": figs}


def connect_duck() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect()
    try:
        con.execute("PRAGMA threads=auto;")
    except Exception:
        pass
    return con


def list_parquets(src: Union[str, Path, List[Union[str, Path]]]) -> Union[str, List[str]]:
    """
    Accepts:
      - single parquet file
      - folder containing *.parquet
      - glob pattern (e.g., /data/e3/*.parquet)
      - list of files
    Returns:
      - string for DuckDB read_parquet(...) OR list of paths
    """
    if isinstance(src, (list, tuple)):
        files = [str(Path(x)) for x in src]
        files = [_duckdb_path(f) for f in files]
        return files

    srcp = Path(str(src)).expanduser()
    # If it's a directory -> use *.parquet
    if srcp.exists() and srcp.is_dir():
        pattern = _duckdb_path(srcp / "*.parquet")
        return pattern

    # If it's a file that exists
    if srcp.exists() and srcp.is_file():
        return _duckdb_path(srcp)

    # Otherwise treat as glob/pattern
    # DuckDB can read patterns like /path/*.parquet directly
    return _duckdb_path(srcp)


def _read_parquet_expr(src: Union[str, List[str]]) -> str:
    """
    Build a DuckDB read_parquet(...) expression.
    DuckDB supports:
      read_parquet('path/*.parquet')
      read_parquet(['file1.parquet','file2.parquet'])
    """
    if isinstance(src, list):
        quoted = ",".join([f"'{s}'" for s in src])
        return f"read_parquet([{quoted}])"
    else:
        return f"read_parquet('{src}')"


def col_exists(con: duckdb.DuckDBPyConnection, parquet_expr: str, col: str) -> bool:
    try:
        df = con.execute(f"DESCRIBE SELECT * FROM {parquet_expr}").df()
        return (df["column_name"].astype(str) == col).any()
    except Exception:
        # fallback (older duckdb)
        try:
            df = con.execute(f"PRAGMA table_info({parquet_expr})").df()
            return (df["name"].astype(str) == col).any()
        except Exception:
            return False


def pick_etld_col(con: duckdb.DuckDBPyConnection, parquet_expr: str) -> Optional[str]:
    if col_exists(con, parquet_expr, "etld1"):
        return "etld1"
    if col_exists(con, parquet_expr, "eTLD+1"):
        return '"eTLD+1"'
    return None


# --------------------------- Plot helpers ---------------------------

def save_line(df: pd.DataFrame, x: str, y: str, path: Path, title: str,
              xlabel: str, ylabel: str, show: bool = False):
    if df.empty:
        return
    plt.figure()
    plt.plot(df[x], df[y])
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.tight_layout()
    plt.savefig(path)
    if show:
        plt.show()
    plt.close()


def save_bar(df: pd.DataFrame, x: str, y: str, path: Path, title: str,
             xlabel: str, ylabel: str, show: bool = False):
    if df.empty:
        return
    plt.figure()
    plt.bar(df[x].astype(str), df[y])
    plt.title(title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.xticks(rotation=75, ha="right")
    plt.tight_layout()
    plt.savefig(path)
    if show:
        plt.show()
    plt.close()

def save_heatmap(qrc_df, path, title, show=False):
    if qrc_df.empty:
        return

    import numpy as np
    plt.figure()

    data = (
        qrc_df
        .set_index(["qtype", "rcode"])["cnt"]
        .unstack(fill_value=0)
    )

    # log-scale to handle skew
    log_data = np.log10(data + 1)

    plt.imshow(log_data, aspect="auto", cmap="viridis")
    plt.title(title + " (log10 scale)")
    plt.yticks(range(len(log_data.index)), log_data.index.astype(str))
    plt.xticks(range(len(log_data.columns)), log_data.columns.astype(str), rotation=45, ha="right")
    plt.colorbar(label="log10(count + 1)")
    plt.tight_layout()
    plt.savefig(path)
    if show:
        plt.show()
    plt.close()


# --------------------------- Main API ---------------------------

def dnscope_mini(
    src: Union[str, Path, List[Union[str, Path]]],
    out: Union[str, Path] = "run_out",
    topn: int = 20,
    show: bool = True,
    verbose: bool = True
) -> Dict[str, pd.DataFrame]:
    """
    Notebook-friendly runner.
    Returns a dict of DataFrames so you can inspect them in Jupyter.
    """
    if verbose:
        print(BANNER)

    dirs = ensure_dirs(out)
    con = connect_duck()

    src_norm = list_parquets(src)
    parquet_expr = _read_parquet_expr(src_norm)

    # Safety: check required columns exist
    required = ['frame.time_epoch', 'dns.qry.type', 'dns.flags.rcode']
    # in parquet schema, these appear with dots; DuckDB needs quoting like "frame.time_epoch"
    # we'll just test existence exactly as stored.
    missing = []
    schema = con.execute(f"DESCRIBE SELECT * FROM {parquet_expr}").df()
    cols = set(schema["column_name"].astype(str).tolist())
    for c in required:
        if c not in cols:
            missing.append(c)

    if missing:
        con.close()
        raise ValueError(f"Missing required columns in parquet: {missing}\n"
                         f"Found columns sample: {list(cols)[:20]}")

    # Basic sanity
    basic = con.execute(f"""
        SELECT COUNT(*) AS rows,
               MIN("frame.time_epoch") AS min_ts,
               MAX("frame.time_epoch") AS max_ts
        FROM {parquet_expr}
    """).df()
    if verbose:
        display(basic) if "display" in globals() else print(basic)

    # ---- RQ1: daily counts ----
    daily = con.execute(f"""
        SELECT date_trunc('day', to_timestamp(CAST("frame.time_epoch" AS DOUBLE))) AS day,
               COUNT(*) AS dns_events
        FROM {parquet_expr}
        WHERE "frame.time_epoch" IS NOT NULL
        GROUP BY day
        ORDER BY day
    """).df()
    daily.to_csv(dirs["tables"] / "daily_global.csv", index=False)
    save_line(daily, "day", "dns_events", dirs["figs"] / "daily_dns.png",
              "DNS events per day", "Day", "Events", show=show)

    # optional regional daily
    regional_daily = pd.DataFrame()
    if "region" in cols:
        regional_daily = con.execute(f"""
            SELECT region,
                   date_trunc('day', to_timestamp(CAST("frame.time_epoch" AS DOUBLE))) AS day,
                   COUNT(*) AS dns_events
            FROM {parquet_expr}
            WHERE "frame.time_epoch" IS NOT NULL AND region IS NOT NULL
            GROUP BY region, day
            ORDER BY day, region
        """).df()
        regional_daily.to_csv(dirs["tables"] / "regional_daily.csv", index=False)

        # Many lines (one per region) -> save separate figures
        for reg, sub in regional_daily.groupby("region"):
            safe = re.sub(r"[^a-zA-Z0-9_-]", "_", str(reg))
            save_line(sub.sort_values("day"), "day", "dns_events",
                      dirs["figs"] / f"regional_daily_{safe}.png",
                      f"DNS per day — {reg}", "Day", "Events", show=False)

    # ---- RQ2: qtype×rcode + ANY share ----
    qrc = con.execute(f"""
        SELECT CAST("dns.qry.type" AS INT) AS qtype,
               CAST("dns.flags.rcode" AS INT) AS rcode,
               COUNT(*) AS cnt
        FROM {parquet_expr}
        WHERE "dns.qry.type" IS NOT NULL
        GROUP BY qtype, rcode
        ORDER BY cnt DESC
    """).df()
    qrc.to_csv(dirs["tables"] / "qtype_rcode.csv", index=False)
    save_heatmap(qrc, dirs["figs"] / "qtype_rcode_heatmap.png", "QTYPE×RCODE (counts)", show=show)

    daily_any = con.execute(f"""
        WITH events AS (
          SELECT date_trunc('day', to_timestamp(CAST("frame.time_epoch" AS DOUBLE))) AS day,
                 CAST("dns.qry.type" AS INT) AS qtype
          FROM {parquet_expr}
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
    daily_any.to_csv(dirs["tables"] / "daily_any.csv", index=False)
    save_line(daily_any, "day", "any_pct", dirs["figs"] / "daily_any_pct.png",
              "ANY share per day (%)", "Day", "ANY %", show=show)

    # ---- RQ3: top src_24 and eTLD+1 ----
    if "src_24" in cols:
        top_src24 = con.execute(f"""
            SELECT src_24, COUNT(*) AS hits
            FROM {parquet_expr}
            GROUP BY src_24
            ORDER BY hits DESC
            LIMIT {int(topn)}
        """).df()
    else:
        top_src24 = pd.DataFrame()

    if not top_src24.empty:
        top_src24.to_csv(dirs["tables"] / "top_src24.csv", index=False)
        save_bar(top_src24, "src_24", "hits", dirs["figs"] / "top_src24.png",
                f"Top {topn} /24 sources", "/24", "Hits", show=show)

    etld_col = pick_etld_col(con, parquet_expr)
    if etld_col:
        top_etld1 = con.execute(f"""
            WITH norm AS (
              SELECT lower(NULLIF(TRIM({etld_col}), '')) AS etld1
              FROM {parquet_expr}
            )
            SELECT etld1, COUNT(*) AS hits
            FROM norm
            WHERE etld1 IS NOT NULL
              AND etld1 NOT IN ('null','nan','<unknown extended label>','bind','local','stage','')
            GROUP BY etld1
            ORDER BY hits DESC
            LIMIT {int(topn)}
        """).df()
    else:
        top_etld1 = pd.DataFrame()

    if not top_etld1.empty:
        top_etld1.to_csv(dirs["tables"] / "top_etld1.csv", index=False)
        save_bar(top_etld1, "etld1", "hits", dirs["figs"] / "top_etld1.png",
                f"Top {topn} eTLD+1", "eTLD+1", "Hits", show=show)

    con.close()

    if verbose:
        print("\nSummary:")
        print(f"  Tables: {dirs['tables']}")
        print(f"  Figures: {dirs['figs']}")

    return {
        "basic": basic,
        "daily": daily,
        "regional_daily": regional_daily,
        "qtype_rcode": qrc,
        "daily_any": daily_any,
        "top_src24": top_src24,
        "top_etld1": top_etld1,
    }
