#!/usr/bin/env python3
# dnscope.py — Analyze DNS IBR from PCAP/Parquet with charts and optional Geo maps

import sys
import os
import argparse
import duckdb
import pandas as pd

# --- Optional/variant imports ---
# Scapy (streaming reader is better than rdpcap for large files)
try:
    from scapy.utils import PcapReader
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.inet import IP
except Exception:
    from scapy.all import PcapReader, DNS, DNSQR, IP  # type: ignore

# Banner (fallback if not installed)
try:
    import pyfiglet
except Exception:
    pyfiglet = None

# Plotting
import matplotlib.pyplot as plt

# Parquet writer (for chunked streaming without append)
import pyarrow as pa
import pyarrow.parquet as pq

# Geo (optional)
try:
    import geoip2.database  # type: ignore
    import geopandas as gpd  # type: ignore
    from shapely.geometry import Point  # type: ignore
    GEO_EXTRAS_OK = True
except Exception:
    GEO_EXTRAS_OK = False


# ---------------- Utilities ----------------
def banner(text="DNScope"):
    if pyfiglet:
        try:
            ascii_banner = pyfiglet.figlet_format(text)
            print(ascii_banner)
        except Exception:
            print(f"=== {text} ===")
    else:
        print(f"=== {text} ===")

    print("=" * 70)
    print(" C8 Project - Noroff University Cyber Security - MOHAMMED ALTANIB")
    print("=" * 70)


def normalize_qname(qname: bytes) -> str:
    """Decode, lowercase, and strip trailing dot from a DNS qname."""
    try:
        s = qname.decode(errors="ignore")
    except Exception:
        return ""
    return s.strip().lower().rstrip(".")


# Common DNS QTYPE mapping
QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY"
}

# Naive benign keywords (placeholder heuristic)
BENIGN_KEYWORDS = {"mozilla", "google", "firefox", "microsoft", "windows"}


# ---------------- PCAP -> Parquet (streaming) ----------------
def stream_pcap_to_parquet(pcap_path: str, parquet_path: str):
    """Stream a PCAP/PCAPNG file and write DNS query rows into Parquet using PyArrow writer."""
    os.makedirs(os.path.dirname(parquet_path) or ".", exist_ok=True)

    records = []
    count = 0

    schema = pa.schema([
        pa.field("src_ip", pa.string()),
        pa.field("query_name", pa.string()),
        pa.field("query_type", pa.int32()),
        pa.field("timestamp", pa.float64()),
        pa.field("classification", pa.string()),
    ])

    # Ensure a fresh file each run (no unsupported append with PyArrow)
    if os.path.exists(parquet_path):
        os.remove(parquet_path)

    writer = pq.ParquetWriter(parquet_path, schema=schema, compression="snappy")

    try:
        with PcapReader(pcap_path) as pr:
            for pkt in pr:
                count += 1
                if pkt is None or not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
                    continue
                try:
                    src_ip = pkt[IP].src if pkt.haslayer(IP) else None
                    qname = normalize_qname(pkt[DNSQR].qname or b"")
                    qtype = int(pkt[DNSQR].qtype or 0)
                    ts = float(getattr(pkt, "time", 0.0))

                    classification = "benign" if (qname and any(k in qname for k in BENIGN_KEYWORDS)) else "suspicious"

                    records.append((src_ip, qname, qtype, ts, classification))

                    # Flush every 100k rows to control memory usage
                    if len(records) >= 100_000:
                        df_chunk = pd.DataFrame(records, columns=["src_ip", "query_name", "query_type", "timestamp", "classification"])
                        table = pa.Table.from_pandas(df_chunk, schema=schema, preserve_index=False)
                        writer.write_table(table)
                        records.clear()
                except Exception:
                    # Skip malformed packets
                    continue

        # Write remaining rows
        if records:
            df_chunk = pd.DataFrame(records, columns=["src_ip", "query_name", "query_type", "timestamp", "classification"])
            table = pa.Table.from_pandas(df_chunk, schema=schema, preserve_index=False)
            writer.write_table(table)

        print(f"[+] Saved extracted DNS data to {parquet_path} (from {count:,} packets)")
    finally:
        writer.close()


# ---------------- DuckDB helpers ----------------
def _set_duckdb_threads(con):
    """Try to set threads=auto; fallback to CPU-1; ignore if unsupported."""
    try:
        con.execute("PRAGMA threads=auto;")
        return
    except Exception:
        pass
    try:
        threads = max(1, (os.cpu_count() or 2) - 1)
        con.execute(f"PRAGMA threads={threads};")
    except Exception:
        pass  # continue with defaults


# ---------------- Analysis with DuckDB ----------------
def analyze_with_duckdb(parquet_path: str, top_n: int = 10):
    con = duckdb.connect()
    _set_duckdb_threads(con)

    top_domains = con.execute(f"""
        SELECT query_name, COUNT(*) AS freq
        FROM read_parquet('{parquet_path}')
        WHERE query_name IS NOT NULL AND query_name <> ''
        GROUP BY query_name
        ORDER BY freq DESC
        LIMIT {top_n}
    """).df()

    top_ips = con.execute(f"""
        SELECT src_ip, COUNT(*) AS freq
        FROM read_parquet('{parquet_path}')
        WHERE src_ip IS NOT NULL AND src_ip <> ''
        GROUP BY src_ip
        ORDER BY freq DESC
        LIMIT {top_n}
    """).df()

    query_types = con.execute(f"""
        SELECT query_type, COUNT(*) AS freq
        FROM read_parquet('{parquet_path}')
        WHERE query_type IS NOT NULL
        GROUP BY query_type
        ORDER BY freq DESC
    """).df()

    classification_stats = con.execute(f"""
        SELECT classification, COUNT(*) AS freq
        FROM read_parquet('{parquet_path}')
        GROUP BY classification
        ORDER BY freq DESC
    """).df()

    con.close()

    # Map qtype numbers -> names for readability
    if not query_types.empty:
        query_types["qtype"] = query_types["query_type"].map(QTYPE_MAP).fillna(query_types["query_type"].astype(str))

    return top_domains, top_ips, query_types, classification_stats


# ---------------- Outputs ----------------
def save_tables_csv(out_dir, top_domains, top_ips, query_types, classification_stats):
    os.makedirs(out_dir, exist_ok=True)
    top_domains.to_csv(os.path.join(out_dir, "top_domains.csv"), index=False)
    top_ips.to_csv(os.path.join(out_dir, "top_ips.csv"), index=False)

    # Save query types with readable label if present
    qt = query_types.copy()
    if "qtype" in qt.columns:
        qt = qt[["qtype", "freq"]].rename(columns={"qtype": "query_type"})
    qt.to_csv(os.path.join(out_dir, "query_types.csv"), index=False)

    classification_stats.to_csv(os.path.join(out_dir, "classification_stats.csv"), index=False)
    print("[+] Results saved as CSV (top_domains.csv, top_ips.csv, query_types.csv, classification_stats.csv)")


def plot_charts(out_dir, top_domains, top_ips, query_types, classification_stats):
    os.makedirs(out_dir, exist_ok=True)

    if not top_domains.empty:
        plt.figure(figsize=(10, 5))
        plt.bar(top_domains["query_name"], top_domains["freq"])
        plt.xticks(rotation=45, ha="right")
        plt.title("Top Queried Domains")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "top_domains.png"), bbox_inches="tight")
        plt.close()

    if not top_ips.empty:
        plt.figure(figsize=(10, 5))
        plt.bar(top_ips["src_ip"], top_ips["freq"])
        plt.xticks(rotation=45, ha="right")
        plt.title("Top Source IPs")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, "top_ips.png"), bbox_inches="tight")
        plt.close()

    if not query_types.empty:
        labels = query_types["qtype"] if "qtype" in query_types.columns else query_types["query_type"].astype(str)
        plt.figure(figsize=(6, 6))
        plt.pie(query_types["freq"], labels=labels, autopct="%1.1f%%")
        plt.title("DNS Query Type Distribution")
        plt.savefig(os.path.join(out_dir, "query_types.png"), bbox_inches="tight")
        plt.close()

    if not classification_stats.empty:
        plt.figure(figsize=(6, 6))
        plt.pie(classification_stats["freq"], labels=classification_stats["classification"], autopct="%1.1f%%")
        plt.title("Benign vs Suspicious Queries")
        plt.savefig(os.path.join(out_dir, "classification.png"), bbox_inches="tight")
        plt.close()

    print("[+] Charts saved as PNG (top_domains.png, top_ips.png, query_types.png, classification.png)")


# ---------------- GeoIP + World Map (optional) ----------------
def geoip_map(parquet_path: str, out_dir: str, geoip_db: str, world_shp: str):
    if not GEO_EXTRAS_OK:
        print("[!] Geo extras not installed. Skipping GeoIP map.")
        return

    if not (geoip_db and os.path.exists(geoip_db)):
        print("[!] GeoIP database not found. Skipping map.")
        return
    if not (world_shp and os.path.exists(world_shp)):
        print("[!] World shapefile not found. Skipping map.")
        return

    # Load parquet for classification lookup
    df = pd.read_parquet(parquet_path)

    # Compute top IPs (10) for mapping
    con = duckdb.connect()
    top_ips = con.execute(f"""
        SELECT src_ip, COUNT(*) AS freq
        FROM read_parquet('{parquet_path}')
        WHERE src_ip IS NOT NULL AND src_ip <> ''
        GROUP BY src_ip
        ORDER BY freq DESC
        LIMIT 10
    """).df()
    con.close()

    # Geolocate
    geo_records = []
    reader = geoip2.database.Reader(geoip_db)
    for _, row in top_ips.iterrows():
        ip = row["src_ip"]
        try:
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            country = response.country.name
        except Exception:
            lat = lon = None
            country = "Unknown"

        try:
            classification = df.loc[df["src_ip"] == ip, "classification"].mode().iat[0]
        except Exception:
            classification = "Unknown"

        geo_records.append([ip, country, lat, lon, classification])
    reader.close()

    geo_df = pd.DataFrame(geo_records, columns=["src_ip", "country", "lat", "lon", "classification"])
    geo_df.to_csv(os.path.join(out_dir, "geoip_info.csv"), index=False)
    print("[+] GeoIP info saved as geoip_info.csv")

    # Plot world + points
    world = gpd.read_file(world_shp)
    geo_clean = geo_df.dropna(subset=["lat", "lon"]).reset_index(drop=True)
    if geo_clean.empty:
        print("[!] No geolocatable IPs to plot.")
        return

    gdf_points = gpd.GeoDataFrame(
        geo_clean,
        geometry=[Point(xy) for xy in zip(geo_clean["lon"], geo_clean["lat"])],
        crs="EPSG:4326"
    )

    color_map = {"benign": "green", "suspicious": "red", "Unknown": "gray"}
    colors = gdf_points["classification"].map(lambda c: color_map.get(str(c).lower(), "gray"))

    fig, ax = plt.subplots(figsize=(12, 6))
    world.plot(ax=ax, color="lightgrey", edgecolor="black")
    gdf_points.plot(ax=ax, color=colors, markersize=60, alpha=0.85)
    for _, r in gdf_points.iterrows():
        ax.annotate(r["src_ip"], (r["lon"], r["lat"]), fontsize=8)
    plt.title("Geographic Distribution of DNS Source IPs")
    out_path = os.path.join(out_dir, "world_map_ips.png")
    plt.savefig(out_path, bbox_inches="tight")
    plt.close()
    print(f"[+] World map saved as {out_path}")


# ---------------- Main ----------------
def main():
    parser = argparse.ArgumentParser(description="Analyze DNS Internet Background Radiation from PCAP/Parquet.")
    parser.add_argument("input", help="PCAP/PCAPNG or Parquet file")
    parser.add_argument("--out", default="outputs", help="Output directory (default: outputs)")
    parser.add_argument("--top-n", type=int, default=10, help="Top N domains/IPs (default: 10)")
    parser.add_argument("--geoip-db", default="/usr/share/GeoIP/GeoLite2-City.mmdb", help="Path to GeoLite2-City.mmdb")
    parser.add_argument("--world-shp", default="world_shapefile/ne_110m_admin_0_countries.shp", help="Path to world shapefile (.shp)")
    parser.add_argument("--no-charts", action="store_true", help="Skip generating charts")
    parser.add_argument("--no-geo", action="store_true", help="Skip GeoIP/world map")
    parser.add_argument("--no-banner", action="store_true", help="Hide ASCII banner")
    parser.add_argument("--banner-text", default="DNScope", help="Text for ASCII banner (default: DNScope)")

    args = parser.parse_args()

    if not args.no_banner:
        banner(args.banner_text)

    inp = args.input
    os.makedirs(args.out, exist_ok=True)

    # Decide parquet target
        # Decide parquet target
    if inp.endswith((".pcap", ".pcapng", ".pcap.gz")):
        parquet_path = os.path.join(args.out, os.path.basename(inp) + ".parquet")
        print(f"[+] Processing PCAP: {inp}")
        stream_pcap_to_parquet(inp, parquet_path)
    elif inp.endswith(".parquet"):
        parquet_path = inp
        print(f"[+] Using existing Parquet: {parquet_path}")
    else:
        print(f"[!] Unknown file type: {inp}")
        sys.exit(1)


    print(f"[+] Analyzing {parquet_path}")
    top_domains, top_ips, query_types, classification_stats = analyze_with_duckdb(parquet_path, top_n=args.top_n)

    # Console previews
    pd.set_option("display.max_rows", 20)
    print("\n=== Top Queried Domains ===")
    print(top_domains)
    print("\n=== Top Source IPs ===")
    print(top_ips)
    print("\n=== DNS Query Type Distribution ===")
    print(query_types if "qtype" not in query_types.columns else query_types[["qtype", "freq"]])
    print("\n=== Benign vs Suspicious Queries ===")
    print(classification_stats)

    # Save tables + charts
    save_tables_csv(args.out, top_domains, top_ips, query_types, classification_stats)
    if not args.no_charts:
        plot_charts(args.out, top_domains, top_ips, query_types, classification_stats)

    # Geo map (optional)
    if not args.no_geo:
        geoip_map(parquet_path, args.out, args.geoip_db, args.world_shp)

    print("\n[✓] Done.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print("Usage: python dnscope.py <input.pcapng|input.parquet> [--out outputs] [--no-geo]")
        sys.exit(1)
    main()
