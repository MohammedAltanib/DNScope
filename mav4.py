import duckdb
import sys
import matplotlib.pyplot as plt
import pyfiglet
import pandas as pd
from scapy.all import rdpcap, DNS, DNSQR, IP
import os
import geoip2.database
import geopandas as gpd
from shapely.geometry import Point

# ---------------- Banner ----------------
ascii_banner = pyfiglet.figlet_format("Mohammed Altanib")
print(ascii_banner)
print("="*70)
print("        C8 Project - Noroff University Cyber Security")
print("="*70)

if len(sys.argv) < 2:
    print("Usage: python3 mav5.py dns_records.pcapng")
    sys.exit(1)

input_file = sys.argv[1]
print(f"[+] Processing {input_file}")

# ---------------- Step 1: PCAP -> Parquet ----------------
if input_file.endswith(".pcap") or input_file.endswith(".pcapng"):
    print("[+] Extracting DNS packets from PCAP/PCAPNG...")
    packets = rdpcap(input_file)

    records = []
    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            try:
                src_ip = pkt[IP].src if pkt.haslayer(IP) else None
                query_name = pkt[DNSQR].qname.decode(errors="ignore") if pkt[DNSQR].qname else None
                query_type = pkt[DNSQR].qtype
                timestamp = pkt.time

                benign_keywords = ["mozilla", "google", "firefox", "microsoft", "windows"]
                if query_name and any(k in query_name.lower() for k in benign_keywords):
                    classification = "benign"
                else:
                    classification = "suspicious"

                records.append([src_ip, query_name, query_type, timestamp, classification])

            except Exception:
                continue

    df = pd.DataFrame(records, columns=["src_ip", "query_name", "query_type", "timestamp", "classification"])
    parquet_file = input_file + ".parquet"
    df.to_parquet(parquet_file, engine="pyarrow", compression="snappy")
    print(f"[+] Saved extracted DNS data to {parquet_file}")

else:
    parquet_file = input_file

# ---------------- Step 2: DuckDB Analysis ----------------
print(f"[+] Analyzing {parquet_file}")

top_domains = duckdb.query(f"""
SELECT query_name, COUNT(*) as freq
FROM '{parquet_file}'
WHERE query_name IS NOT NULL
GROUP BY query_name
ORDER BY freq DESC
LIMIT 10
""").to_df()

top_ips = duckdb.query(f"""
SELECT src_ip, COUNT(*) as freq
FROM '{parquet_file}'
WHERE src_ip IS NOT NULL
GROUP BY src_ip
ORDER BY freq DESC
LIMIT 10
""").to_df()

query_types = duckdb.query(f"""
SELECT query_type, COUNT(*) as freq
FROM '{parquet_file}'
WHERE query_type IS NOT NULL
GROUP BY query_type
ORDER BY freq DESC
""").to_df()

classification_stats = duckdb.query(f"""
SELECT classification, COUNT(*) as freq
FROM '{parquet_file}'
GROUP BY classification
""").to_df()

print("\n=== Top 10 Queried Domains ===")
print(top_domains)
print("\n=== Top 10 Source IPs ===")
print(top_ips)
print("\n=== DNS Query Type Distribution ===")
print(query_types)
print("\n=== Benign vs Suspicious Queries ===")
print(classification_stats)

# ---------------- Step 3: Save CSVs ----------------
top_domains.to_csv("top_domains.csv", index=False)
top_ips.to_csv("top_ips.csv", index=False)
query_types.to_csv("query_types.csv", index=False)
classification_stats.to_csv("classification_stats.csv", index=False)

print("\n[+] Results saved as CSV (top_domains.csv, top_ips.csv, query_types.csv, classification_stats.csv)")

# ---------------- Step 4: Charts ----------------
plt.figure(figsize=(10,5))
plt.bar(top_domains['query_name'], top_domains['freq'], color='skyblue')
plt.xticks(rotation=45, ha='right')
plt.title("Top 10 Queried Domains")
plt.tight_layout()
plt.savefig("top_domains.png")
plt.close()

plt.figure(figsize=(10,5))
plt.bar(top_ips['src_ip'], top_ips['freq'], color='lightgreen')
plt.xticks(rotation=45, ha='right')
plt.title("Top 10 Source IPs")
plt.tight_layout()
plt.savefig("top_ips.png")
plt.close()

plt.figure(figsize=(6,6))
plt.pie(query_types['freq'], labels=query_types['query_type'], autopct='%1.1f%%')
plt.title("DNS Query Type Distribution")
plt.savefig("query_types.png")
plt.close()

plt.figure(figsize=(6,6))
plt.pie(classification_stats['freq'], labels=classification_stats['classification'], autopct='%1.1f%%')
plt.title("Benign vs Suspicious Queries")
plt.savefig("classification.png")
plt.close()

print("[+] Charts saved as PNG")

# ---------------- Step 5: GeoIP + World Map ----------------
geoip_db = "/usr/share/GeoIP/GeoLite2-City.mmdb"
if os.path.exists(geoip_db):
    geo_records = []
    reader = geoip2.database.Reader(geoip_db)
    for _, row in top_ips.iterrows():
        ip = row["src_ip"]
        try:
            response = reader.city(ip)
            lat = response.location.latitude
            lon = response.location.longitude
            country = response.country.name
            classification = df[df["src_ip"] == ip]["classification"].mode()[0]
            geo_records.append([ip, country, lat, lon, classification])
        except:
            geo_records.append([ip, "Unknown", None, None, "Unknown"])
    reader.close()

    geo_df = pd.DataFrame(geo_records, columns=["src_ip", "country", "lat", "lon", "classification"])
    geo_df.to_csv("geoip_info.csv", index=False)
    print("[+] GeoIP info saved as geoip_info.csv")

    world = gpd.read_file("world_shapefile/ne_110m_admin_0_countries.shp")

    geo_clean = geo_df.dropna(subset=["lat", "lon"]).reset_index(drop=True)
    gdf_points = gpd.GeoDataFrame(
        geo_clean,
        geometry=[Point(xy) for xy in zip(geo_clean["lon"], geo_clean["lat"])],
        crs="EPSG:4326"
    )

    colors = gdf_points["classification"].map({"benign": "green", "suspicious": "red", "Unknown": "gray"})

    fig, ax = plt.subplots(figsize=(12,6))
    world.plot(ax=ax, color="lightgrey", edgecolor="black")
    gdf_points.plot(ax=ax, color=colors, markersize=60, alpha=0.8)

    for idx, row in gdf_points.iterrows():
        ax.annotate(row["src_ip"], (row["lon"], row["lat"]), fontsize=8, color="blue")

    plt.title("Geographic Distribution of DNS Source IPs (Benign=Green, Suspicious=Red)")
    plt.savefig("world_map_ips.png")
    plt.close()

    print("[+] World map saved as world_map_ips.png")

else:
    print("[!] GeoIP database not found. Skipping map.")
