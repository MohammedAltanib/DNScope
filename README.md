# DNScope 🔍

DNScope is a Python tool for analyzing DNS traffic from PCAP/PCAPNG files.  
It was developed as part of the **Bachelor Project (C8 - Noroff University, Cyber Security)** focusing on **DNS Internet Background Radiation** using **Cloud Telescope datasets**.

The tool performs the following tasks:
- Extracts DNS queries from PCAP/PCAPNG files.
- Classifies queries as **benign** or **suspicious**.
- Saves results into **Parquet** format for fast analysis.
- Runs analytical queries using **DuckDB**.
- Generates **CSV reports and charts (PNG)**.
- Maps source IPs on a **world map** using **GeoIP + GeoPandas**.

---

## 📦 Requirements

Python ≥ 3.9 is recommended.  

Dependencies are listed in `requirements.txt`.  
Minimal version (for DNScope only):

```txt
duckdb
matplotlib
pyfiglet
pandas
scapy
geoip2
geopandas
shapely
pyarrow
