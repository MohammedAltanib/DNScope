#New execution way

sudo apt update

sudo apt install python3-venv tshark -y

python3 -m venv venv

source venv/bin/activate

pip install pandas pyarrow duckdb matplotlib





sudo nano build_rq1_all_regions.py






import subprocess
from pathlib import Path
from collections import defaultdict
import pandas as pd
import re

DATA_DIR = Path("cloud_telescope_raw_dataset_3")
OUT = "rq1_all_regions.parquet"
BIN_SECONDS = 3600  # hourly bins

AWS_REGION_RE = re.compile(
    r"(us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9][a-z]?"
)

def infer_region(path: Path) -> str:
    text = str(path)
    m = AWS_REGION_RE.search(text)
    return m.group(0) if m else "unknown"

def count_packets_by_time(pcap_path: Path, display_filter=None):
    cmd = ["tshark", "-r", str(pcap_path), "-T", "fields", "-e", "frame.time_epoch"]

    if display_filter:
        cmd.insert(3, "-Y")
        cmd.insert(4, display_filter)

    counts = defaultdict(int)

    p = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        errors="ignore"
    )

    for line in p.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            ts = float(line)
            bin_ts = int(ts // BIN_SECONDS) * BIN_SECONDS
            counts[bin_ts] += 1
        except ValueError:
            continue

    p.wait()
    return counts

def main():
    pcaps = list(DATA_DIR.rglob("*.pcap")) + list(DATA_DIR.rglob("*.pcap.gz"))

    if not pcaps:
        raise SystemExit("No PCAP files found. Check DATA_DIR path.")

    rows = []

    for i, pcap in enumerate(pcaps, 1):
        region = infer_region(pcap)
        print(f"[{i}/{len(pcaps)}] Processing {pcap} | region={region}")

        total_counts = count_packets_by_time(pcap)
        dns_counts = count_packets_by_time(pcap, "dns || udp.port == 53")

        all_bins = set(total_counts.keys()) | set(dns_counts.keys())

        for bin_ts in sorted(all_bins):
            total_pkts = total_counts.get(bin_ts, 0)
            dns_pkts = dns_counts.get(bin_ts, 0)

            rows.append({
                "region": region,
                "bin_ts": pd.to_datetime(bin_ts, unit="s", utc=True),
                "dns_pkts": dns_pkts,
                "total_pkts": total_pkts,
                "dns_share": dns_pkts / total_pkts if total_pkts else 0
            })

    df = pd.DataFrame(rows)
    df.to_parquet(OUT, index=False)

    print(f"Done. Wrote {OUT}")
    print(df.head())

if __name__ == "__main__":
    main()



    
python build_rq1_all_regions.py


here we go now we have rq1_all_regions.parquet
later only use rq1.py
i will edit that later if they asked to 
 r u reading ?! all respcet prof
