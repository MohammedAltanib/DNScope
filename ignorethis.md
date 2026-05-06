#New execution way

sudo apt update

sudo apt install python3-venv tshark -y

python3 -m venv venv

source venv/bin/activate

pip install pandas pyarrow duckdb matplotlib

sudo nano build_rq1_all_regions.py

    
python build_rq1_all_regions.py


here we go now we have:

rq1_all_regions.parquet

python RQ1.py
