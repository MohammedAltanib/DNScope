## You have to enable the venv before any kind of analysis

#──(venv)─(kali㉿kali)-[/mnt/data/dataset3_parquet/test]
#└─$ python3


import duckdb
duckdb.sql("""
COPY (
  SELECT * 
  FROM read_parquet('/mnt/data/dataset3_parquet/e3/*.parquet', union_by_name=True)
) TO '/mnt/data/dataset3_parquet/e3_merged.parquet' (FORMAT PARQUET);
""")
