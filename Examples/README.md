## Examples

The `Examples/` directory contains MEM-SBOM output from two real-world Python applications with multi-process architectures.

### Celery

[Celery](https://github.com/celery/celery) is a distributed task queue. The application was run and its memory was dumped while processing tasks. Celery spawns multiple worker processes, making it a good test case for MEM-SBOM's cross-process module extraction and deduplication.
```bash
python3 vol.py -f celery.vmem linux.mem_sbom.MEM_SBOM --pid 9818 --skip-heap --dep > celery_debug.txt
```

| File | Description |
|------|-------------|
| `celery_debug.txt` | Full pipeline output showing process tree discovery, per-process module extraction, classification, and version resolution |
| `Celery_SBOM.json` | Generated CycloneDX 1.5 SBOM|

### Apache Airflow

[Apache Airflow](https://github.com/apache/airflow) is a workflow orchestration platform. It has a complex multi-process architecture with several component types, each running as a separate Python process under a single parent. The memory was dumped while Airflow was actively running.

The process tree rooted at PID 22162 includes 26 Python processes:

| PID | Role |
|-----|------|
| 22162 | Standalone (root) |
| 22165 | Scheduler |
| 22167 | DAG Processor |
| 22170 | API Server |
| 22171 | Triggerer |
| 22176–22180 | API Server workers (python3.9) |
| 22181 | Triggerer gunicorn master |
| 22182–22183 | Triggerer gunicorn workers |
| 22184 | Scheduler gunicorn master |
| 22185 | Triggerer child |
| 22186–22187 | Scheduler gunicorn workers |

MEM-SBOM discovers the full tree from the root PID, extracts modules from each Python process, and deduplicates across workers that share modules.
```bash
python3 vol.py -f airflow.vmem linux.mem_sbom.MEM_SBOM --pid 22162 --skip-heap --dep > airflow_debug.txt
```

| File | Description |
|------|-------------|
| `airflow_debug.txt` | Full pipeline output showing the 26-process tree, module extraction per process, cross-process merge, and dependency analysis |
| `Airflow_SBOM.json` | Generated CycloneDX 1.5 SBOM |
