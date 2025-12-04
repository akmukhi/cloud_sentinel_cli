# Cloud Sentinel CLI

[![CI](https://github.com/USERNAME/cloud_sentinel_cli/actions/workflows/ci.yml/badge.svg)](https://github.com/USERNAME/cloud_sentinel_cli/actions/workflows/ci.yml)
[![Codecov](https://codecov.io/gh/USERNAME/cloud_sentinel_cli/branch/main/graph/badge.svg)](https://codecov.io/gh/USERNAME/cloud_sentinel_cli)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Lint: ruff](https://img.shields.io/badge/lint-ruff-yellow.svg)](https://github.com/astral-sh/ruff)

Cloud Sentinel is a lightweight, extensible CLI for detecting cloud misconfigurations and operational drift across GCP services. It focuses on quick, scriptable checks that are easy to automate in CI/CD and scheduled jobs.

- **Misconfigurations**: Opinionated checks for risky defaults and insecure resource settings.
- **IAM drift**: Detect unexpected role bindings, over-privileged service accounts, and policy deviations.
- **ETL/Airflow health**: Spot stale DAGs, failing tasks, and scheduling gaps.
- **Cloud Run hygiene**: Validate service configs, revisions, and runtime settings.
- **Extensible modules**: Add your own checks under `sentinel/modules/`.

> Note: Kubernetes health checks are planned. Current modules target GCP IAM, Storage, Airflow, and Cloud Run.

---

## Quickstart

Prerequisites:

- Python 3.10+ recommended
- GCP credentials via Application Default Credentials (ADC) or a service account

Install (editable) for local development:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -U pip
pip install -e .
```

Alternatively, run directly via `pipx` once packaging is enabled.

---

## Usage

After install, invoke the CLI:

```bash
cloudsentinal --help
```

### Scan GCP Resources

Scan both IAM and Storage for misconfigurations:

```bash
cloudsentinal scan gcp --project <PROJECT_ID>
```

With custom service account key age threshold:

```bash
cloudsentinal scan gcp --project <PROJECT_ID> --key-age-threshold 180
```

Skip public access checks (faster):

```bash
cloudsentinal scan gcp --project <PROJECT_ID> --skip-public
```

### Output Formats

Default output is human-readable table format. For automation, use JSON:

```bash
cloudsentinal scan gcp --project <PROJECT_ID> --format json > results.json
```

JSON output structure:

```json
{
  "gcp": {
    "iam": {
      "risks": [
        {
          "resource": "projects/my-project",
          "issue": "Overly permissive role binding: roles/owner",
          "severity": "high",
          "metadata": {...}
        }
      ],
      "passed": [
        {
          "check": "no_public_members",
          "resource": "projects/my-project",
          "message": "No public member bindings found"
        }
      ]
    },
    "storage": {
      "public_buckets": [...],
      "encryption_issues": [...]
    }
  }
}
```

### Scan Cloud Run Services

```bash
cloudsentinal scan services --project <PROJECT_ID> --region us-central1
```

Available flags:

- `--region`: target a specific Cloud Run region (default `-` for all)
- `--max-revision-age`: mark revisions older than N days (default 30)
- `--max-revisions`: mark services retaining more than N revisions (default 5)
- `--image-age-threshold`: mark container images older than N days (default 90)

Checks performed:

- Unauthenticated public access (IAM policy grants `allUsers`/`allAuthenticatedUsers`)
- Outdated container images (older than threshold or tagged `latest`)
- Containers missing CPU/Memory limits
- Stale revisions (age or retention over threshold)

Use JSON output for automation:

```bash
cloudsentinal scan services --project <PROJECT_ID> --format json
```

JSON snippet:

```json
{
  "services": {
    "cloud_run": {
      "public_access": [...],
      "outdated_images": [...],
      "resource_limits": [...],
      "stale_revisions": [...]
    }
  }
}
```

### Scan Airflow/ETL Instances

Scan self-hosted Airflow instances for health and configuration issues:

```bash
cloudsentinal scan etl --airflow-url http://airflow.example.com:8080 --username admin --password secret
```

With API token authentication:

```bash
cloudsentinal scan etl --airflow-url http://airflow.example.com:8080 --api-token <TOKEN>
```

Available flags:

- `--airflow-url`: Airflow webserver URL (required)
- `--username` / `--password`: Basic authentication credentials
- `--api-token`: API token for authentication (alternative to username/password)
- `--stale-dag-threshold`: Flag DAGs not updated in N days (default: 7)
- `--slow-task-multiplier`: Flag tasks slower than baseline * multiplier (default: 2.0)
- `--failure-window-hours`: Look back N hours for failed DAG runs (default: 24)

Checks performed:

- **DAG run failures**: Failed DAG runs in the past 24 hours (HIGH severity)
- **Slow-running tasks**: Tasks running slower than baseline (MEDIUM severity)
- **Unhealthy workers**: Airflow instance health check failures (HIGH severity)
- **Stale DAGs**: DAGs not updated in N days (MEDIUM severity)
- **Missing retry logic**: DAGs or tasks without retry configuration (LOW severity)

The command provides an alert summary showing counts per issue type:

```
⚠️  Alert Summary: 3 failed DAG(s), 1 slow task(s), 2 stale DAG(s)
```

Use JSON output for automation:

```bash
cloudsentinal scan etl --airflow-url http://airflow.example.com:8080 --api-token <TOKEN> --format json
```

JSON structure:

```json
{
  "etl": {
    "airflow": {
      "failed_dags": [...],
      "slow_tasks": [...],
      "unhealthy_workers": [...],
      "stale_dags": [...],
      "missing_retries": [...]
    },
    "summary": {
      "failed_dags": 3,
      "slow_tasks": 1,
      "unhealthy_workers": 0,
      "stale_dags": 2,
      "missing_retries": 5
    }
  }
}
```

**Authentication**: The Airflow REST API requires authentication. Use either:
- Basic authentication with `--username` and `--password`
- API token with `--api-token` (recommended for automation)

**Required Permissions**: Your Airflow user needs read access to:
- DAG metadata (`/api/v1/dags`)
- DAG runs (`/api/v1/dags/{dag_id}/dagRuns`)
- Task instances (`/api/v1/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances`)
- Health endpoint (`/api/v1/health`)

### Planned Commands

- IAM checks:
  ```bash
  cloudsentinal iam scan --project <PROJECT_ID>
  cloudsentinal iam diff --baseline baseline_iam.yaml --project <PROJECT_ID>
  ```

- Storage checks:
  ```bash
  cloudsentinal storage scan --project <PROJECT_ID>
  ```


---

## Authentication

Cloud Sentinel uses Google Cloud authentication. Options:

- **Application Default Credentials (ADC)**
  ```bash
  gcloud auth application-default login
  export GOOGLE_CLOUD_PROJECT=<PROJECT_ID>
  ```

- **Service Account JSON key** (least preferred for local use)
  ```bash
  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
  export GOOGLE_CLOUD_PROJECT=<PROJECT_ID>
  ```

Ensure your principal has least-privilege access to list/describe resources relevant to the checks you run.

---

## Project Structure

```
cloud_sentinel_cli/
├─ sentinel/
│  ├─ __init__.py
│  ├─ cli.py               # CLI entrypoint and command wiring
│  ├─ modules/
│  │  ├─ gcp_iam.py        # IAM checks (bindings, roles, SA posture)
│  │  ├─ gcp_storage.py    # Storage checks (ACLs, bucket posture)
│  │  ├─ etl_airflow.py    # Airflow/ETL health
│  │  └─ cloud_run.py      # Cloud Run configuration hygiene
│  └─ utils/               # Shared helpers
├─ tests/                  # Unit/integration tests
├─ LICENSE
└─ README.md
```

---

## Development

Set up a local environment:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .[dev]
```

Recommended tooling:

- Formatter: `black`
- Linting: `ruff` or `flake8`
- Testing: `pytest`

Run linters and tests:

```bash
ruff check .
black --check .
pytest -q
```

---

## Configuration

CLI flags take precedence over environment variables. Common environment variables (optional):

- `GOOGLE_CLOUD_PROJECT`: default project if not passed via `--project`.
- `GOOGLE_APPLICATION_CREDENTIALS`: path to a service account key.

Module-specific configuration is provided via subcommand flags. Use `--help` for details.

---

## Output

By default, output is human-readable table format with rich formatting (colors, tables). For automation, use JSON or YAML:

```bash
cloudsentinal scan gcp --project <PROJECT_ID> --format json > results.json
cloudsentinal scan gcp --project <PROJECT_ID> --format yaml > results.yaml
```

Supported formats: `table` (default, with rich formatting), `json`, `yaml`.

### Writing to Files

Use the `--output` flag to write results to a file:

```bash
cloudsentinal scan all --format json --output report.json
```

Use `--quiet` to suppress summary output when writing to file:

```bash
cloudsentinal scan all --format json --output report.json --quiet
```

### Severity Levels

Findings are categorized with severity levels (`LOW`, `MEDIUM`, `HIGH`) to help prioritize remediation. The CLI uses color coding in table output:
- **HIGH/CRITICAL**: Red
- **MEDIUM**: Yellow  
- **LOW**: Green

## CI/CD Integration

### Fail on High Severity

Use the `--fail-on-high` flag to exit with code 1 if any HIGH severity findings are detected. This is perfect for CI/CD pipelines:

```bash
cloudsentinal scan gcp --project <PROJECT_ID> --fail-on-high
```

Exit codes:
- `0`: No findings or only MEDIUM/LOW severity findings (unless `--fail-on-high` is set)
- `1`: Findings detected (or HIGH severity findings if `--fail-on-high` is set)

### Scan All Services

Run all available scans in one command:

```bash
cloudsentinal scan all --project <PROJECT_ID> --format json --output report.json
```

This runs:
- GCP IAM and Storage scans
- Cloud Run services scan
- ETL/Airflow scan (if `--airflow-url` is provided)

### GitHub Actions Example

See `.github/workflows/cloudsentinel-scan.yml` for a complete example. Basic usage:

```yaml
- name: Run CloudSentinel Scan
  run: |
    cloudsentinal scan all \
      --project ${{ secrets.GCP_PROJECT_ID }} \
      --format json \
      --output report.json \
      --fail-on-high
```

## Alerts

### Slack Alerts

Send findings to Slack via webhook:

```bash
cloudsentinal scan all \
  --project <PROJECT_ID> \
  --slack-webhook https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

The alert includes:
- Summary of findings by category
- Top findings with details
- Severity breakdown

### Email Alerts

Send findings via email:

```bash
cloudsentinal scan all \
  --project <PROJECT_ID> \
  --email-to alerts@example.com \
  --email-from cloudsentinel@example.com \
  --smtp-server smtp.gmail.com \
  --smtp-port 587 \
  --smtp-user your-email@gmail.com \
  --smtp-password your-app-password
```

Email alerts include an HTML-formatted report with the same information as Slack alerts.

---

## Roadmap

- Kubernetes cluster and workload health checks
- Baseline policy definition and drift detection across modules
- Pluggable rule engine and policy-as-code
- Rich exit codes for CI gating

---

## Contributing

Contributions are welcome!

1. Fork the repo and create a feature branch
2. Add/modify code and tests
3. Run linters and tests locally
4. Open a PR with context and examples

Please keep modules focused, composable, and testable.

---

## License

Licensed under the Apache License, Version 2.0. See the `LICENSE` file for details.
