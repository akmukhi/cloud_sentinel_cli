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

- Airflow (ETL) health:
  ```bash
  cloudsentinal airflow health --env <composer|self-hosted> --project <PROJECT_ID>
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

By default, output is human-readable table format. For automation, prefer JSON:

```bash
cloudsentinal scan gcp --project <PROJECT_ID> --format json > results.json
```

Supported formats: `table` (default), `json`.

Findings are categorized with severity levels (`LOW`, `MEDIUM`, `HIGH`) to help prioritize remediation. Cloud Run service scans surface the severity per issue in both table and JSON output.

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
