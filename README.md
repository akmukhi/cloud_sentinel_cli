# Cloud Sentinel CLI

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
sentinel --help
```

Example commands (subject to change as the CLI evolves):

- IAM checks:
  ```bash
  sentinel iam scan --project <PROJECT_ID>
  sentinel iam diff --baseline baseline_iam.yaml --project <PROJECT_ID>
  ```

- Storage checks:
  ```bash
  sentinel storage scan --project <PROJECT_ID>
  ```

- Airflow (ETL) health:
  ```bash
  sentinel airflow health --env <composer|self-hosted> --project <PROJECT_ID>
  ```

- Cloud Run hygiene:
  ```bash
  sentinel cloud-run scan --project <PROJECT_ID> --region <REGION>
  ```

> The exact subcommands and flags will align with implementations in `sentinel/cli.py` and `sentinel/modules/`. See `--help` on each subcommand for the latest interface once implemented.

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

By default, output is human-readable. For automation, prefer JSON:

```bash
sentinel iam scan --project <PROJECT_ID> --format json > results.json
```

Planned formats: `table`, `json`, `yaml`.

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
