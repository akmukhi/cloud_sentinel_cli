"""Airflow/ETL scanning helpers for the Cloud Sentinel CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore


class AirflowModuleError(RuntimeError):
    """Base exception for Airflow scanning errors."""


class MissingDependencyError(AirflowModuleError):
    """Raised when requests library is not installed."""


class AuthenticationError(AirflowModuleError):
    """Raised when authentication fails."""


class ConnectionError(AirflowModuleError):
    """Raised when unable to connect to Airflow API."""


@dataclass
class ETLFinding:
    """Represents a single ETL/Airflow issue."""

    dag_id: str
    check: str
    severity: str
    message: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the finding for JSON output."""
        data = asdict(self)
        data["metadata"] = self.metadata or {}
        return data


@dataclass
class ETLScanResult:
    """Container for ETL scan results grouped by check type."""

    failed_dags: List[ETLFinding]
    slow_tasks: List[ETLFinding]
    unhealthy_workers: List[ETLFinding]
    stale_dags: List[ETLFinding]
    missing_retries: List[ETLFinding]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result for JSON output."""
        return {
            "failed_dags": [finding.to_dict() for finding in self.failed_dags],
            "slow_tasks": [finding.to_dict() for finding in self.slow_tasks],
            "unhealthy_workers": [finding.to_dict() for finding in self.unhealthy_workers],
            "stale_dags": [finding.to_dict() for finding in self.stale_dags],
            "missing_retries": [finding.to_dict() for finding in self.missing_retries],
        }

    def get_summary(self) -> Dict[str, int]:
        """Generate alert summary counts."""
        return {
            "failed_dags": len(self.failed_dags),
            "slow_tasks": len(self.slow_tasks),
            "unhealthy_workers": len(self.unhealthy_workers),
            "stale_dags": len(self.stale_dags),
            "missing_retries": len(self.missing_retries),
        }

    def all_findings(self) -> List[ETLFinding]:
        """Flatten all findings for table rendering."""
        findings: List[ETLFinding] = []
        findings.extend(self.failed_dags)
        findings.extend(self.slow_tasks)
        findings.extend(self.unhealthy_workers)
        findings.extend(self.stale_dags)
        findings.extend(self.missing_retries)
        return findings


def scan_airflow(
    airflow_url: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    api_token: Optional[str] = None,
    stale_dag_threshold_days: int = 7,
    slow_task_multiplier: float = 2.0,
    failure_window_hours: int = 24,
) -> ETLScanResult:
    """Scan Airflow instance for health and configuration issues.

    Args:
        airflow_url: Base URL of Airflow webserver (e.g., http://airflow.example.com:8080)
        username: Username for basic authentication
        password: Password for basic authentication
        api_token: API token for authentication (alternative to username/password)
        stale_dag_threshold_days: Flag DAGs not updated in this many days
        slow_task_multiplier: Flag tasks slower than baseline * this multiplier
        failure_window_hours: Look back this many hours for failed DAG runs

    Returns:
        An ETLScanResult with grouped findings.
    """
    if requests is None:
        raise MissingDependencyError(
            "requests library is not installed. "
            "Install it with `pip install requests` to enable Airflow scanning."
        )

    if not airflow_url:
        raise ValueError("airflow_url is required")

    # Normalize URL
    airflow_url = airflow_url.rstrip("/")
    if not airflow_url.startswith(("http://", "https://")):
        airflow_url = f"http://{airflow_url}"

    # Setup authentication
    auth = None
    headers = {"Content-Type": "application/json"}
    if api_token:
        headers["Authorization"] = f"Bearer {api_token}"
    elif username and password:
        from requests.auth import HTTPBasicAuth

        auth = HTTPBasicAuth(username, password)

    client = AirflowAPIClient(airflow_url, auth=auth, headers=headers)

    result = ETLScanResult(
        failed_dags=[],
        slow_tasks=[],
        unhealthy_workers=[],
        stale_dags=[],
        missing_retries=[],
    )

    try:
        # Check health
        health_status = client.check_health()
        if not health_status.get("healthy", False):
            result.unhealthy_workers.append(
                ETLFinding(
                    dag_id="system",
                    check="unhealthy_workers",
                    severity="HIGH",
                    message="Airflow instance health check failed",
                    metadata={"status": health_status},
                )
            )

        # Get all DAGs
        dags = client.list_dags()
        now = datetime.now(timezone.utc)

        for dag in dags:
            dag_id = dag.get("dag_id", "")
            if not dag_id:
                continue

            # Check for stale DAGs
            last_parsed = dag.get("last_parsed_time")
            if last_parsed:
                try:
                    parsed_time = _parse_airflow_timestamp(last_parsed)
                    if parsed_time:
                        age_days = (now - parsed_time).days
                        if age_days > stale_dag_threshold_days:
                            result.stale_dags.append(
                                ETLFinding(
                                    dag_id=dag_id,
                                    check="stale_dags",
                                    severity="MEDIUM",
                                    message=f"DAG not updated in {age_days} days",
                                    metadata={
                                        "last_parsed": last_parsed,
                                        "age_days": age_days,
                                    },
                                )
                            )
                except (ValueError, TypeError):
                    logger.debug("Could not parse last_parsed_time for DAG %s", dag_id)

            # Check for missing retry logic
            if not dag.get("has_retries", False):
                # Try to get DAG details to check retries
                dag_details = client.get_dag(dag_id)
                if dag_details:
                    default_args = dag_details.get("default_args", {})
                    tasks = dag_details.get("tasks", [])
                    has_retries = (
                        default_args.get("retries", 0) > 0
                        or any(
                            task.get("retries", 0) > 0
                            for task in tasks
                            if isinstance(task, dict)
                        )
                    )
                    if not has_retries:
                        result.missing_retries.append(
                            ETLFinding(
                                dag_id=dag_id,
                                check="missing_retries",
                                severity="LOW",
                                message="DAG or tasks missing retry logic",
                                metadata={},
                            )
                        )

            # Check for failed DAG runs
            failed_runs = client.get_failed_dag_runs(
                dag_id, hours_back=failure_window_hours
            )
            if failed_runs:
                result.failed_dags.append(
                    ETLFinding(
                        dag_id=dag_id,
                        check="failed_dags",
                        severity="HIGH",
                        message=f"{len(failed_runs)} failed DAG run(s) in past {failure_window_hours} hours",
                        metadata={
                            "failure_count": len(failed_runs),
                            "failed_runs": failed_runs[:5],  # Limit to first 5
                        },
                    )
                )

            # Check for slow tasks
            slow_tasks_data = client.get_slow_tasks(
                dag_id, multiplier=slow_task_multiplier
            )
            for task_data in slow_tasks_data:
                result.slow_tasks.append(
                    ETLFinding(
                        dag_id=dag_id,
                        check="slow_tasks",
                        severity="MEDIUM",
                        message=task_data.get("message", "Task running slower than baseline"),
                        metadata=task_data,
                    )
                )

    except requests.exceptions.RequestException as exc:
        raise ConnectionError(f"Failed to connect to Airflow API: {exc}") from exc
    except Exception as exc:
        logger.debug("Error during Airflow scan: %s", exc)
        raise AirflowModuleError(f"Airflow scan failed: {exc}") from exc

    return result


class AirflowAPIClient:
    """Client for interacting with Airflow REST API."""

    def __init__(
        self,
        base_url: str,
        auth: Optional[Any] = None,
        headers: Optional[Dict[str, str]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.headers = headers or {}
        self.session = requests.Session()
        if auth:
            self.session.auth = auth
        self.session.headers.update(self.headers)

    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make a request to the Airflow API."""
        url = f"{self.base_url}/api/v1{endpoint}"
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as exc:
            if exc.response.status_code == 401:
                raise AuthenticationError("Authentication failed") from exc
            raise
        except requests.exceptions.RequestException as exc:
            raise ConnectionError(f"API request failed: {exc}") from exc

    def check_health(self) -> Dict[str, Any]:
        """Check Airflow health status."""
        try:
            return self._request("GET", "/health")
        except Exception as exc:
            logger.debug("Health check failed: %s", exc)
            return {"healthy": False, "error": str(exc)}

    def list_dags(self) -> List[Dict[str, Any]]:
        """List all DAGs."""
        response = self._request("GET", "/dags")
        return response.get("dags", [])

    def get_dag(self, dag_id: str) -> Optional[Dict[str, Any]]:
        """Get details for a specific DAG."""
        try:
            response = self._request("GET", f"/dags/{dag_id}")
            return response
        except requests.exceptions.HTTPError:
            return None

    def get_failed_dag_runs(
        self, dag_id: str, hours_back: int = 24
    ) -> List[Dict[str, Any]]:
        """Get failed DAG runs in the past N hours."""
        try:
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(hours=hours_back)
            params = {
                "start_date_gte": start_date.isoformat(),
                "start_date_lte": end_date.isoformat(),
                "state": "failed",
                "limit": 100,
            }
            response = self._request("GET", f"/dags/{dag_id}/dagRuns", params=params)
            return response.get("dag_runs", [])
        except Exception as exc:
            logger.debug("Failed to get failed DAG runs for %s: %s", dag_id, exc)
            return []

    def get_slow_tasks(
        self, dag_id: str, multiplier: float = 2.0
    ) -> List[Dict[str, Any]]:
        """Identify tasks running slower than baseline."""
        slow_tasks: List[Dict[str, Any]] = []
        try:
            # Get recent successful task instances to calculate baseline
            end_date = datetime.now(timezone.utc)
            start_date = end_date - timedelta(days=7)  # Look back 7 days for baseline

            # Get task instances
            params = {
                "start_date_gte": start_date.isoformat(),
                "limit": 1000,
            }
            response = self._request(
                "GET", f"/dags/{dag_id}/dagRuns", params=params
            )
            dag_runs = response.get("dag_runs", [])

            # Calculate baseline durations per task
            task_baselines: Dict[str, List[float]] = {}
            for dag_run in dag_runs:
                dag_run_id = dag_run.get("dag_run_id")
                if not dag_run_id:
                    continue

                # Get task instances for this DAG run
                try:
                    task_response = self._request(
                        "GET",
                        f"/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances",
                    )
                    task_instances = task_response.get("task_instances", [])

                    for task_instance in task_instances:
                        if task_instance.get("state") != "success":
                            continue

                        task_id = task_instance.get("task_id", "")
                        duration = task_instance.get("duration")
                        if task_id and duration:
                            if task_id not in task_baselines:
                                task_baselines[task_id] = []
                            task_baselines[task_id].append(float(duration))

                except Exception:
                    continue

            # Calculate averages and find slow tasks
            task_averages = {
                task_id: sum(durations) / len(durations)
                for task_id, durations in task_baselines.items()
                if len(durations) > 0
            }

            # Check current/latest runs
            latest_runs = dag_runs[:10]  # Check last 10 runs
            for dag_run in latest_runs:
                dag_run_id = dag_run.get("dag_run_id")
                try:
                    task_response = self._request(
                        "GET",
                        f"/dags/{dag_id}/dagRuns/{dag_run_id}/taskInstances",
                    )
                    task_instances = task_response.get("task_instances", [])

                    for task_instance in task_instances:
                        task_id = task_instance.get("task_id", "")
                        duration = task_instance.get("duration")
                        state = task_instance.get("state", "")

                        if task_id in task_averages and duration:
                            baseline = task_averages[task_id]
                            if float(duration) > baseline * multiplier:
                                slow_tasks.append(
                                    {
                                        "task_id": task_id,
                                        "dag_run_id": dag_run_id,
                                        "duration": duration,
                                        "baseline": baseline,
                                        "multiplier": float(duration) / baseline,
                                        "state": state,
                                        "message": f"Task '{task_id}' running {float(duration) / baseline:.1f}x slower than baseline",
                                    }
                                )

                except Exception:
                    continue

        except Exception as exc:
            logger.debug("Failed to analyze slow tasks for %s: %s", dag_id, exc)

        return slow_tasks


def _parse_airflow_timestamp(timestamp_str: str) -> Optional[datetime]:
    """Parse Airflow timestamp string to datetime."""
    if not timestamp_str:
        return None

    # Try common formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(timestamp_str, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    # Try ISO format
    try:
        dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        return dt
    except (ValueError, AttributeError):
        pass

    return None


