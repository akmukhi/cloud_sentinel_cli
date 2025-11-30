"""GCP IAM scanning helpers for the Cloud Sentinel CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Sequence

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from google.cloud import resourcemanager  # type: ignore
    from google.iam import admin_v1  # type: ignore
    from google.iam.v1 import iam_policy_pb2  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    resourcemanager = None  # type: ignore
    admin_v1 = None  # type: ignore
    iam_policy_pb2 = None  # type: ignore

try:  # pragma: no cover - optional dependency
    from google.auth.exceptions import DefaultCredentialsError  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    class DefaultCredentialsError(Exception):
        """Fallback exception used when google-auth is unavailable."""

try:  # pragma: no cover - optional dependency
    from google.api_core import exceptions as gcp_exceptions  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    class _FallbackError(Exception):
        """Fallback for Google API exceptions when the SDK is missing."""

    class gcp_exceptions:  # type: ignore
        GoogleAPIError = _FallbackError
        Forbidden = _FallbackError
        NotFound = _FallbackError


class IAMModuleError(RuntimeError):
    """Base exception for IAM scanning errors."""


class MissingDependencyError(IAMModuleError):
    """Raised when google-cloud-resource-manager or google-cloud-iam is not installed."""


class CredentialsError(IAMModuleError):
    """Raised when ADC or service-account credentials are missing/invalid."""


@dataclass
class IAMRisk:
    """Represents a single IAM risk detected during scanning."""

    resource: str
    issue: str
    severity: str
    metadata: Dict[str, Any]
    category: str = "gcp_iam"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the risk for JSON output."""
        data = asdict(self)
        data["metadata"] = self.metadata or {}
        return data


@dataclass
class IAMResult:
    """Container for IAM scan results with risks and passed checks."""

    risks: List[IAMRisk]
    passed: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result for JSON output."""
        return {
            "risks": [risk.to_dict() for risk in self.risks],
            "passed": self.passed,
        }


def scan_iam(project_id: str, key_age_threshold_days: int = 90) -> IAMResult:
    """Run IAM misconfiguration checks for the provided project.

    Args:
        project_id: Google Cloud project identifier.
        key_age_threshold_days: Threshold in days for detecting old service account keys.

    Returns:
        An IAMResult object containing risks and passed checks.
    """
    if not project_id:
        raise ValueError("project_id is required")

    risks: List[IAMRisk] = []
    passed: List[Dict[str, Any]] = []

    # Check project-level IAM policy
    try:
        project_risks, project_passed = _check_project_iam_policy(
            project_id, key_age_threshold_days
        )
        risks.extend(project_risks)
        passed.extend(project_passed)
    except IAMModuleError:
        raise
    except Exception as exc:  # pragma: no cover - network
        logger.debug("Error scanning project IAM: %s", exc)
        raise IAMModuleError(f"Failed to scan IAM: {exc}") from exc

    return IAMResult(risks=risks, passed=passed)


def _check_project_iam_policy(
    project_id: str, key_age_threshold_days: int
) -> tuple[List[IAMRisk], List[Dict[str, Any]]]:
    """Check project-level IAM policy for misconfigurations."""
    risks: List[IAMRisk] = []
    passed: List[Dict[str, Any]] = []

    if resourcemanager is None:
        raise MissingDependencyError(
            "google-cloud-resource-manager is not installed. "
            "Install it with `pip install google-cloud-resource-manager` to enable IAM scanning."
        )

    try:
        client = resourcemanager.ProjectsClient()
        project_path = f"projects/{project_id}"
        policy = client.get_iam_policy(
            resource=project_path,
            request={"options": {"requested_policy_version": 3}},
        )
    except DefaultCredentialsError as exc:  # pragma: no cover - ADC specific
        raise CredentialsError(
            "Google Cloud credentials were not found. "
            "Run `gcloud auth application-default login` or set "
            "GOOGLE_APPLICATION_CREDENTIALS."
        ) from exc
    except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
        raise IAMModuleError(f"Failed to get IAM policy: {exc}") from exc

    bindings = getattr(policy, "bindings", []) or []

    # Check for overly permissive roles
    admin_roles_found = []
    public_members_found = []
    for binding in bindings:
        role = binding.role if hasattr(binding, "role") else binding.get("role", "")
        members = (
            list(binding.members)
            if hasattr(binding, "members")
            else binding.get("members", [])
        )

        # Check for *Admin roles
        if role.endswith("Admin") and role.startswith("roles/"):
            admin_roles_found.append({"role": role, "members": members})
            risks.append(
                IAMRisk(
                    resource=f"projects/{project_id}",
                    issue=f"Overly permissive role binding: {role}",
                    severity="high",
                    metadata={"role": role, "members": members},
                )
            )

        # Check for public members
        public_members = [
            m for m in members if m in {"allUsers", "allAuthenticatedUsers"}
        ]
        if public_members:
            public_members_found.append({"role": role, "members": public_members})
            risks.append(
                IAMRisk(
                    resource=f"projects/{project_id}",
                    issue=f"Public access granted via role: {role}",
                    severity="critical",
                    metadata={"role": role, "public_members": public_members},
                )
            )

    if not admin_roles_found:
        passed.append(
            {
                "check": "no_admin_roles",
                "resource": f"projects/{project_id}",
                "message": "No overly permissive Admin roles found",
            }
        )

    if not public_members_found:
        passed.append(
            {
                "check": "no_public_members",
                "resource": f"projects/{project_id}",
                "message": "No public member bindings found",
            }
        )

    # Check service account keys
    try:
        sa_risks, sa_passed = _check_service_account_keys(
            project_id, key_age_threshold_days
        )
        risks.extend(sa_risks)
        passed.extend(sa_passed)
    except Exception as exc:  # pragma: no cover - network
        logger.debug("Error checking service account keys: %s", exc)
        # Don't fail the entire scan if SA key check fails

    return risks, passed


def _check_service_account_keys(
    project_id: str, key_age_threshold_days: int
) -> tuple[List[IAMRisk], List[Dict[str, Any]]]:
    """Check service account keys for age violations."""
    risks: List[IAMRisk] = []
    passed: List[Dict[str, Any]] = []

    if admin_v1 is None:
        logger.debug("google-cloud-iam not available, skipping service account key checks")
        return risks, passed

    try:
        client = admin_v1.IAMClient()
        parent = f"projects/{project_id}"
        # list_service_accounts expects a request object or parent string
        request = {"name": parent}
        service_accounts = client.list_service_accounts(request=request)
    except DefaultCredentialsError:  # pragma: no cover - ADC specific
        logger.debug("Credentials error when listing service accounts")
        return risks, passed
    except gcp_exceptions.GoogleAPIError:  # pragma: no cover - network
        logger.debug("API error when listing service accounts")
        return risks, passed

    threshold_date = datetime.now(timezone.utc).replace(
        microsecond=0
    ) - timedelta(days=key_age_threshold_days)

    old_keys_found = []
    for sa in service_accounts:
        sa_name = sa.name
        sa_email = sa.email

        try:
            keys = client.list_service_account_keys(name=f"{sa_name}/keys")
        except gcp_exceptions.GoogleAPIError:  # pragma: no cover - network
            logger.debug("Error listing keys for service account %s", sa_email)
            continue

        for key in keys:
            if key.key_type != admin_v1.ServiceAccountKeyType.USER_MANAGED:
                continue

            # Check key creation time
            if hasattr(key, "valid_after_time"):
                created_time = key.valid_after_time
            elif hasattr(key, "valid_after"):
                created_time = key.valid_after
            else:
                continue

            if isinstance(created_time, str):
                # Parse ISO format string
                try:
                    created_time = datetime.fromisoformat(
                        created_time.replace("Z", "+00:00")
                    )
                except (ValueError, AttributeError):
                    continue

            if created_time < threshold_date:
                age_days = (datetime.now(timezone.utc) - created_time).days
                old_keys_found.append(
                    {
                        "service_account": sa_email,
                        "key_name": key.name,
                        "age_days": age_days,
                    }
                )
                risks.append(
                    IAMRisk(
                        resource=sa_email,
                        issue=f"Service account key older than {key_age_threshold_days} days",
                        severity="medium",
                        metadata={
                            "service_account": sa_email,
                            "key_name": key.name,
                            "age_days": age_days,
                            "created_time": created_time.isoformat(),
                        },
                    )
                )

    if not old_keys_found:
        passed.append(
            {
                "check": "service_account_keys_age",
                "resource": f"projects/{project_id}",
                "message": f"All service account keys are newer than {key_age_threshold_days} days",
            }
        )

    return risks, passed

