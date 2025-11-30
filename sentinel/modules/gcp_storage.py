"""GCP Storage scanning helpers for the Cloud Sentinel CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import logging
from typing import Any, Dict, Iterable, List, Sequence

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from google.cloud import storage  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    storage = None  # type: ignore

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


class StorageModuleError(RuntimeError):
    """Base exception for storage scanning errors."""


class MissingDependencyError(StorageModuleError):
    """Raised when google-cloud-storage is not installed."""


class CredentialsError(StorageModuleError):
    """Raised when ADC or service-account credentials are missing/invalid."""


@dataclass
class Finding:
    """Represents a single issue detected during scanning."""

    resource: str
    issue: str
    severity: str
    metadata: Dict[str, Any]
    category: str = "gcp_storage"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the finding for JSON output."""
        data = asdict(self)
        data["metadata"] = self.metadata or {}
        return data


@dataclass
class StorageResult:
    """Container for Storage scan results with public buckets and encryption issues."""

    public_buckets: List[Dict[str, Any]]
    encryption_issues: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result for JSON output."""
        return {
            "public_buckets": self.public_buckets,
            "encryption_issues": self.encryption_issues,
        }


def scan_buckets(project_id: str, include_public: bool = True) -> List[Finding]:
    """Run a best-effort scan across all buckets in the provided project.

    Args:
        project_id: Google Cloud project identifier.
        include_public: When False, skips the more expensive public ACL check.

    Returns:
        A list of Finding objects describing detected misconfigurations.
    """

    if not project_id:
        raise ValueError("project_id is required")

    client = _build_storage_client(project_id)
    findings: List[Finding] = []

    try:
        bucket_iter = client.list_buckets(project=project_id)
    except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
        raise StorageModuleError(f"Failed to list buckets: {exc}") from exc

    for bucket in bucket_iter:
        try:
            findings.extend(_evaluate_bucket(bucket, include_public))
        except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
            logger.debug("Skipping bucket %s due to API error: %s", bucket.name, exc)
            continue

    return findings


def scan_buckets_structured(
    project_id: str, include_public: bool = True
) -> StorageResult:
    """Run a structured scan across all buckets in the provided project.

    Args:
        project_id: Google Cloud project identifier.
        include_public: When False, skips the more expensive public ACL check.

    Returns:
        A StorageResult object containing public_buckets and encryption_issues.
    """
    if not project_id:
        raise ValueError("project_id is required")

    client = _build_storage_client(project_id)
    public_buckets: List[Dict[str, Any]] = []
    encryption_issues: List[Dict[str, Any]] = []

    try:
        bucket_iter = client.list_buckets(project=project_id)
    except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
        raise StorageModuleError(f"Failed to list buckets: {exc}") from exc

    for bucket in bucket_iter:
        try:
            metadata = _bucket_metadata(bucket)

            # Check for public access
            if include_public and _bucket_is_public(bucket):
                public_buckets.append(metadata)

            # Check for encryption
            encryption = getattr(bucket, "encryption", None)
            default_kms_key = getattr(bucket, "default_kms_key_name", None)
            if not encryption and not default_kms_key:
                encryption_issues.append(
                    {
                        **metadata,
                        "issue": "Bucket encryption not configured",
                        "severity": "high",
                    }
                )
        except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
            logger.debug("Skipping bucket %s due to API error: %s", bucket.name, exc)
            continue

    return StorageResult(
        public_buckets=public_buckets, encryption_issues=encryption_issues
    )


def _build_storage_client(project_id: str):
    if storage is None:
        raise MissingDependencyError(
            "google-cloud-storage is not installed. "
            "Install it with `pip install google-cloud-storage` to enable scanning."
        )

    try:
        return storage.Client(project=project_id)
    except DefaultCredentialsError as exc:  # pragma: no cover - ADC specific
        raise CredentialsError(
            "Google Cloud credentials were not found. "
            "Run `gcloud auth application-default login` or set "
            "GOOGLE_APPLICATION_CREDENTIALS."
        ) from exc


def _evaluate_bucket(bucket: "storage.Bucket", include_public: bool) -> List[Finding]:
    findings: List[Finding] = []
    metadata = _bucket_metadata(bucket)

    if include_public and _bucket_is_public(bucket):
        findings.append(
            Finding(
                resource=metadata["resource"],
                issue="Bucket grants access to allUsers/allAuthenticatedUsers",
                severity="high",
                metadata=metadata,
            )
        )

    if not metadata.get("uniform_bucket_level_access", False):
        findings.append(
            Finding(
                resource=metadata["resource"],
                issue="Uniform bucket-level access disabled",
                severity="medium",
                metadata=metadata,
            )
        )

    # Check for encryption
    encryption = getattr(bucket, "encryption", None)
    default_kms_key = getattr(bucket, "default_kms_key_name", None)
    if not encryption and not default_kms_key:
        findings.append(
            Finding(
                resource=metadata["resource"],
                issue="Bucket encryption not configured",
                severity="high",
                metadata=metadata,
            )
        )

    if not metadata.get("versioning_enabled", False):
        findings.append(
            Finding(
                resource=metadata["resource"],
                issue="Object versioning disabled",
                severity="low",
                metadata=metadata,
            )
        )

    return findings


def _bucket_metadata(bucket: "storage.Bucket") -> Dict[str, Any]:
    iam_config = getattr(bucket, "iam_configuration", {}) or {}
    uniform_cfg = iam_config.get("uniformBucketLevelAccess", {}) or {}
    metadata = {
        "resource": f"projects/{getattr(bucket, 'project_number', 'unknown')}/buckets/{bucket.name}",
        "bucket": bucket.name,
        "location": getattr(bucket, "location", "unspecified"),
        "storage_class": getattr(bucket, "storage_class", "unspecified"),
        "public_access_prevention": iam_config.get("publicAccessPrevention", "unspecified"),
        "uniform_bucket_level_access": bool(uniform_cfg.get("enabled", False)),
        "versioning_enabled": bool(getattr(bucket, "versioning_enabled", False)),
    }
    return metadata


def _bucket_is_public(bucket: "storage.Bucket") -> bool:
    try:
        policy = bucket.get_iam_policy(requested_policy_version=3)
    except gcp_exceptions.Forbidden:  # pragma: no cover - permission
        logger.debug("Forbidden when reading IAM policy for bucket %s", bucket.name)
        return False
    except gcp_exceptions.GoogleAPIError:  # pragma: no cover - network
        logger.debug("Unable to read IAM policy for bucket %s", bucket.name)
        return False

    bindings = getattr(policy, "bindings", None)
    if bindings is None:
        bindings = policy.get("bindings", [])  # type: ignore[assignment]

    for binding in bindings:
        members: Sequence[str] = binding.get("members", [])
        if _members_include_public(members):
            return True
    return False


def _members_include_public(members: Iterable[str]) -> bool:
    for member in members:
        if member in {"allUsers", "allAuthenticatedUsers"}:
            return True
    return False


def serialize_findings(findings: Iterable[Finding]) -> str:
    """Render findings as a JSON string."""

    return json.dumps([finding.to_dict() for finding in findings], indent=2)
