"""Cloud Run scanning helpers for the Cloud Sentinel CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import logging
from typing import Any, Dict, Iterable, List, Sequence

logger = logging.getLogger(__name__)

try:  # pragma: no cover - optional dependency
    from google.cloud import run_v2  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    run_v2 = None  # type: ignore

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


class CloudRunModuleError(RuntimeError):
    """Base exception for Cloud Run scanning errors."""


class MissingDependencyError(CloudRunModuleError):
    """Raised when google-cloud-run is not installed."""


class CredentialsError(CloudRunModuleError):
    """Raised when ADC or service-account credentials are missing/invalid."""


@dataclass
class ServiceFinding:
    """Represents a single Cloud Run service issue."""

    service: str
    check: str
    severity: str
    message: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the finding for JSON output."""
        data = asdict(self)
        data["metadata"] = _sanitize_metadata(self.metadata)
        return data


@dataclass
class ServiceScanResult:
    """Container for Cloud Run scan results grouped by check."""

    public_access: List[ServiceFinding]
    outdated_images: List[ServiceFinding]
    resource_limits: List[ServiceFinding]
    stale_revisions: List[ServiceFinding]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result for JSON output."""
        return {
            "public_access": [finding.to_dict() for finding in self.public_access],
            "outdated_images": [finding.to_dict() for finding in self.outdated_images],
            "resource_limits": [finding.to_dict() for finding in self.resource_limits],
            "stale_revisions": [finding.to_dict() for finding in self.stale_revisions],
        }

    def all_findings(self) -> List[ServiceFinding]:
        """Flatten all findings for table rendering."""
        findings: List[ServiceFinding] = []
        findings.extend(self.public_access)
        findings.extend(self.outdated_images)
        findings.extend(self.resource_limits)
        findings.extend(self.stale_revisions)
        return findings


def scan_services(
    project_id: str,
    region: str | None = None,
    include_public: bool = True,
    max_revision_age_days: int = 30,
    max_revisions: int = 5,
    image_age_days: int = 90,
) -> ServiceScanResult:
    """Scan Cloud Run services for misconfigurations.

    Args:
        project_id: Google Cloud project identifier.
        region: Cloud Run region (defaults to all regions '-').
        include_public: When False, skips IAM policy checks for public access.
        max_revision_age_days: Flag revisions older than this threshold.
        max_revisions: Flag when retained revisions exceed this count.
        image_age_days: Threshold for container image freshness.

    Returns:
        A ServiceScanResult with grouped findings.
    """

    if not project_id:
        raise ValueError("project_id is required")

    if run_v2 is None:
        raise MissingDependencyError(
            "google-cloud-run is not installed. "
            "Install it with `pip install google-cloud-run` to enable Cloud Run scanning."
        )

    region = region or "-"
    parent = f"projects/{project_id}/locations/{region}"

    try:
        services_client = run_v2.ServicesClient()
        revisions_client = run_v2.RevisionsClient()
    except DefaultCredentialsError as exc:  # pragma: no cover - ADC specific
        raise CredentialsError(
            "Google Cloud credentials were not found. "
            "Run `gcloud auth application-default login` or set "
            "GOOGLE_APPLICATION_CREDENTIALS."
        ) from exc

    result = ServiceScanResult(
        public_access=[],
        outdated_images=[],
        resource_limits=[],
        stale_revisions=[],
    )

    try:
        services_iter = services_client.list_services(parent=parent)
    except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
        raise CloudRunModuleError(f"Failed to list Cloud Run services: {exc}") from exc

    for service in services_iter:
        service_name = service.name
        service_metadata = _service_metadata(service, region)

        if include_public and _service_is_public(services_client, service_name):
            result.public_access.append(
                ServiceFinding(
                    service=service_name,
                    check="public_access",
                    severity="HIGH",
                    message="Service allows unauthenticated (allUsers/allAuthenticatedUsers) access",
                    metadata=service_metadata,
                )
            )

        # Inspect revisions for image age, resource limits, and stale revisions.
        try:
            revisions = list(
                revisions_client.list_revisions(parent=service_name, filter="")
            )
        except gcp_exceptions.GoogleAPIError as exc:  # pragma: no cover - network
            logger.debug(
                "Skipping revision checks for %s due to API error: %s",
                service_name,
                exc,
            )
            continue

        now = datetime.now(timezone.utc)

        for revision in revisions:
            metadata = _revision_metadata(revision, service_metadata)
            created_at = metadata.get("created_at")

            # Outdated or latest-tagged images
            for image in _revision_images(revision):
                if _is_latest_tag(image):
                    result.outdated_images.append(
                        ServiceFinding(
                            service=service_name,
                            check="outdated_images",
                            severity="MEDIUM",
                            message=f"Container image '{image}' uses the 'latest' tag",
                            metadata={**metadata, "image": image},
                        )
                    )
                    continue

                if created_at and (now - created_at).days > image_age_days:
                    result.outdated_images.append(
                        ServiceFinding(
                            service=service_name,
                            check="outdated_images",
                            severity="MEDIUM",
                            message=(
                                f"Container image '{image}' is older than {image_age_days} days"
                            ),
                            metadata={
                                **metadata,
                                "image": image,
                                "age_days": (now - created_at).days,
                            },
                        )
                    )

            # Missing CPU or memory limits
            missing_limits = _containers_missing_limits(revision)
            if missing_limits:
                result.resource_limits.append(
                    ServiceFinding(
                        service=service_name,
                        check="resource_limits",
                        severity="MEDIUM",
                        message="Container resources missing CPU and/or memory limits",
                        metadata={**metadata, "containers": missing_limits},
                    )
                )

        stale = _stale_revisions(revisions, max_revision_age_days, max_revisions)
        for rev in stale:
            result.stale_revisions.append(
                ServiceFinding(
                    service=service_name,
                    check="stale_revisions",
                    severity="LOW",
                    message=rev["message"],
                    metadata={**service_metadata, **rev},
                )
            )

    return result


def _service_is_public(
    services_client: "run_v2.ServicesClient", service_name: str
) -> bool:
    try:
        policy = services_client.get_iam_policy(name=service_name)
    except gcp_exceptions.Forbidden:  # pragma: no cover - permission
        logger.debug("Forbidden when reading IAM policy for %s", service_name)
        return False
    except gcp_exceptions.GoogleAPIError:  # pragma: no cover - network
        logger.debug("Unable to read IAM policy for %s", service_name)
        return False

    bindings = getattr(policy, "bindings", []) or []
    for binding in bindings:
        members = (
            list(binding.members)
            if hasattr(binding, "members")
            else binding.get("members", [])
        )
        if _members_include_public(members):
            return True
    return False


def _members_include_public(members: Iterable[str]) -> bool:
    for member in members:
        if member in {"allUsers", "allAuthenticatedUsers"}:
            return True
    return False


def _service_metadata(service, region: str) -> Dict[str, Any]:
    return {
        "service": service.name,
        "region": region,
        "ingress": getattr(service, "ingress", "INGRESS_UNSPECIFIED"),
        "latest_ready_revision": getattr(service, "latest_ready_revision", None),
    }


def _revision_metadata(revision, base_metadata: Dict[str, Any]) -> Dict[str, Any]:
    created_at = _timestamp_to_datetime(getattr(revision, "create_time", None))
    metadata = {
        **base_metadata,
        "revision": getattr(revision, "name", "unknown"),
        "created_at": created_at,
        "traffic": getattr(revision, "traffic", None),
    }
    return metadata


def _sanitize_metadata(metadata: Dict[str, Any] | None) -> Dict[str, Any]:
    if not metadata:
        return {}
    sanitized: Dict[str, Any] = {}
    for key, value in metadata.items():
        if isinstance(value, datetime):
            sanitized[key] = value.isoformat()
        else:
            sanitized[key] = value
    return sanitized


def _timestamp_to_datetime(timestamp_obj) -> datetime | None:
    if timestamp_obj is None:
        return None
    if isinstance(timestamp_obj, datetime):
        return timestamp_obj if timestamp_obj.tzinfo else timestamp_obj.replace(tzinfo=timezone.utc)
    seconds = getattr(timestamp_obj, "seconds", None)
    nanos = getattr(timestamp_obj, "nanos", 0)
    if seconds is None:
        return None
    return datetime.fromtimestamp(seconds + nanos / 1_000_000_000, tz=timezone.utc)


def _revision_images(revision) -> List[str]:
    images: List[str] = []
    containers = getattr(revision, "containers", []) or []
    for container in containers:
        image = getattr(container, "image", None)
        if image:
            images.append(image)
    return images


def _is_latest_tag(image: str) -> bool:
    if ":" not in image:
        return False
    _, tag = image.rsplit(":", 1)
    return tag.lower() == "latest"


def _containers_missing_limits(revision) -> List[str]:
    containers = getattr(revision, "containers", []) or []
    missing: List[str] = []
    for container in containers:
        name = getattr(container, "name", "container")
        resources = getattr(container, "resources", None)
        limits = getattr(resources, "limits", {}) if resources else {}
        has_cpu = any(key.lower() == "cpu" for key in limits.keys())
        has_memory = any(key.lower() == "memory" for key in limits.keys())
        if not (has_cpu and has_memory):
            missing.append(name)
    return missing


def _stale_revisions(
    revisions: Sequence[Any], max_age_days: int, max_revisions: int
) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    stale: List[Dict[str, Any]] = []

    sorted_revs = sorted(
        revisions,
        key=lambda rev: _timestamp_to_datetime(getattr(rev, "create_time", None))
        or datetime.min.replace(tzinfo=timezone.utc),
        reverse=True,
    )

    for revision in revisions:
        created_at = _timestamp_to_datetime(getattr(revision, "create_time", None))
        if created_at is None:
            continue
        age_days = (now - created_at).days
        if age_days > max_age_days:
            stale.append(
                {
                    "revision": getattr(revision, "name", "unknown"),
                    "age_days": age_days,
                    "message": f"Revision older than {max_age_days} days",
                }
            )

    if len(sorted_revs) > max_revisions:
        for revision in sorted_revs[max_revisions:]:
            created_at = _timestamp_to_datetime(getattr(revision, "create_time", None))
            stale.append(
                {
                    "revision": getattr(revision, "name", "unknown"),
                    "age_days": (now - created_at).days if created_at else None,
                    "message": (
                        f"Exceeded max retained revisions ({max_revisions})"
                    ),
                }
            )

    return stale
