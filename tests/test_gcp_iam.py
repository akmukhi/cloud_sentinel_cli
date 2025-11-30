"""Tests for GCP IAM scanning module."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, Mock, patch

import pytest

from sentinel.modules import gcp_iam


class TestIAMScanning:
    """Test suite for IAM scanning functionality."""

    def test_scan_iam_missing_project_id(self):
        """Test that scan_iam raises ValueError for missing project_id."""
        with pytest.raises(ValueError, match="project_id is required"):
            gcp_iam.scan_iam("")

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    def test_scan_iam_missing_dependency(self, mock_rm):
        """Test that scan_iam raises MissingDependencyError when dependency is missing."""
        mock_rm.ProjectsClient = None
        with pytest.raises(gcp_iam.MissingDependencyError):
            gcp_iam.scan_iam("test-project")

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    @patch("sentinel.modules.gcp_iam.admin_v1")
    def test_scan_iam_no_admin_roles(self, mock_admin, mock_rm):
        """Test scanning with no overly permissive roles."""
        # Mock project client
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client

        # Mock IAM policy with no admin roles
        mock_policy = MagicMock()
        mock_binding = MagicMock()
        mock_binding.role = "roles/viewer"
        mock_binding.members = ["user:test@example.com"]
        mock_policy.bindings = [mock_binding]
        mock_client.get_iam_policy.return_value = mock_policy

        # Mock service accounts (empty)
        mock_iam_client = MagicMock()
        mock_admin.IAMClient.return_value = mock_iam_client
        mock_iam_client.list_service_accounts.return_value = []

        result = gcp_iam.scan_iam("test-project")

        assert len(result.risks) == 0
        assert len(result.passed) >= 1
        assert any("no_admin_roles" in check.get("check", "") for check in result.passed)

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    @patch("sentinel.modules.gcp_iam.admin_v1")
    def test_scan_iam_detects_admin_roles(self, mock_admin, mock_rm):
        """Test detection of overly permissive admin roles."""
        # Mock project client
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client

        # Mock IAM policy with admin role (roles ending with Admin)
        mock_policy = MagicMock()
        mock_binding = MagicMock()
        mock_binding.role = "roles/owner"  # owner is a special case, but let's test with a real Admin role
        mock_binding.members = ["user:admin@example.com"]
        mock_policy.bindings = [mock_binding]
        mock_client.get_iam_policy.return_value = mock_policy

        # Add a binding with an Admin role
        mock_admin_binding = MagicMock()
        mock_admin_binding.role = "roles/resourcemanager.projectIamAdmin"
        mock_admin_binding.members = ["user:admin@example.com"]
        mock_policy.bindings.append(mock_admin_binding)

        # Mock service accounts (empty)
        mock_iam_client = MagicMock()
        mock_admin.IAMClient.return_value = mock_iam_client
        mock_iam_client.list_service_accounts.return_value = []

        result = gcp_iam.scan_iam("test-project")

        # Should detect Admin role
        admin_risks = [r for r in result.risks if "permissive" in r.issue.lower() or "Admin" in r.issue]
        assert len(admin_risks) > 0

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    @patch("sentinel.modules.gcp_iam.admin_v1")
    def test_scan_iam_detects_public_members(self, mock_admin, mock_rm):
        """Test detection of public member bindings."""
        # Mock project client
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client

        # Mock IAM policy with public member
        mock_policy = MagicMock()
        mock_binding = MagicMock()
        mock_binding.role = "roles/storage.objectViewer"
        mock_binding.members = ["allUsers"]
        mock_policy.bindings = [mock_binding]
        mock_client.get_iam_policy.return_value = mock_policy

        # Mock service accounts (empty)
        mock_iam_client = MagicMock()
        mock_admin.IAMClient.return_value = mock_iam_client
        mock_iam_client.list_service_accounts.return_value = []

        result = gcp_iam.scan_iam("test-project")

        # Should detect public access
        public_risks = [r for r in result.risks if "public" in r.issue.lower() or r.severity == "critical"]
        assert len(public_risks) > 0
        assert any("allUsers" in str(r.metadata) for r in public_risks)

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    @patch("sentinel.modules.gcp_iam.admin_v1")
    def test_scan_iam_detects_old_service_account_keys(self, mock_admin, mock_rm):
        """Test detection of old service account keys."""
        # Mock project client
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client

        # Mock IAM policy (no issues)
        mock_policy = MagicMock()
        mock_policy.bindings = []
        mock_client.get_iam_policy.return_value = mock_policy

        # Mock service account with old key
        mock_iam_client = MagicMock()
        mock_admin.IAMClient.return_value = mock_iam_client

        mock_sa = MagicMock()
        mock_sa.name = "projects/test/serviceAccounts/test@test.iam.gserviceaccount.com"
        mock_sa.email = "test@test.iam.gserviceaccount.com"
        mock_iam_client.list_service_accounts.return_value = [mock_sa]

        # Mock old key
        old_date = datetime.now(timezone.utc) - timedelta(days=100)
        mock_key = MagicMock()
        mock_key.key_type = mock_admin.ServiceAccountKeyType.USER_MANAGED
        mock_key.name = "projects/test/serviceAccounts/test@test.iam.gserviceaccount.com/keys/key1"
        mock_key.valid_after_time = old_date
        mock_iam_client.list_service_account_keys.return_value = [mock_key]

        result = gcp_iam.scan_iam("test-project", key_age_threshold_days=90)

        # Should detect old key
        old_key_risks = [r for r in result.risks if "key" in r.issue.lower() and "older" in r.issue.lower()]
        assert len(old_key_risks) > 0

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    @patch("sentinel.modules.gcp_iam.admin_v1")
    def test_scan_iam_passes_new_service_account_keys(self, mock_admin, mock_rm):
        """Test that new service account keys pass the check."""
        # Mock project client
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client

        # Mock IAM policy (no issues)
        mock_policy = MagicMock()
        mock_policy.bindings = []
        mock_client.get_iam_policy.return_value = mock_policy

        # Mock service account with new key
        mock_iam_client = MagicMock()
        mock_admin.IAMClient.return_value = mock_iam_client

        mock_sa = MagicMock()
        mock_sa.name = "projects/test/serviceAccounts/test@test.iam.gserviceaccount.com"
        mock_sa.email = "test@test.iam.gserviceaccount.com"
        mock_iam_client.list_service_accounts.return_value = [mock_sa]

        # Mock new key
        new_date = datetime.now(timezone.utc) - timedelta(days=30)
        mock_key = MagicMock()
        mock_key.key_type = mock_admin.ServiceAccountKeyType.USER_MANAGED
        mock_key.name = "projects/test/serviceAccounts/test@test.iam.gserviceaccount.com/keys/key1"
        mock_key.valid_after_time = new_date
        mock_iam_client.list_service_account_keys.return_value = [mock_key]

        result = gcp_iam.scan_iam("test-project", key_age_threshold_days=90)

        # Should not detect old key
        old_key_risks = [r for r in result.risks if "key" in r.issue.lower() and "older" in r.issue.lower()]
        assert len(old_key_risks) == 0

    def test_iam_risk_to_dict(self):
        """Test IAMRisk serialization."""
        risk = gcp_iam.IAMRisk(
            resource="projects/test",
            issue="Test issue",
            severity="high",
            metadata={"key": "value"},
        )
        result = risk.to_dict()
        assert result["resource"] == "projects/test"
        assert result["issue"] == "Test issue"
        assert result["severity"] == "high"
        assert result["metadata"]["key"] == "value"

    def test_iam_result_to_dict(self):
        """Test IAMResult serialization."""
        risk = gcp_iam.IAMRisk(
            resource="projects/test",
            issue="Test issue",
            severity="high",
            metadata={},
        )
        result = gcp_iam.IAMResult(risks=[risk], passed=[{"check": "test", "message": "OK"}])
        output = result.to_dict()
        assert len(output["risks"]) == 1
        assert len(output["passed"]) == 1
        assert output["risks"][0]["issue"] == "Test issue"

    @patch("sentinel.modules.gcp_iam.resourcemanager")
    def test_scan_iam_credentials_error(self, mock_rm):
        """Test handling of credentials errors."""
        mock_client = MagicMock()
        mock_rm.ProjectsClient.return_value = mock_client
        mock_client.get_iam_policy.side_effect = gcp_iam.DefaultCredentialsError("No credentials")

        with pytest.raises(gcp_iam.CredentialsError):
            gcp_iam.scan_iam("test-project")

