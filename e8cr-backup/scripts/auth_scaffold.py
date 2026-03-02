#!/usr/bin/env python3
"""Auth scaffold for backup platform providers (Veeam, Azure Backup).

Environment variable configuration for real tenant mode.
TODO: Replace sample mode with actual API calls once credentials are available.
"""

import os
import json
from dataclasses import dataclass


@dataclass
class VeeamAuth:
    """Veeam Backup & Replication connection."""
    base_url: str  # e.g., https://veeam-server:9398
    username: str
    password: str
    verify_ssl: bool = True

    @classmethod
    def from_env(cls):
        return cls(
            base_url=os.getenv("VEEAM_BASE_URL", ""),
            username=os.getenv("VEEAM_USERNAME", ""),
            password=os.getenv("VEEAM_PASSWORD", ""),
            verify_ssl=os.getenv("VEEAM_VERIFY_SSL", "true").lower() == "true",
        )

    def is_configured(self):
        return bool(self.base_url and self.username and self.password)


@dataclass
class AzureBackupAuth:
    """Azure Backup via Azure Resource Manager API."""
    subscription_id: str
    vault_name: str
    resource_group: str
    tenant_id: str
    client_id: str
    client_secret: str

    @classmethod
    def from_env(cls):
        return cls(
            subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID", ""),
            vault_name=os.getenv("AZURE_VAULT_NAME", ""),
            resource_group=os.getenv("AZURE_RESOURCE_GROUP", ""),
            tenant_id=os.getenv("AZURE_TENANT_ID", ""),
            client_id=os.getenv("AZURE_CLIENT_ID", ""),
            client_secret=os.getenv("AZURE_CLIENT_SECRET", ""),
        )

    def is_configured(self):
        return all([
            self.subscription_id,
            self.vault_name,
            self.resource_group,
            self.tenant_id,
            self.client_id,
            self.client_secret,
        ])


def print_env_template():
    """Print a template for .env or shell export."""
    template = """
# Veeam Backup & Replication
export VEEAM_BASE_URL="https://veeam-server:9398"
export VEEAM_USERNAME="backup-admin@domain.com"
export VEEAM_PASSWORD="<secure-password>"
export VEEAM_VERIFY_SSL="true"

# Azure Backup
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
export AZURE_VAULT_NAME="<vault-name>"
export AZURE_RESOURCE_GROUP="<resource-group>"
export AZURE_TENANT_ID="<tenant-id>"
export AZURE_CLIENT_ID="<app-registration-client-id>"
export AZURE_CLIENT_SECRET="<app-registration-client-secret>"
"""
    print(template)


if __name__ == "__main__":
    veeam = VeeamAuth.from_env()
    azure = AzureBackupAuth.from_env()

    print(json.dumps({
        "veeam_configured": veeam.is_configured(),
        "azure_configured": azure.is_configured(),
    }, indent=2))

    if not veeam.is_configured() and not azure.is_configured():
        print("\n⚠️ No backup providers configured. Set environment variables:")
        print_env_template()
