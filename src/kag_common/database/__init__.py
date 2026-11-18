"""Shared database helpers for the KAG fleet."""

from kag_common.database.audit import (
    AuditWriteError,
    PhiAccessMixin,
    hash_query,
    record_phi_access,
)
from kag_common.database.rls import (
    bind_session_tenant,
    downgrade_statements,
    register_rls_ddl,
    register_tenant_guc,
    register_tenant_guc_sync,
    tenant_rls_mode,
    tenant_table_names,
    upgrade_statements,
)

__all__ = [
    "AuditWriteError",
    "PhiAccessMixin",
    "bind_session_tenant",
    "downgrade_statements",
    "hash_query",
    "record_phi_access",
    "register_rls_ddl",
    "register_tenant_guc",
    "register_tenant_guc_sync",
    "tenant_rls_mode",
    "tenant_table_names",
    "upgrade_statements",
]
