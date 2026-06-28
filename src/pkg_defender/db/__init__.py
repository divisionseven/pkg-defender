"""Database layer."""

from pkg_defender.db.schema import CURRENT_SCHEMA_VERSION as CURRENT_SCHEMA_VERSION
from pkg_defender.db.schema import get_audit_event_stats as get_audit_event_stats
from pkg_defender.db.schema import get_audit_events as get_audit_events
from pkg_defender.db.schema import get_connection as get_connection
from pkg_defender.db.schema import get_feed_state as get_feed_state
from pkg_defender.db.schema import get_feed_stats_history as get_feed_stats_history
from pkg_defender.db.schema import get_schema_version as get_schema_version
from pkg_defender.db.schema import get_threat as get_threat
from pkg_defender.db.schema import get_threats_for_package as get_threats_for_package
from pkg_defender.db.schema import get_version_timestamp as get_version_timestamp
from pkg_defender.db.schema import get_version_timestamps_batch as get_version_timestamps_batch
from pkg_defender.db.schema import init_db as init_db
from pkg_defender.db.schema import insert_audit_event as insert_audit_event
from pkg_defender.db.schema import insert_bypass as insert_bypass
from pkg_defender.db.schema import insert_feed_stats as insert_feed_stats
from pkg_defender.db.schema import insert_threat as insert_threat
from pkg_defender.db.schema import insert_version_timestamp as insert_version_timestamp
from pkg_defender.db.schema import set_schema_version as set_schema_version
from pkg_defender.db.schema import update_feed_state as update_feed_state
from pkg_defender.models import AuditCooldownEntry as AuditCooldownEntry
from pkg_defender.models import AuditThreatEntry as AuditThreatEntry
from pkg_defender.models import CheckResult as CheckResult
from pkg_defender.models import CooldownResult as CooldownResult
from pkg_defender.models import PackageAuditResult as PackageAuditResult
from pkg_defender.models import ScoredThreat as ScoredThreat
from pkg_defender.models import ThreatRecord as ThreatRecord
from pkg_defender.models import VersionInfo as VersionInfo

__all__ = [
    "CURRENT_SCHEMA_VERSION",
    "get_connection",
    "get_schema_version",
    "init_db",
    "insert_threat",
    "get_threat",
    "get_threats_for_package",
    "insert_version_timestamp",
    "set_schema_version",
    "get_version_timestamp",
    "get_version_timestamps_batch",
    "insert_bypass",
    "update_feed_state",
    "get_feed_state",
    "get_feed_stats_history",
    "insert_audit_event",
    "insert_feed_stats",
    "get_audit_events",
    "get_audit_event_stats",
    "ThreatRecord",
    "VersionInfo",
    "ScoredThreat",
    "CooldownResult",
    "CheckResult",
    "PackageAuditResult",
    "AuditThreatEntry",
    "AuditCooldownEntry",
]
