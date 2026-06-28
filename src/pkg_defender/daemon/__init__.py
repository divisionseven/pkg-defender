"""Background daemon — periodic feed sync and platform service management."""

from pkg_defender.daemon.runner import (
    daemon_loop,
    is_daemon_running,
    read_heartbeat,
    run_daemon,
    write_heartbeat,
)
from pkg_defender.daemon.service import (
    generate_launchd_plist,
    generate_scheduled_task_xml,
    generate_systemd_unit,
    install_service,
    uninstall_service,
)

__all__ = [
    "daemon_loop",
    "generate_launchd_plist",
    "generate_scheduled_task_xml",
    "generate_systemd_unit",
    "install_service",
    "is_daemon_running",
    "read_heartbeat",
    "run_daemon",
    "uninstall_service",
    "write_heartbeat",
]
