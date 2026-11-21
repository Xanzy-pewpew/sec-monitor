import os
import tkinter as tk
from dotenv import load_dotenv
import network_scanner
import security_monitor
from ui.dashboard import SecMonitorDashboard

# Load private environment variables from .env
load_dotenv()
MAX_FAILED_LOGINS = int(os.getenv("MAX_FAILED_LOGINS", 3))


def collect_system_data() -> dict:
    """Collects all network and security telemetry for the UI."""
    return {
        "local_ip": network_scanner.get_local_ip(),
        "public_ip": network_scanner.get_public_ip(),
        "firewall": security_monitor.check_firewall_status(),
        "connections": network_scanner.get_active_connections(),
        "alerts": security_monitor.get_failed_logins(),
    }


if __name__ == "__main__":
    root = tk.Tk()
    app = SecMonitorDashboard(
        root=root,
        scan_callback=collect_system_data,
        max_failed_logins=MAX_FAILED_LOGINS,
    )
    root.mainloop()