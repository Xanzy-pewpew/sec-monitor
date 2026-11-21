import platform
import subprocess

CURRENT_OS = platform.system()  # Returns "Linux", "Windows", or "Darwin" (macOS)


def check_firewall_status() -> str:
    """Checks firewall status dynamically based on the user's operating system."""
    if CURRENT_OS == "Linux":
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            if "Status: active" in result.stdout:
                return "ACTIVE - UFW (Protected)"
            if "Status: inactive" in result.stdout:
                return "INACTIVE - UFW (Warning)"
            return "UFW: Permission denied (Run with sudo)"
        except FileNotFoundError:
            return "UFW not installed"

    elif CURRENT_OS == "Windows":
        try:
            cmd = ["netsh", "advfirewall", "show", "allprofiles", "state"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if "ON" in result.stdout:
                return "ACTIVE - Windows Defender Firewall"
            return "INACTIVE - Windows Firewall (Warning)"
        except Exception:
            return "Windows Firewall: Unable to read status"

    elif CURRENT_OS == "Darwin":
        return "macOS Firewall (Check System Settings)"

    return f"Unsupported OS ({CURRENT_OS})"


def get_failed_logins(limit: int = 5) -> list[str]:
    """Scans OS security logs for failed authentication attempts."""
    if CURRENT_OS == "Linux":
        try:
            cmd = ["journalctl", "-n", "150", "--no-pager"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            alerts = [
                line.strip()
                for line in result.stdout.splitlines()
                if "Failed password" in line or "authentication failure" in line
            ]
            return alerts[-limit:]
        except Exception as e:
            return [f"Error reading Linux logs: {e}"]

    elif CURRENT_OS == "Windows":
        try:
            # Query Windows Security Log for Event ID 4625 (Failed Logon)
            ps_cmd = (
                f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4625}} "
                f"-MaxEvents {limit} -ErrorAction SilentlyContinue | "
                f"ForEach-Object {{ $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss') + ' - Failed Windows Login' }}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
            )
            alerts = [line.strip() for line in result.stdout.splitlines() if line.strip()]
            return alerts
        except Exception:
            return ["Run as Administrator on Windows to inspect Security Event Logs."]

    return [f"Failed login log scanning not configured for {CURRENT_OS}."]