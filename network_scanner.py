import json
import socket
import urllib.request
from datetime import datetime
import psutil

_dns_cache: dict[str, str] = {}
_org_cache: dict[str, str] = {}
_first_seen_cache: dict[tuple, str] = {}

DANGEROUS_PORTS = {21, 23, 445, 3389, 4444, 5900}
SAFE_PORTS = {443, 8443, 993, 995}
IGNORED_KEYWORDS = {"ip-api.com", "ipify.org"}

SERVICE_KEYWORDS = {
    "googlevideo": "YouTube (Video Stream)",
    "youtube": "YouTube",
    "1e100.net": "Google / YouTube",
    "googleusercontent": "Google Cloud / Services",
    "google": "Google",
    "github": "GitHub",
    "githubusercontent": "GitHub",
    "microsoft": "Microsoft / VS Code",
    "visualstudio": "VS Code Services",
    "azure": "Microsoft Azure",
    "amazonaws": "Amazon AWS",
    "cloudflare": "Cloudflare",
    "akamai": "Akamai CDN",
    "fastly": "Fastly CDN",
    "discord": "Discord",
    "spotify": "Spotify",
    "steam": "Steam",
}


def get_local_ip() -> str:
    """Retrieves the machine's local IP address on the LAN."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "Unavailable"


def get_public_ip() -> str:
    """Retrieves the machine's public IP address."""
    try:
        response = urllib.request.urlopen("https://api.ipify.org", timeout=3)
        return response.read().decode("utf-8")
    except Exception:
        return "Offline / Unavailable"


def resolve_hostname(ip: str) -> str:
    """Translates an IP address into a technical hostname."""
    if ip in _dns_cache:
        return _dns_cache[ip]
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        _dns_cache[ip] = hostname
        return hostname
    except Exception:
        _dns_cache[ip] = ""
        return ""


def resolve_ip_owner(ip: str) -> str:
    """Looks up the organization owning the IP using built-in urllib."""
    if ip in _org_cache:
        return _org_cache[ip]
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,org,isp"
        req = urllib.request.urlopen(url, timeout=2)
        data = json.loads(req.read().decode("utf-8"))
        if data.get("status") == "success":
            owner = data.get("org") or data.get("isp") or "Unlisted Network"
            clean_owner = owner.split(",")[0][:28]
            _org_cache[ip] = clean_owner
            return clean_owner
    except Exception:
        pass

    _org_cache[ip] = "Unlisted Network"
    return "Unlisted Network"


def identify_service_name(hostname: str, owner: str) -> str:
    """Extracts a clean website/service name (e.g., YouTube, VS Code, GitHub)."""
    combined = f"{hostname} {owner}".lower()
    for keyword, friendly_name in SERVICE_KEYWORDS.items():
        if keyword in combined:
            return friendly_name
    if owner and owner != "Unlisted Network":
        return owner
    return "General Web Service"


def evaluate_connection_status(port: int) -> str:
    """Evaluates connection safety: SECURE (Green), WARNING (Yellow), or DANGER (Red)."""
    if port in DANGEROUS_PORTS:
        return "DANGER"
    if port in SAFE_PORTS:
        return "SECURE"
    return "WARNING"


def get_active_connections() -> list[dict]:
    """Returns grouped active connections along with individual TCP socket details."""
    grouped: dict[tuple, dict] = {}
    current_socket_keys = set()

    for conn in psutil.net_connections(kind="inet"):
        if conn.status != "ESTABLISHED" or not conn.raddr:
            continue

        ip = conn.raddr.ip
        port = conn.raddr.port

        if ip.startswith("127.") or ip == "::1":
            continue

        if conn.pid:
            try:
                app_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                app_name = "System Process"
        else:
            app_name = "System / Root"

        hostname = resolve_hostname(ip)
        if any(ignored in hostname.lower() for ignored in IGNORED_KEYWORDS):
            continue

        owner = resolve_ip_owner(ip)
        service_name = identify_service_name(hostname, owner)
        status = evaluate_connection_status(port)
        display_host = hostname if hostname else f"Direct IP ({owner})"

        # Track timestamp per individual socket (IP + Port + App)
        socket_key = (app_name, ip, port)
        current_socket_keys.add(socket_key)
        if socket_key not in _first_seen_cache:
            _first_seen_cache[socket_key] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        socket_time = _first_seen_cache[socket_key]

        # Group key for the top-level parent row
        group_key = (app_name, service_name, port)

        detail_entry = {
            "time": socket_time,
            "app": f"└─ TCP Socket",
            "service": service_name,
            "website": display_host,
            "ip": ip,
            "port": port,
            "status": status,
        }

        if group_key not in grouped:
            grouped[group_key] = {
                "group_id": f"{app_name}_{service_name}_{port}",
                "time": socket_time,
                "app": app_name,
                "base_service": service_name,
                "website": display_host,
                "ip": ip,
                "port": port,
                "status": status,
                "details": [detail_entry],
            }
        else:
            # Avoid adding exact duplicate IP+Port inside the dropdown
            existing_ips = {(d["ip"], d["port"]) for d in grouped[group_key]["details"]}
            if (ip, port) not in existing_ips:
                grouped[group_key]["details"].append(detail_entry)

    # Clean up old timestamps
    for old_key in list(_first_seen_cache.keys()):
        if old_key not in current_socket_keys:
            del _first_seen_cache[old_key]

    results = []
    for item in grouped.values():
        count = len(item["details"])
        if count > 1:
            item["service"] = f"{item['base_service']} ({count}x)"
            item["ip"] = f"{count} IPs (Click arrow)"
        else:
            item["service"] = item["base_service"]
        results.append(item)

    priority = {"DANGER": 0, "WARNING": 1, "SECURE": 2}
    results.sort(key=lambda x: (priority.get(x["status"], 3), x["app"]))
    return results