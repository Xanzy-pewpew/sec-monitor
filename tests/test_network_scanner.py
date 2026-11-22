from network_scanner import evaluate_connection_status, identify_service_name


def test_evaluate_connection_status_danger():
    assert evaluate_connection_status(21) == "DANGER"    # FTP
    assert evaluate_connection_status(23) == "DANGER"    # Telnet
    assert evaluate_connection_status(445) == "DANGER"   # SMB
    assert evaluate_connection_status(3389) == "DANGER"  # RDP
    assert evaluate_connection_status(4444) == "DANGER"  # Metasploit default


def test_evaluate_connection_status_secure():
    assert evaluate_connection_status(443) == "SECURE"   # HTTPS
    assert evaluate_connection_status(8443) == "SECURE"  # Alt HTTPS
    assert evaluate_connection_status(993) == "SECURE"   # IMAPS


def test_evaluate_connection_status_warning():
    assert evaluate_connection_status(80) == "WARNING"   # Okrypterad HTTP
    assert evaluate_connection_status(8080) == "WARNING"


def test_identify_service_name_known_keywords():
    assert identify_service_name("rr1---sn-4g5e6n7k.googlevideo.com", "Google LLC") == "YouTube (Video Stream)"
    assert identify_service_name("api.github.com", "GitHub Inc") == "GitHub"
    assert identify_service_name("server.discord.gg", "Cloudflare") == "Discord"


def test_identify_service_name_fallback():
    assert identify_service_name("", "Telia Company AB") == "Telia Company AB"
    assert identify_service_name("", "Unlisted Network") == "General Web Service"