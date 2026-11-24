# SecMonitor — Cross-Platform Local Security & Network Monitor

**Current Version:** `v0.1.0` (Initial Release)

**SecMonitor** is a lightweight, educational hobby project built in Python with Tkinter. It provides a real-time desktop dashboard for visualizing active external network connections, firewall status, and failed login attempts without having to run multiple terminal commands manually (`netstat`, `ss`, `ufw`, `journalctl`).

> **Note:** This is a personal learning and diagnostic tool—not a replacement for enterprise security suites or full packet analyzers like Wireshark.


## Features

- **Real-Time Auto-Scanning:** Updates automatically every 5 seconds in a non-blocking background thread.
- **Grouped & Expandable Network Tree:** Groups multiple TCP sockets per application and service (e.g., `VS Code (5x)`) with an expandable arrow (`▸`) to inspect individual IP addresses, hostnames, and timestamps.
- **Human-Readable Service Identification:** Resolves IP addresses via Reverse DNS and RDAP/WHOIS lookups into recognizable service names (e.g., `YouTube`, `GitHub`, `Microsoft / VS Code`).
- **Color-Coded Risk Assessment:** Categorizes connections into `SECURE` (Green), `WARNING` (Yellow), and `DANGER` (Red) based on port and encryption standards.
- **Cross-Platform Security Checks:**
  - **Linux / Ubuntu:** Checks `ufw` firewall status and scans `journalctl` for failed SSH/authentication attempts.
  - **Windows:** Checks Windows Defender Firewall profiles (`netsh`) and queries Windows Security Event Logs (Event ID `4625`) for failed logins.
- **Resizable Split Layout:** Drag the horizontal divider bar between the active connections table and the intrusion detection log panel to customize the view.

---

## Project Structure

```text
sec-monitor/
├── .env.example          # Template for local environment variables
├── .gitignore            # Excludes .env, venv/, and cache files from Git
├── requirements.txt      # Python dependencies
├── network_scanner.py    # IP lookups, DNS/org resolution, and risk evaluation
├── security_monitor.py   # Cross-platform firewall & failed login log scanner
├── main.py               # Entry point connecting telemetry modules to the UI
└── ui/
    ├── __init__.py
    └── dashboard.py      # Tkinter GUI layout, styles, and 5-second refresh loop
```


## Installation & Setup

```bash
git clone https://github.com/Xanzy-pewpew/sec-monitor.git
cd sec-monitor
```

## Create local `.env` file
```bash
cp .env.example .env
```
(On Windows Command Prompt, use `copy .env.example .env`)

## Set up virtual environment and install dependencies On Ubuntu/Debian Linux:
```bash
sudo apt update && sudo apt install -y python3-tk python3-venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## On Windows (PowerShell/Terminal):
```PowerShell
python -m venv venv
.\venv\Scripts\activate
pip install -r requirements.txt
```

## Running the Application
`Standard Mode`
```bash
python main.py
```

`Elevated Mode`
Running with elevated privileges allows the monitor to read process names for all system-level sockets and inspect protected OS security logs:

- **Ubuntu/Linux:**
```bash
sudo ./venv/bin/python main.py
```
- **Windows:** Open PowerShell or Command Prompt as Administrator, activate `venv`, and run `python main.py`


---

## Roadmap & Planned Features

This project is under active development. Planned improvements include:

- [ ] **UI Customization:** Theme switcher (Dark/Light mode) and configurable scan intervals directly in the dashboard. (Not sure about this yet!)
- [x] **Automated Testing:** Unit tests with `pytest` to verify risk classification logic, port rules, and cross-platform OS checks.
- [ ] **Active Intrusion Protection:** Option to block suspicious IP addresses directly via `ufw` (Linux) or Windows Defender Firewall from the UI, plus automated blocking rules for repeated failed logins.
- [ ] **Alert History & Export:** Automatic logging of `WARNING` and `DANGER` events to a local CSV/JSON file for post-incident review.
- [ ] **Listening Ports Monitor:** Dedicated view for local `LISTEN` ports to spot unintended open services on the host machine.
- [ ] **Desktop Notifications:** Native OS pop-up alerts when a high-risk (`DANGER`) connection is detected in the background.

