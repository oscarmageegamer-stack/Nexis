# Nexis v0.3.0

Nexis is a modular security-intelligence framework for authorised testing and monitoring of systems and networks you own or are explicitly permitted to assess.

## Install / update on Windows
From the Nexis project folder in VS Code:
`py -m pip install -e .`
Then open a new terminal and run `nexis`.

After future GitHub updates, use `git pull` and rerun the editable install if packaging metadata changes.

## Current capabilities
- Recon: IP information and DNS
- Network: local discovery, automatic IPv4/subnet inference, Nmap host discovery, baseline comparison
- Wi-Fi: local adapter information
- Crypto: hash/encoding identification and file hashing
- Web: HTTP security-header inspection
- Host: local host information
- Intelligence core: persistent local events, network baselines, change detection and explainable risk assessment
- Monitoring: `watch network [seconds]`
- Investigation: `network investigate <ip>` for observed local devices
- Reports: JSON session reports

## Intelligence workflow
1. `network baseline` establishes a local-network snapshot.
2. `network changes` compares the current snapshot with the saved baseline.
3. `watch network 30` periodically observes the local network and reports changes.
4. `events 50` shows recent Nexis events.
5. `report` writes a session report.

Discovery changes are observations, not proof of compromise. Nexis deliberately avoids presenting latency as physical distance and does not infer a device's physical location from its IP address.

Only test systems, networks, websites and devices you own or have explicit permission to assess.
