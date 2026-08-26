# Nexis v0.5.0

Nexis is a modular security-intelligence framework for authorised testing and monitoring of systems, networks, organisations, projects and public websites.

## Windows update
From the Nexis project folder:
`git pull`
`py -m pip install -e .`
Then open a new terminal and run `nexis`.

## Current capabilities
- Recon: IP information, DNS, public-IP geolocation
- Public footprint: organisation/project public-web footprinting
- Network: local discovery, IPv4/subnet inference, Nmap host discovery, baselines, change detection, investigation
- Wi-Fi: local adapter information
- Crypto: hash identification and file hashing
- Password security: defensive password-hash format/storage audit; no credential attack functionality
- Web intelligence: security headers, TLS/certificate details, technology hints, robots.txt/security.txt/sitemap presence, public archive history
- Host: local host information
- Tool integration: detection of locally installed Nmap, TShark and Metasploit tooling
- Intelligence core: events, baselines, explainable risk assessment and monitoring
- Reporting: JSON session reports

## Example commands
`recon myip`
`recon geo 8.8.8.8`
`recon footprint "Example Organisation" "United Kingdom"`
`network discover`
`network baseline`
`network changes`
`network investigate 192.168.1.20`
`crypto password-audit <hash>`
`web inspect https://example.com`
`web public-files https://example.com`
`web history https://example.com`
`tools status`
`watch network 30`
`events 50`
`report`

## Security model
Nexis is designed around a sensor -> events -> baseline -> correlation -> risk -> investigation -> reporting workflow. Discovery and anomaly observations are not proof of compromise.

Public IP geolocation is approximate and normally identifies a provider or region rather than an exact physical location. Private LAN addresses do not have public Internet geolocation.

The footprint and website-intelligence modules are passive/public-web oriented. They do not attempt authentication, credential theft, personal-dossier construction, or exploitation.

Only test systems, networks, websites and data you own or have explicit permission to assess.
