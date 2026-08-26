# Nexis v0.4.0

Nexis is a modular security-intelligence framework for authorised testing and monitoring of systems and networks you own or are explicitly permitted to assess.

## Install / update on Windows
From the Nexis project folder in VS Code:
`git pull`
`py -m pip install -e .`
Then open a new terminal and run `nexis`.

## Current capabilities
- Recon: IP information, DNS and approximate public-IP geolocation
- Network: local discovery, IPv4/subnet inference, Nmap host discovery, baseline comparison, investigations
- Wi-Fi: local adapter information
- Crypto: hash/encoding identification and file hashing
- Web: HTTP security-header inspection
- Host: local host information
- Intelligence core: persistent events, network baselines, change detection and explainable risk assessment
- Monitoring: `watch network [seconds]`
- Tool integration: detection of locally installed Nmap, TShark and Metasploit tooling; Nexis does not expose exploit execution
- Reporting: JSON session reports

## Useful commands
`network discover`
`network baseline`
`network changes`
`network investigate <ip>`
`watch network 30`
`recon geo <public-ip>`
`recon myip`
`tools status`
`tools tshark`
`events 50`
`report`

## Geolocation note
Public-IP coordinates are approximate and normally identify a provider/region rather than a person's or device's exact physical position. Private LAN addresses are not publicly geolocatable.

## Intelligence workflow
Nexis is being developed around a sensor -> events -> baseline -> correlation -> risk -> investigation -> reporting architecture. Discovery changes are observations, not proof of compromise.

Only test systems, networks, websites and devices you own or have explicit permission to assess.
