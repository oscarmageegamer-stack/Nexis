# Nexis v0.4.0

Nexis is a modular security-intelligence framework for authorised testing and monitoring of systems and networks you own or are explicitly permitted to assess.

## Install / update on Windows
From the Nexis project folder in VS Code:
`git pull`
`py -m pip install -e .`
Then open a new terminal and run `nexis`.

## Current capabilities
- Recon: IP information, DNS, approximate public-IP geolocation, and public organisation/project footprinting
- Network: local discovery, IPv4/subnet inference, Nmap host discovery, baseline comparison, investigations
- Wi-Fi: local adapter information
- Crypto: hash/encoding identification and file hashing
- Web: HTTP security-header inspection
- Host: local host information
- Intelligence core: persistent events, network baselines, change detection and explainable risk assessment
- Monitoring: `watch network [seconds]`
- Tool integration: detection of locally installed Nmap, TShark, Metasploit, OWASP Amass, SpiderFoot and WhatWeb tooling; Nexis does not expose exploit execution
- Reporting: JSON session reports

## Footprint module
`recon footprint "Organisation Name" "Country"`

The footprint feature performs a public-web presence search for organisations, brands and projects. It collects public result URLs/titles/snippets from several search categories and is designed for defensive attack-surface and brand research. It deliberately avoids building personal dossiers or aggregating sensitive personal data such as private addresses, phone numbers or personal emails.

Useful commands:
`network discover`
`network baseline`
`network changes`
`network investigate <ip>`
`watch network 30`
`recon geo <public-ip>`
`recon myip`
`recon footprint "Organisation Name" "Country"`
`tools status`
`tools tshark`
`events 50`
`report`

## Geolocation note
Public-IP coordinates are approximate and normally identify a provider/region rather than a person's or device's exact physical position. Private LAN addresses are not publicly geolocatable.

## Intelligence workflow
Nexis is being developed around a sensor -> events -> baseline -> correlation -> risk -> investigation -> reporting architecture. Discovery changes are observations, not proof of compromise.

Only test systems, networks, websites and devices you own or have explicit permission to assess.
