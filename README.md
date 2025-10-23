# GhostDelegation

A tool that scans your Active Directory for accounts with delegation rights pointing to SPNs that do not exist or no longer exist. Inspired by https://github.com/p0dalirius/GhostSPN Remi GASCOU (Podalirius)

## Installation

```bash
git clone https://github.com/MrSacre/GhostDelegation.git
cd GhostDelegation
pip install -r requirements.txt
```

## Usage

```bash
GhostDelegation v1.0 based on GhostSPN by Remi GASCOU (Podalirius)

usage: GhostDelegation.py [-h] -u USERNAME [-p PASSWORD] -d DOMAIN [--dc-ip DC_IP] [--ssl] [--export]

Check constrained delegation and ghost SPN issues via LDAP.

options:
  -h, --help            show this help message and exit
  -u, --username USERNAME
                        Username
  -p, --password PASSWORD
                        Password (if not provided, will be prompted)
  -d, --domain DOMAIN   Domain name (e.g. test.local)
  --dc-ip DC_IP         Domain Controller IP address (if not provided, uses the domain name)
  --ssl                 Use LDAPS (port 636)
  --export              Export vulnerable SPNs to vulnerableSPN.txt in the format Account:target
     
```

## Disclaimer

This tool is intended for authorized security auditing and research only.
Do not use it on systems or networks without explicit permission.
