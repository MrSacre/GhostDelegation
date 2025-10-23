#!/usr/bin/env python3
import getpass
import argparse
from ldap3 import Server, Connection, SUBTREE, ALL
import re
import sys
import dns.resolver
from typing import List, Dict

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

    @staticmethod
    def disable():
        Colors.HEADER = ''
        Colors.BLUE = ''
        Colors.CYAN = ''
        Colors.GREEN = ''
        Colors.YELLOW = ''
        Colors.RED = ''
        Colors.END = ''
        Colors.BOLD = ''

def check_dns_resolution(host, search_suffix=None):
    results = {"A": [], "AAAA": []}
    resolver = dns.resolver.Resolver()
    candidates = [host]
    if search_suffix and '.' not in host:
        candidates.append(f"{host}.{search_suffix}")
    for candidate in candidates:
        for rtype in ["A", "AAAA"]:
            try:
                answers = resolver.resolve(candidate, rtype)
                results[rtype].extend([r.to_text() for r in answers])
            except Exception:
                pass
    return results

class ConstrainedDelegationChecker:
    def __init__(self, server: str, username: str, password: str, domain: str, use_ssl: bool = False):
        self.domain = domain
        self.base_dn = ','.join([f'DC={part}' for part in domain.split('.')])
        port = 636 if use_ssl else 389
        ldap_server = Server(server, port=port, get_info=ALL, use_ssl=use_ssl)
        user_dn = f"{username}@{domain}"
        self.conn = Connection(ldap_server, user=user_dn, password=password, auto_bind=True)
        print(f"{Colors.GREEN}[+]{Colors.END} Connected to {Colors.CYAN}{server}{Colors.END}")
        print(f"{Colors.GREEN}[+]{Colors.END} Base DN: {Colors.CYAN}{self.base_dn}{Colors.END}\n")

    def get_constrained_delegation_accounts(self) -> List[Dict]:
        ldap_filter = '(msDS-AllowedToDelegateTo=*)'
        attributes = [
            'sAMAccountName',
            'distinguishedName',
            'msDS-AllowedToDelegateTo',
            'servicePrincipalName',
            'userAccountControl',
            'objectClass'
        ]
        print(f"{Colors.BLUE}[*]{Colors.END} Searching for accounts with constrained delegation...")
        self.conn.search(
            search_base=self.base_dn,
            search_filter=ldap_filter,
            search_scope=SUBTREE,
            attributes=attributes
        )
        results = []
        for entry in self.conn.entries:
            account_info = {
                'sAMAccountName': str(entry.sAMAccountName),
                'distinguishedName': str(entry.distinguishedName),
                'delegatedSPNs': list(entry['msDS-AllowedToDelegateTo']),
                'ownSPNs': list(entry.servicePrincipalName) if entry.servicePrincipalName else [],
                'objectClass': list(entry.objectClass)
            }
            results.append(account_info)
        print(f"{Colors.GREEN}[+]{Colors.END} Found {Colors.BOLD}{len(results)}{Colors.END} accounts with constrained delegation\n")
        return results

    def extract_hostname_from_spn(self, spn: str) -> str:
        m = re.match(r'^[^/\\]+[\\/](?P<host>[^:@\s]+)', spn)
        if m:
            return m.group('host')
        candidate = spn.split('@', 1)[0].split(':', 1)[0]
        if re.match(r'^[A-Za-z0-9\.-]+$', candidate):
            return candidate
        return None

    def analyze_delegation_and_ghosts(self, export_path: str = None) -> int:
        accounts = self.get_constrained_delegation_accounts()
        if not accounts:
            print(f"{Colors.YELLOW}[!]{Colors.END} No constrained delegation configurations found")
            return 0
        print(f"{Colors.BOLD}{'='*80}{Colors.END}")
        print(f"{Colors.BOLD}ANALYZING DELEGATION TARGETS{Colors.END}")
        print(f"{Colors.BOLD}{'='*80}{Colors.END}\n")
        vulnerable_count = 0
        vulnerable_entries: List[str] = []
        for account in accounts:
            account_name = account['sAMAccountName']
            for spn in account['delegatedSPNs']:
                hostname = self.extract_hostname_from_spn(spn)
                if not hostname:
                    print(f"{Colors.YELLOW}[!]{Colors.END} Unable to parse SPN: {spn}")
                    continue
                dns_results = check_dns_resolution(hostname, self.domain)
                if not dns_results['A'] and not dns_results['AAAA']:
                    vulnerable_count += 1
                    vulnerable_entries.append(f"{account_name}:{spn}")
                    print(f"{Colors.RED}[!] GHOST SPN DETECTED{Colors.END}")
                    print(f"    Account: {Colors.CYAN}{account_name}{Colors.END}")
                    print(f"    Target:  {Colors.RED}{spn}{Colors.END}")
                    print(f"    Host:    {Colors.RED}{hostname}{Colors.END} (DNS resolution failed)\n")
        if export_path and vulnerable_entries:
            try:
                with open(export_path, 'w', encoding='utf-8') as f:
                    for line in vulnerable_entries:
                        f.write(f"{line}\n")
                print(f"{Colors.GREEN}[+]{Colors.END} Exported {len(vulnerable_entries)} vulnerable entries to {export_path}")
            except Exception as e:
                print(f"{Colors.RED}[!]{Colors.END} Failed to write export file: {e}")
        return vulnerable_count

    def close(self):
        self.conn.unbind()

def main():
    print("GhostDelegation v1.0 based on GhostSPN by Remi GASCOU (Podalirius)\n")
    parser = argparse.ArgumentParser(
        description="Check constrained delegation and ghost SPN issues via LDAP."
    )
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", help="Password (if not provided, will be prompted)")
    parser.add_argument("-d", "--domain", required=True, help="Domain name (e.g. test.local)")
    parser.add_argument("--dc-ip", dest="dc_ip", help="Domain Controller IP address (if not provided, uses the domain name)")
    parser.add_argument("--ssl", action="store_true", help="Use LDAPS (port 636)")
    parser.add_argument("--export", action="store_true", help="Export vulnerable SPNs to vulnerableSPN.txt in the format Account:target")
    args = parser.parse_args()

    if not args.password:
        args.password = getpass.getpass("Password: ")

    server = args.dc_ip if args.dc_ip else args.domain
    use_ssl = args.ssl
    export_path = "vulnerableSPN.txt" if args.export else None

    try:
        checker = ConstrainedDelegationChecker(
            server=server,
            username=args.username,
            password=args.password,
            domain=args.domain,
            use_ssl=use_ssl
        )
        checker.analyze_delegation_and_ghosts(export_path=export_path)
        checker.close()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
