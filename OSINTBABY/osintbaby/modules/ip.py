"""IP Address OSINT module."""

import socket
from typing import Dict, Any, List
from ..core.base import OSINTBase, console


class IPOSINT(OSINTBase):
    """IP Address reconnaissance module."""

    def get_module_name(self) -> str:
        return "IP OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run all IP OSINT checks."""
        console.print(f"[cyan]Running IP OSINT for: {target}[/cyan]")
        
        results = {
            "target": target,
            "geolocation": self._get_geolocation(target),
            "reverse_dns": self._get_reverse_dns(target),
            "abuse_info": self._get_abuse_info(target),
            "blacklist_check": self._check_blacklists(target),
            "asn_info": self._get_asn_info(target),
            "ports": self._check_common_ports(target),
        }
        
        return results

    def _get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get IP geolocation using free APIs."""
        # ip-api.com (free, no API key needed)
        url = f"http://ip-api.com/json/{ip}"
        response = self._make_request(url)
        
        if response:
            data = response.json()
            return {
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "zip": data.get("zip"),
                "lat": data.get("lat"),
                "lon": data.get("lon"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as": data.get("as"),
            }
        
        return {}

    def _get_reverse_dns(self, ip: str) -> List[str]:
        """Get reverse DNS entries."""
        hostnames = []
        
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            hostnames.append(hostname)
        except socket.herror:
            pass
        
        return hostnames

    def _get_abuse_info(self, ip: str) -> Dict[str, Any]:
        """Get abuse contact information."""
        # AbuseIPDB (requires free API key for full functionality)
        # For demo, using ip-api.com data
        return self._get_geolocation(ip)

    def _check_blacklists(self, ip: str) -> Dict[str, bool]:
        """Check IP against DNS blacklists."""
        blacklists = [
            "zen.spamhaus.org",
            "bl.spamcop.net",
            "b.barracudacentral.org",
            "dnsbl.sorbs.net",
            "spam.dnsbl.sorbs.net",
        ]
        
        results = {}
        reversed_ip = ".".join(reversed(ip.split(".")))
        
        for bl in blacklists:
            try:
                query = f"{reversed_ip}.{bl}"
                socket.gethostbyname(query)
                results[bl] = True  # Listed
            except socket.gaierror:
                results[bl] = False  # Not listed
        
        return results

    def _get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN information."""
        # Using BGPView API
        url = f"https://api.bgpview.io/ip/{ip}"
        response = self._make_request(url)
        
        if response:
            data = response.json().get("data", {})
            prefixes = data.get("prefixes", [])
            
            if prefixes:
                prefix = prefixes[0]
                asn = prefix.get("asn", {})
                return {
                    "prefix": prefix.get("prefix"),
                    "asn": asn.get("asn"),
                    "asn_name": asn.get("name"),
                    "asn_description": asn.get("description"),
                    "country_code": asn.get("country_code"),
                }
        
        return {}

    def _check_common_ports(self, ip: str) -> Dict[int, Dict[str, Any]]:
        """Check common ports (basic scan)."""
        common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            8080: "HTTP-Proxy",
        }
        
        results = {}
        
        for port, service in common_ports.items():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    results[port] = {
                        "service": service,
                        "state": "open"
                    }
            except Exception:
                pass
        
        return results