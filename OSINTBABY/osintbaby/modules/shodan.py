"""Shodan OSINT module (using free tier)."""

from typing import Dict, Any, List
from ..core.base import OSINTBase, console


class ShodanOSINT(OSINTBase):
    """Shodan reconnaissance module."""

    def get_module_name(self) -> str:
        return "Shodan OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run Shodan lookup."""
        console.print(f"[cyan]Running Shodan OSINT for: {target}[/cyan]")
        
        results = {
            "target": target,
            "host_info": self._get_host_info(target),
            "internet_db": self._internetdb_lookup(target),
        }
        
        return results

    def _get_host_info(self, ip: str) -> Dict[str, Any]:
        """Get host information from Shodan."""
        api_key = self.config.get("api_keys", {}).get("shodan")
        
        if not api_key:
            return {"note": "Shodan API key not configured. Get free key at shodan.io"}
        
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": api_key}
        
        response = self._make_request(url, params=params, delay=2)
        
        if response:
            data = response.json()
            return {
                "ip": data.get("ip_str"),
                "hostnames": data.get("hostnames", []),
                "country": data.get("country_name"),
                "city": data.get("city"),
                "org": data.get("org"),
                "isp": data.get("isp"),
                "asn": data.get("asn"),
                "ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "os": data.get("os"),
                "domains": data.get("domains", []),
                "last_update": data.get("last_update"),
                "services": self._parse_services(data.get("data", []))
            }
        
        return {"error": "Lookup failed or IP not found"}

    def _parse_services(self, data: List[Dict]) -> List[Dict[str, Any]]:
        """Parse service data from Shodan response."""
        services = []
        
        for service in data[:10]:  # Limit to first 10 services
            services.append({
                "port": service.get("port"),
                "transport": service.get("transport"),
                "product": service.get("product"),
                "version": service.get("version"),
                "banner": service.get("data", "")[:200],  # First 200 chars
                "ssl": "ssl" in service,
            })
        
        return services

    def _internetdb_lookup(self, ip: str) -> Dict[str, Any]:
        """Use Shodan InternetDB (free, no API key needed)."""
        url = f"https://internetdb.shodan.io/{ip}"
        response = self._make_request(url)
        
        if response:
            if response.status_code == 200:
                data = response.json()
                return {
                    "ip": data.get("ip"),
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "cpes": data.get("cpes", []),
                    "vulns": data.get("vulns", []),
                    "tags": data.get("tags", []),
                }
            elif response.status_code == 404:
                return {"note": "IP not found in InternetDB"}
        
        return {"error": "Lookup failed"}