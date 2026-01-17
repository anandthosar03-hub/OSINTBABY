"""Domain OSINT module."""

import dns.resolver
import whois
import socket
from typing import Dict, Any, List
from bs4 import BeautifulSoup
from ..core.base import OSINTBase, console


class DomainOSINT(OSINTBase):
    """Domain reconnaissance module."""

    def get_module_name(self) -> str:
        return "Domain OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run all domain OSINT checks."""
        console.print(f"[cyan]Running domain OSINT for: {target}[/cyan]")
        
        results = {
            "target": target,
            "dns_records": self._get_dns_records(target),
            "whois": self._get_whois(target),
            "subdomains": self._enumerate_subdomains(target),
            "technologies": self._detect_technologies(target),
            "security_headers": self._check_security_headers(target),
            "ssl_info": self._get_ssl_info(target),
        }
        
        return results

    def _get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Retrieve DNS records."""
        records = {}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, 
                    dns.resolver.NoNameservers, Exception):
                records[record_type] = []
        
        return records

    def _get_whois(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information."""
        try:
            w = whois.whois(domain)
            return {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "status": w.status,
                "emails": w.emails,
                "org": w.org,
                "country": w.country,
            }
        except Exception as e:
            return {"error": str(e)}

    def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using crt.sh."""
        subdomains = set()
        
        # crt.sh - Certificate Transparency
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = self._make_request(url)
        
        if response:
            try:
                data = response.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and "*" not in sub:
                            subdomains.add(sub)
            except Exception:
                pass
        
        # DNSDumpster (scraping)
        subdomains.update(self._dnsdumpster_subdomains(domain))
        
        return sorted(list(subdomains))[:50]  # Limit results

    def _dnsdumpster_subdomains(self, domain: str) -> List[str]:
        """Get subdomains from DNSDumpster."""
        subdomains = []
        
        try:
            # Get CSRF token
            session_response = self._make_request("https://dnsdumpster.com/")
            if not session_response:
                return subdomains
            
            soup = BeautifulSoup(session_response.text, "html.parser")
            csrf_token = soup.find("input", {"name": "csrfmiddlewaretoken"})
            
            if csrf_token:
                csrf = csrf_token.get("value")
                cookies = session_response.cookies
                
                # Make search request
                headers = {
                    "Referer": "https://dnsdumpster.com/",
                }
                data = {
                    "csrfmiddlewaretoken": csrf,
                    "targetip": domain,
                    "user": "free"
                }
                
                self.session.cookies.update(cookies)
                response = self._make_request(
                    "https://dnsdumpster.com/",
                    method="POST",
                    data=data,
                    headers=headers
                )
                
                if response:
                    soup = BeautifulSoup(response.text, "html.parser")
                    tables = soup.findAll("table")
                    
                    for table in tables:
                        rows = table.findAll("tr")
                        for row in rows:
                            cells = row.findAll("td")
                            if cells:
                                subdomain = cells[0].get_text().strip()
                                if domain in subdomain:
                                    subdomains.append(subdomain.split("\n")[0])
        except Exception:
            pass
        
        return subdomains

    def _detect_technologies(self, domain: str) -> Dict[str, Any]:
        """Detect web technologies."""
        technologies = {
            "server": None,
            "powered_by": None,
            "frameworks": [],
            "cms": None,
        }
        
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            response = self._make_request(url)
            
            if response:
                headers = response.headers
                technologies["server"] = headers.get("Server")
                technologies["powered_by"] = headers.get("X-Powered-By")
                
                # Detect from content
                content = response.text.lower()
                
                # CMS Detection
                cms_signatures = {
                    "WordPress": ["wp-content", "wp-includes"],
                    "Drupal": ["drupal.js", "drupal.css"],
                    "Joomla": ["joomla", "/media/system/js/"],
                    "Shopify": ["shopify", "cdn.shopify.com"],
                    "Wix": ["wix.com", "static.wixstatic.com"],
                }
                
                for cms, signatures in cms_signatures.items():
                    if any(sig in content for sig in signatures):
                        technologies["cms"] = cms
                        break
                
                # Framework detection
                framework_signatures = {
                    "React": ["react", "_reactroot"],
                    "Angular": ["ng-app", "angular"],
                    "Vue.js": ["vue.js", "__vue__"],
                    "jQuery": ["jquery"],
                    "Bootstrap": ["bootstrap"],
                }
                
                for framework, signatures in framework_signatures.items():
                    if any(sig in content for sig in signatures):
                        technologies["frameworks"].append(framework)
                
                break
        
        return technologies

    def _check_security_headers(self, domain: str) -> Dict[str, Any]:
        """Check security headers."""
        security_headers = {
            "Strict-Transport-Security": None,
            "Content-Security-Policy": None,
            "X-Frame-Options": None,
            "X-Content-Type-Options": None,
            "X-XSS-Protection": None,
            "Referrer-Policy": None,
            "Permissions-Policy": None,
        }
        
        for scheme in ["https", "http"]:
            url = f"{scheme}://{domain}"
            response = self._make_request(url)
            
            if response:
                for header in security_headers:
                    security_headers[header] = response.headers.get(header)
                break
        
        return security_headers

    def _get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information."""
        import ssl
        import socket
        from datetime import datetime
        
        ssl_info = {}
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "san": cert.get("subjectAltName", []),
                    }
        except Exception as e:
            ssl_info["error"] = str(e)
        
        return ssl_info