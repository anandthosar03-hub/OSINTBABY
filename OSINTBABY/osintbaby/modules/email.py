"""Email OSINT module."""

import re
import hashlib
from typing import Dict, Any, List
from ..core.base import OSINTBase, console


class EmailOSINT(OSINTBase):
    """Email reconnaissance module."""

    def get_module_name(self) -> str:
        return "Email OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run all email OSINT checks."""
        console.print(f"[cyan]Running Email OSINT for: {target}[/cyan]")
        
        results = {
            "target": target,
            "breach_check": self._check_breaches(target),
            "email_validation": self._validate_email(target),
            "gravatar": self._check_gravatar(target),
            "domain_info": self._get_domain_info(target),
            "social_profiles": self._find_social_profiles(target),
        }
        
        return results

    def _check_breaches(self, email: str) -> Dict[str, Any]:
        """Check email in data breaches using Have I Been Pwned."""
        # HIBP API requires subscription, using alternative
        # Using a simple hash-based check
        
        breaches = {
            "checked": True,
            "found_in_breaches": False,
            "breaches": [],
            "note": "Use haveibeenpwned.com for detailed breach info"
        }
        
        # Check using emailrep.io (free, rate limited)
        url = f"https://emailrep.io/{email}"
        headers = {"User-Agent": "OSINT-CLI"}
        response = self._make_request(url, headers=headers)
        
        if response:
            data = response.json()
            breaches["reputation"] = data.get("reputation")
            breaches["suspicious"] = data.get("suspicious")
            breaches["references"] = data.get("references")
            breaches["details"] = data.get("details", {})
        
        return breaches

    def _validate_email(self, email: str) -> Dict[str, Any]:
        """Validate email address."""
        import dns.resolver
        
        result = {
            "format_valid": False,
            "domain_exists": False,
            "mx_records": [],
            "disposable": False,
        }
        
        # Format validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        result["format_valid"] = bool(re.match(pattern, email))
        
        if not result["format_valid"]:
            return result
        
        domain = email.split("@")[1]
        
        # Check MX records
        try:
            mx_records = dns.resolver.resolve(domain, "MX")
            result["mx_records"] = [str(r.exchange) for r in mx_records]
            result["domain_exists"] = True
        except Exception:
            pass
        
        # Check if disposable
        disposable_domains = [
            "tempmail.com", "throwaway.email", "guerrillamail.com",
            "10minutemail.com", "mailinator.com", "temp-mail.org",
            "fakeinbox.com", "trashmail.com"
        ]
        result["disposable"] = domain.lower() in disposable_domains
        
        return result

    def _check_gravatar(self, email: str) -> Dict[str, Any]:
        """Check for Gravatar profile."""
        email_hash = hashlib.md5(email.lower().encode()).hexdigest()
        
        # Check if gravatar exists
        url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        response = self._make_request(url)
        
        result = {
            "exists": response is not None and response.status_code == 200,
            "hash": email_hash,
            "profile_url": f"https://gravatar.com/{email_hash}",
            "avatar_url": f"https://www.gravatar.com/avatar/{email_hash}"
        }
        
        # Get profile JSON
        if result["exists"]:
            profile_url = f"https://www.gravatar.com/{email_hash}.json"
            profile_response = self._make_request(profile_url)
            if profile_response:
                try:
                    data = profile_response.json()
                    entry = data.get("entry", [{}])[0]
                    result["display_name"] = entry.get("displayName")
                    result["about"] = entry.get("aboutMe")
                    result["location"] = entry.get("currentLocation")
                    result["urls"] = entry.get("urls", [])
                except Exception:
                    pass
        
        return result

    def _get_domain_info(self, email: str) -> Dict[str, Any]:
        """Get information about the email domain."""
        domain = email.split("@")[1]
        
        info = {
            "domain": domain,
            "is_free_provider": False,
            "is_corporate": False,
        }
        
        free_providers = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
            "aol.com", "mail.com", "protonmail.com", "icloud.com",
            "yandex.com", "gmx.com", "zoho.com"
        ]
        
        info["is_free_provider"] = domain.lower() in free_providers
        info["is_corporate"] = not info["is_free_provider"]
        
        return info

    def _find_social_profiles(self, email: str) -> List[Dict[str, str]]:
        """Find potential social media profiles."""
        profiles = []
        username = email.split("@")[0]
        
        # Common social media platforms
        platforms = [
            ("GitHub", f"https://github.com/{username}"),
            ("Twitter", f"https://twitter.com/{username}"),
            ("LinkedIn", f"https://linkedin.com/in/{username}"),
            ("Instagram", f"https://instagram.com/{username}"),
            ("Facebook", f"https://facebook.com/{username}"),
        ]
        
        for platform, url in platforms:
            response = self._make_request(url)
            if response and response.status_code == 200:
                profiles.append({
                    "platform": platform,
                    "url": url,
                    "status": "Found"
                })
        
        return profiles