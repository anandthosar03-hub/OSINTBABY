"""Phone number OSINT module."""

import re
from typing import Dict, Any, List
from ..core.base import OSINTBase, console


class PhoneOSINT(OSINTBase):
    """Phone number reconnaissance module."""

    # Country codes
    COUNTRY_CODES = {
        "1": "USA/Canada",
        "7": "Russia",
        "20": "Egypt",
        "27": "South Africa",
        "30": "Greece",
        "31": "Netherlands",
        "32": "Belgium",
        "33": "France",
        "34": "Spain",
        "36": "Hungary",
        "39": "Italy",
        "40": "Romania",
        "41": "Switzerland",
        "43": "Austria",
        "44": "United Kingdom",
        "45": "Denmark",
        "46": "Sweden",
        "47": "Norway",
        "48": "Poland",
        "49": "Germany",
        "51": "Peru",
        "52": "Mexico",
        "53": "Cuba",
        "54": "Argentina",
        "55": "Brazil",
        "56": "Chile",
        "57": "Colombia",
        "58": "Venezuela",
        "60": "Malaysia",
        "61": "Australia",
        "62": "Indonesia",
        "63": "Philippines",
        "64": "New Zealand",
        "65": "Singapore",
        "66": "Thailand",
        "81": "Japan",
        "82": "South Korea",
        "84": "Vietnam",
        "86": "China",
        "90": "Turkey",
        "91": "India",
        "92": "Pakistan",
        "93": "Afghanistan",
        "94": "Sri Lanka",
        "95": "Myanmar",
        "98": "Iran",
        "212": "Morocco",
        "213": "Algeria",
        "216": "Tunisia",
        "218": "Libya",
        "220": "Gambia",
        "221": "Senegal",
        "234": "Nigeria",
        "254": "Kenya",
        "255": "Tanzania",
        "256": "Uganda",
        "260": "Zambia",
        "263": "Zimbabwe",
        "264": "Namibia",
        "351": "Portugal",
        "352": "Luxembourg",
        "353": "Ireland",
        "354": "Iceland",
        "355": "Albania",
        "358": "Finland",
        "359": "Bulgaria",
        "370": "Lithuania",
        "371": "Latvia",
        "372": "Estonia",
        "373": "Moldova",
        "374": "Armenia",
        "375": "Belarus",
        "380": "Ukraine",
        "381": "Serbia",
        "385": "Croatia",
        "386": "Slovenia",
        "420": "Czech Republic",
        "421": "Slovakia",
        "852": "Hong Kong",
        "853": "Macau",
        "886": "Taiwan",
        "960": "Maldives",
        "961": "Lebanon",
        "962": "Jordan",
        "963": "Syria",
        "964": "Iraq",
        "965": "Kuwait",
        "966": "Saudi Arabia",
        "967": "Yemen",
        "968": "Oman",
        "971": "UAE",
        "972": "Israel",
        "973": "Bahrain",
        "974": "Qatar",
        "975": "Bhutan",
        "976": "Mongolia",
        "977": "Nepal",
    }

    def get_module_name(self) -> str:
        return "Phone OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run phone number OSINT checks."""
        console.print(f"[cyan]Running Phone OSINT for: {target}[/cyan]")
        
        # Clean the phone number
        cleaned = self._clean_phone_number(target)
        
        results = {
            "target": target,
            "cleaned": cleaned,
            "parsed_info": self._parse_phone_number(cleaned),
            "carrier_info": self._lookup_carrier(cleaned),
            "numverify": self._numverify_lookup(cleaned),
        }
        
        return results

    def _clean_phone_number(self, phone: str) -> str:
        """Clean and normalize phone number."""
        # Remove all non-numeric characters except +
        cleaned = re.sub(r'[^\d+]', '', phone)
        
        # Ensure it starts with +
        if not cleaned.startswith('+'):
            # Assume it might be missing the +
            if len(cleaned) > 10:
                cleaned = '+' + cleaned
        
        return cleaned

    def _parse_phone_number(self, phone: str) -> Dict[str, Any]:
        """Parse phone number to extract information."""
        result = {
            "valid_format": False,
            "country_code": None,
            "country": None,
            "national_number": None,
            "line_type": None,
        }
        
        # Remove + for processing
        number = phone.lstrip('+')
        
        if not number.isdigit():
            return result
        
        # Try to match country code
        for i in range(1, 4):
            code = number[:i]
            if code in self.COUNTRY_CODES:
                result["country_code"] = f"+{code}"
                result["country"] = self.COUNTRY_CODES[code]
                result["national_number"] = number[i:]
                result["valid_format"] = True
                break
        
        # Determine line type (mobile/landline) based on patterns
        if result["valid_format"]:
            national = result["national_number"]
            
            # Basic heuristics (country-specific rules would be more accurate)
            if result["country_code"] == "+1":  # USA/Canada
                if len(national) == 10:
                    result["line_type"] = "Geographic"
            elif result["country_code"] == "+44":  # UK
                if national.startswith("7"):
                    result["line_type"] = "Mobile"
                else:
                    result["line_type"] = "Geographic/Landline"
        
        return result

    def _lookup_carrier(self, phone: str) -> Dict[str, Any]:
        """Lookup carrier information."""
        # Using free API - Note: Many carrier lookup APIs require payment
        # This is a basic implementation
        
        result = {
            "carrier": None,
            "type": None,
        }
        
        # Basic carrier lookup using MNC patterns
        # This is simplified - real implementation would need HLR lookup
        
        return result

    def _numverify_lookup(self, phone: str) -> Dict[str, Any]:
        """Lookup using numverify API."""
        # Numverify has a free tier
        api_key = self.config.get("api_keys", {}).get("numverify")
        
        if not api_key:
            return {"note": "Numverify API key not configured"}
        
        # Remove + for API call
        number = phone.lstrip('+')
        
        url = "http://apilayer.net/api/validate"
        params = {
            "access_key": api_key,
            "number": number,
            "country_code": "",
            "format": 1
        }
        
        response = self._make_request(url, params=params)
        
        if response:
            return response.json()
        
        return {"error": "Lookup failed"}