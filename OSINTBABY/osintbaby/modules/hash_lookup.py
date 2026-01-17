"""Hash lookup OSINT module."""

from typing import Dict, Any
from ..core.base import OSINTBase, console
from ..core.utils import get_hash_type


class HashOSINT(OSINTBase):
    """Hash lookup module for malware/file analysis."""

    def get_module_name(self) -> str:
        return "Hash OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run hash lookup checks."""
        console.print(f"[cyan]Running Hash OSINT for: {target}[/cyan]")
        
        hash_type = get_hash_type(target)
        
        results = {
            "target": target,
            "hash_type": hash_type,
            "virustotal": self._virustotal_lookup(target),
            "malware_bazaar": self._malware_bazaar_lookup(target),
            "hybrid_analysis": self._hybrid_analysis_lookup(target),
            "hashcat_mode": self._get_hashcat_mode(hash_type),
        }
        
        return results

    def _virustotal_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Lookup hash on VirusTotal."""
        api_key = self.config.get("api_keys", {}).get("virustotal")
        
        if not api_key:
            return {"note": "VirusTotal API key not configured"}
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": api_key}
        
        response = self._make_request(url, headers=headers, delay=15)
        
        if response:
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            stats = attributes.get("last_analysis_stats", {})
            
            return {
                "found": True,
                "sha256": attributes.get("sha256"),
                "sha1": attributes.get("sha1"),
                "md5": attributes.get("md5"),
                "file_type": attributes.get("type_description"),
                "file_size": attributes.get("size"),
                "file_names": attributes.get("names", [])[:5],
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "reputation": attributes.get("reputation"),
                "tags": attributes.get("tags", []),
            }
        
        return {"found": False}

    def _malware_bazaar_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Lookup hash on MalwareBazaar."""
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {
            "query": "get_info",
            "hash": file_hash
        }
        
        response = self._make_request(url, method="POST", data=data)
        
        if response:
            result = response.json()
            
            if result.get("query_status") == "ok":
                sample = result.get("data", [{}])[0]
                return {
                    "found": True,
                    "sha256": sample.get("sha256_hash"),
                    "sha1": sample.get("sha1_hash"),
                    "md5": sample.get("md5_hash"),
                    "file_type": sample.get("file_type"),
                    "file_type_mime": sample.get("file_type_mime"),
                    "file_size": sample.get("file_size"),
                    "signature": sample.get("signature"),
                    "first_seen": sample.get("first_seen"),
                    "last_seen": sample.get("last_seen"),
                    "file_name": sample.get("file_name"),
                    "intelligence": sample.get("intelligence", {}),
                    "tags": sample.get("tags", []),
                }
            
            return {"found": False, "status": result.get("query_status")}
        
        return {"error": "Lookup failed"}

    def _hybrid_analysis_lookup(self, file_hash: str) -> Dict[str, Any]:
        """Lookup hash on Hybrid Analysis."""
        # Hybrid Analysis API requires registration
        api_key = self.config.get("api_keys", {}).get("hybrid_analysis")
        
        if not api_key:
            # Return link for manual lookup
            return {
                "manual_lookup": f"https://www.hybrid-analysis.com/search?query={file_hash}",
                "note": "API key not configured"
            }
        
        url = f"https://www.hybrid-analysis.com/api/v2/search/hash"
        headers = {
            "api-key": api_key,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"hash": file_hash}
        
        response = self._make_request(
            url,
            method="POST",
            data=data,
            headers=headers
        )
        
        if response:
            return response.json()
        
        return {"error": "Lookup failed"}

    def _get_hashcat_mode(self, hash_type: str) -> Dict[str, Any]:
        """Get hashcat mode for the hash type."""
        modes = {
            "MD5": {"mode": 0, "example": "hashcat -m 0 hash.txt wordlist.txt"},
            "SHA1": {"mode": 100, "example": "hashcat -m 100 hash.txt wordlist.txt"},
            "SHA256": {"mode": 1400, "example": "hashcat -m 1400 hash.txt wordlist.txt"},
        }
        
        return modes.get(hash_type, {"note": "Unknown hash type"})