"""Base class for OSINT modules."""

import requests
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import time
from rich.console import Console

console = Console()


class OSINTBase(ABC):
    """Base class for all OSINT modules."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": config.get("settings", {}).get(
                "user_agent", "OSINT-CLI/1.0"
            )
        })
        self.timeout = config.get("settings", {}).get("timeout", 30)
        self.last_request_time = 0

    def _rate_limit(self, delay: float = 1.0):
        """Implement rate limiting between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self.last_request_time = time.time()

    def _make_request(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        delay: float = 1.0
    ) -> Optional[requests.Response]:
        """Make an HTTP request with error handling."""
        self._rate_limit(delay)
        
        try:
            if method.upper() == "GET":
                response = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=self.timeout
                )
            elif method.upper() == "POST":
                response = self.session.post(
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    timeout=self.timeout
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")

            response.raise_for_status()
            return response

        except requests.exceptions.Timeout:
            console.print(f"[red]Request timeout for {url}[/red]")
        except requests.exceptions.HTTPError as e:
            console.print(f"[red]HTTP error: {e}[/red]")
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Request error: {e}[/red]")
        
        return None

    @abstractmethod
    def run(self, target: str) -> Dict[str, Any]:
        """Run the OSINT module against the target."""
        pass

    @abstractmethod
    def get_module_name(self) -> str:
        """Return the module name."""
        pass