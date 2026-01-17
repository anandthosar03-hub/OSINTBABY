"""Username OSINT module."""

import asyncio
import aiohttp
from typing import Dict, Any, List
from ..core.base import OSINTBase, console


class UsernameOSINT(OSINTBase):
    """Username reconnaissance module (similar to Sherlock)."""

    # Sites to check
    SITES = {
        "GitHub": {
            "url": "https://github.com/{username}",
            "error_type": "status_code"
        },
        "Twitter": {
            "url": "https://twitter.com/{username}",
            "error_type": "status_code"
        },
        "Instagram": {
            "url": "https://www.instagram.com/{username}/",
            "error_type": "status_code"
        },
        "Reddit": {
            "url": "https://www.reddit.com/user/{username}",
            "error_type": "status_code"
        },
        "Pinterest": {
            "url": "https://www.pinterest.com/{username}/",
            "error_type": "status_code"
        },
        "TikTok": {
            "url": "https://www.tiktok.com/@{username}",
            "error_type": "status_code"
        },
        "YouTube": {
            "url": "https://www.youtube.com/@{username}",
            "error_type": "status_code"
        },
        "Twitch": {
            "url": "https://www.twitch.tv/{username}",
            "error_type": "status_code"
        },
        "Steam": {
            "url": "https://steamcommunity.com/id/{username}",
            "error_type": "status_code"
        },
        "Spotify": {
            "url": "https://open.spotify.com/user/{username}",
            "error_type": "status_code"
        },
        "Medium": {
            "url": "https://medium.com/@{username}",
            "error_type": "status_code"
        },
        "DeviantArt": {
            "url": "https://www.deviantart.com/{username}",
            "error_type": "status_code"
        },
        "Flickr": {
            "url": "https://www.flickr.com/people/{username}",
            "error_type": "status_code"
        },
        "Vimeo": {
            "url": "https://vimeo.com/{username}",
            "error_type": "status_code"
        },
        "SoundCloud": {
            "url": "https://soundcloud.com/{username}",
            "error_type": "status_code"
        },
        "Behance": {
            "url": "https://www.behance.net/{username}",
            "error_type": "status_code"
        },
        "Dribbble": {
            "url": "https://dribbble.com/{username}",
            "error_type": "status_code"
        },
        "GitLab": {
            "url": "https://gitlab.com/{username}",
            "error_type": "status_code"
        },
        "Bitbucket": {
            "url": "https://bitbucket.org/{username}/",
            "error_type": "status_code"
        },
        "HackerNews": {
            "url": "https://news.ycombinator.com/user?id={username}",
            "error_type": "message",
            "error_msg": "No such user"
        },
        "Keybase": {
            "url": "https://keybase.io/{username}",
            "error_type": "status_code"
        },
        "Patreon": {
            "url": "https://www.patreon.com/{username}",
            "error_type": "status_code"
        },
        "ProductHunt": {
            "url": "https://www.producthunt.com/@{username}",
            "error_type": "status_code"
        },
        "Telegram": {
            "url": "https://t.me/{username}",
            "error_type": "status_code"
        },
        "Docker Hub": {
            "url": "https://hub.docker.com/u/{username}",
            "error_type": "status_code"
        },
        "npm": {
            "url": "https://www.npmjs.com/~{username}",
            "error_type": "status_code"
        },
        "PyPI": {
            "url": "https://pypi.org/user/{username}/",
            "error_type": "status_code"
        },
        "Trello": {
            "url": "https://trello.com/{username}",
            "error_type": "status_code"
        },
        "Gravatar": {
            "url": "https://gravatar.com/{username}",
            "error_type": "status_code"
        },
    }

    def get_module_name(self) -> str:
        return "Username OSINT"

    def run(self, target: str) -> Dict[str, Any]:
        """Run username enumeration."""
        console.print(f"[cyan]Running Username OSINT for: {target}[/cyan]")
        console.print(f"[yellow]Checking {len(self.SITES)} sites...[/yellow]")
        
        # Run async checks
        results = asyncio.run(self._check_all_sites(target))
        
        found_profiles = [r for r in results if r["status"] == "Found"]
        
        return {
            "target": target,
            "total_sites_checked": len(self.SITES),
            "profiles_found": len(found_profiles),
            "results": results
        }

    async def _check_all_sites(self, username: str) -> List[Dict[str, Any]]:
        """Check all sites asynchronously."""
        async with aiohttp.ClientSession() as session:
            tasks = []
            for site_name, site_info in self.SITES.items():
                task = self._check_site(session, username, site_name, site_info)
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            return [r for r in results if isinstance(r, dict)]

    async def _check_site(
        self,
        session: aiohttp.ClientSession,
        username: str,
        site_name: str,
        site_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Check a single site for username."""
        url = site_info["url"].format(username=username)
        
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=10),
                allow_redirects=True,
                headers={"User-Agent": "OSINT-CLI/1.0"}
            ) as response:
                
                error_type = site_info.get("error_type", "status_code")
                
                if error_type == "status_code":
                    found = response.status == 200
                elif error_type == "message":
                    text = await response.text()
                    error_msg = site_info.get("error_msg", "")
                    found = error_msg not in text and response.status == 200
                else:
                    found = response.status == 200
                
                return {
                    "site": site_name,
                    "url": url,
                    "status": "Found" if found else "Not Found",
                    "http_status": response.status
                }
                
        except asyncio.TimeoutError:
            return {
                "site": site_name,
                "url": url,
                "status": "Timeout",
                "http_status": None
            }
        except Exception as e:
            return {
                "site": site_name,
                "url": url,
                "status": "Error",
                "http_status": None,
                "error": str(e)
            }