import asyncio
import httpx
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from .parsers import parse_php_version, evaluate_vulnerability, detect_waf

class AsyncScannerEngine:
    def __init__(self, targets: list[str], concurrency: int = 25, timeout: int = 5):
        self.targets = targets
        self.semaphore = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def scan_single_target(self, client: httpx.AsyncClient, url: str, progress, task_id) -> dict:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        result = {
            "url": url,
            "is_php": False,
            "version": "None",
            "status": "Clear",
            "waf": "None",
            "notes": "No footprint detected."
        }

        async with self.semaphore:
            try:
                response = await client.head(url, timeout=self.timeout, follow_redirects=True)
                
                # Check for active WAF interference
                detected_waf = detect_waf(response.headers)
                if detected_waf:
                    result["waf"] = detected_waf

                # Check for cookies indicating a hidden PHP architecture
                if "PHPSESSID" in response.cookies or "laravel_session" in response.cookies:
                    result["is_php"] = True
                    result["notes"] = "Hidden PHP instance (Session cookie drop)."

                server_h = response.headers.get("Server", "")
                powered_h = response.headers.get("X-Powered-By", "")
                combined = f"{server_h} {powered_h}"

                version = parse_php_version(combined)
                if version:
                    result["is_php"] = True
                    result["version"] = version
                    status, note = evaluate_vulnerability(version)
                    result["status"] = status
                    result["notes"] = note
                elif result["is_php"]:
                    result["status"] = "Mitigated/Hidden" if detected_waf else "Review Required"
                    result["notes"] = f"PHP detected but backend version string stripped. Protected by {detected_waf}." if detected_waf else "PHP active but headers masked."

            except httpx.RequestError:
                result["status"] = "Unreachable"
                result["notes"] = "Target failed to respond to network request."
            
            finally:
                progress.advance(task_id)
            
            return result

    # Ensure this function is aligned EXACTLY with 'async def scan_single_target' above!
    async def run(self) -> list[dict]:
        limits = httpx.Limits(max_keepalive_connections=10, max_connections=100)
        
        with Progress(
            SpinnerColumn(spinner_name="dots"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
        ) as progress:
            
            task_id = progress.add_task("[cyan]Auditing target vectors...", total=len(self.targets))
            
            async with httpx.AsyncClient(limits=limits, verify=False, follow_redirects=True) as client:
                tasks = [self.scan_single_target(client, url, progress, task_id) for url in self.targets]
                return await asyncio.gather(*tasks)