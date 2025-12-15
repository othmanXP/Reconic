import asyncio
import aiohttp
import json
import sys
import os
import re
import ssl
import time
import logging
import hashlib
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple, Any
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from datetime import datetime
from dataclasses import dataclass, asdict, field
from collections import defaultdict, deque

try:
    import tldextract
    from bs4 import BeautifulSoup
    import dns.asyncresolver
    from colorama import Fore, Style, init
    import aiofiles
    import yaml
    import requests
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Install: pip install aiohttp aiofiles tldextract beautifulsoup4 dnspython colorama PyYAML requests")
    sys.exit(1)

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reconic.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class ScanConfig:
    """Scanner configuration"""
    target_url: str
    timeout: int = 20
    concurrency: int = 100
    max_depth: int = 3
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Proxy support
    proxy: Optional[str] = None
    tor: bool = False
    
    # Authentication
    auth_cookie: Optional[str] = None
    auth_header: Optional[str] = None
    
    # Feature flags
    use_subfinder: bool = True
    use_amass: bool = False  # Slower but more thorough
    use_katana: bool = True
    use_nuclei: bool = True
    use_httpx: bool = True
    use_playwright: bool = False  # Fallback for heavy JS
    
    takeover_check: bool = True
    
    # Paths
    output_dir: Path = Path('./reconic_output')
    wordlist_dir: Path = Path('./wordlists')
    nuclei_templates: Optional[Path] = None
    
    # Tool configuration
    tools: 'ToolConfig' = field(default_factory=lambda: ToolConfig())


# ============================================================================
# INTERACTIVE MODE
# ============================================================================

class InteractiveMode:
    """Interactive mode for granular control"""
    
    def __init__(self, config: ScanConfig, tools: 'ToolConfig'):
        self.config = config
        self.tools = tools
        self.selected_subdomains: List[str] = []
        self.selected_tests: Set[str] = set()
    
    async def run(self):
        """Run interactive mode"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}INTERACTIVE MODE{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        # Step 1: Get target
        target = input(f"{Fore.CYAN}Enter target domain (e.g., example.com):{Style.RESET_ALL} ").strip()
        if not target:
            print(f"{Fore.RED}[!] Target required{Style.RESET_ALL}")
            return
        
        self.config.target_url = f"https://{target}" if not target.startswith('http') else target
        domain_obj = tldextract.extract(self.config.target_url)
        base_domain = f"{domain_obj.domain}.{domain_obj.suffix}"
        
        # Step 2: Subdomain enumeration
        print(f"\n{Fore.YELLOW}[*] Step 1: Subdomain Enumeration{Style.RESET_ALL}\n")
        
        enum_choice = self._menu(
            "Choose subdomain enumeration method:",
            [
                "Run Subfinder (fast, recommended)",
                "Run Amass (slow, thorough)",
                "Both Subfinder + Amass",
                "Provide custom subdomain list",
                "Skip (provide full URLs later)"
            ]
        )
        
        discovered_subdomains = []
        
        if enum_choice == 1 and self.tools.subfinder:
            print(f"\n{Fore.CYAN}Running Subfinder...{Style.RESET_ALL}")
            subfinder = SubfinderEnum(self.config)
            discovered_subdomains = await subfinder.enumerate(base_domain)
            print(f"{Fore.GREEN}✓ Found {len(discovered_subdomains)} subdomains{Style.RESET_ALL}")
        
        elif enum_choice == 2 and self.tools.amass:
            print(f"\n{Fore.CYAN}Running Amass (this will take 10-20 minutes)...{Style.RESET_ALL}")
            amass = AmassEnum(self.config)
            discovered_subdomains = await amass.enumerate(base_domain)
            print(f"{Fore.GREEN}✓ Found {len(discovered_subdomains)} subdomains{Style.RESET_ALL}")
        
        elif enum_choice == 3:
            if self.tools.subfinder:
                print(f"\n{Fore.CYAN}Running Subfinder...{Style.RESET_ALL}")
                subfinder = SubfinderEnum(self.config)
                subs1 = await subfinder.enumerate(base_domain)
                discovered_subdomains.extend(subs1)
            
            if self.tools.amass:
                print(f"\n{Fore.CYAN}Running Amass...{Style.RESET_ALL}")
                amass = AmassEnum(self.config)
                subs2 = await amass.enumerate(base_domain)
                discovered_subdomains.extend(subs2)
            
            discovered_subdomains = list(set(discovered_subdomains))
            print(f"{Fore.GREEN}✓ Found {len(discovered_subdomains)} unique subdomains{Style.RESET_ALL}")
        
        elif enum_choice == 4:
            print(f"\n{Fore.YELLOW}Paste subdomains (one per line, press Ctrl+D when done):{Style.RESET_ALL}")
            print(f"{Fore.CYAN}Example:")
            print(f"  www.example.com")
            print(f"  api.example.com")
            print(f"  staging.example.com{Style.RESET_ALL}\n")
            
            try:
                while True:
                    line = input().strip()
                    if line:
                        discovered_subdomains.append(line)
            except EOFError:
                pass
            
            print(f"\n{Fore.GREEN}✓ Loaded {len(discovered_subdomains)} subdomains{Style.RESET_ALL}")
        
        # Step 3: Select subdomains to test
        if discovered_subdomains:
            print(f"\n{Fore.YELLOW}[*] Step 2: Select Subdomains to Test{Style.RESET_ALL}\n")
            
            # Show first 20
            print(f"{Fore.CYAN}Discovered subdomains (showing first 20):{Style.RESET_ALL}")
            for i, sub in enumerate(discovered_subdomains[:20], 1):
                print(f"  {i}. {sub}")
            
            if len(discovered_subdomains) > 20:
                print(f"  ... and {len(discovered_subdomains) - 20} more")
            
            print()
            select_choice = self._menu(
                "How do you want to select subdomains?",
                [
                    "Test all discovered subdomains",
                    "Test first 10 subdomains only",
                    "Select specific subdomains by number",
                    "Filter by keyword (e.g., 'api', 'admin', 'staging')"
                ]
            )
            
            if select_choice == 1:
                self.selected_subdomains = discovered_subdomains
            elif select_choice == 2:
                self.selected_subdomains = discovered_subdomains[:10]
            elif select_choice == 3:
                print(f"\n{Fore.YELLOW}Enter subdomain numbers (comma-separated, e.g., 1,3,5):{Style.RESET_ALL}")
                selection = input("> ").strip()
                try:
                    indices = [int(x.strip()) - 1 for x in selection.split(',')]
                    self.selected_subdomains = [discovered_subdomains[i] for i in indices if 0 <= i < len(discovered_subdomains)]
                except:
                    print(f"{Fore.RED}Invalid selection, using all{Style.RESET_ALL}")
                    self.selected_subdomains = discovered_subdomains
            elif select_choice == 4:
                keyword = input(f"\n{Fore.YELLOW}Enter keyword to filter:{Style.RESET_ALL} ").strip().lower()
                self.selected_subdomains = [s for s in discovered_subdomains if keyword in s.lower()]
                print(f"{Fore.GREEN}✓ Filtered to {len(self.selected_subdomains)} subdomains{Style.RESET_ALL}")
        else:
            # Manual URL entry
            print(f"\n{Fore.YELLOW}Enter full URLs to test (one per line, Ctrl+D when done):{Style.RESET_ALL}")
            urls = []
            try:
                while True:
                    line = input().strip()
                    if line:
                        urls.append(line)
            except EOFError:
                pass
            
            self.selected_subdomains = [urlparse(u).netloc for u in urls]
        
        if not self.selected_subdomains:
            print(f"{Fore.RED}[!] No subdomains selected{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}✓ Selected {len(self.selected_subdomains)} subdomains for testing{Style.RESET_ALL}")
        
        # Step 4: Select tests
        print(f"\n{Fore.YELLOW}[*] Step 3: Select Tests to Run{Style.RESET_ALL}\n")
        
        available_tests = [
            ("alive", "Alive Host Verification (httpx)", self.tools.httpx),
            ("crawl", "Endpoint Discovery (Katana)", self.tools.katana),
            ("takeover", "Subdomain Takeover Detection", True),
            ("nuclei", "Vulnerability Scanning (Nuclei)", self.tools.nuclei),
            ("playwright", "Deep JS Crawling (Playwright)", self.tools.playwright_available)
        ]
        
        print(f"{Fore.CYAN}Available tests:{Style.RESET_ALL}")
        for i, (key, name, available) in enumerate(available_tests, 1):
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if available else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {i}. {status} {name}")
        
        print(f"\n{Fore.YELLOW}Select tests to run:{Style.RESET_ALL}")
        print(f"  a) All available tests")
        print(f"  Enter numbers separated by commas (e.g., 1,2,4)")
        
        choice = input("> ").strip().lower()
        
        if choice == 'a':
            self.selected_tests = {key for key, _, available in available_tests if available}
        else:
            try:
                indices = [int(x.strip()) for x in choice.split(',')]
                self.selected_tests = {available_tests[i-1][0] for i in indices 
                                      if 1 <= i <= len(available_tests) and available_tests[i-1][2]}
            except:
                print(f"{Fore.RED}Invalid selection, running all available tests{Style.RESET_ALL}")
                self.selected_tests = {key for key, _, available in available_tests if available}
        
        # Step 5: Configuration
        print(f"\n{Fore.YELLOW}[*] Step 4: Additional Configuration{Style.RESET_ALL}\n")
        
        if self._yes_no("Enable proxy/TOR?"):
            proxy_choice = self._menu(
                "Proxy type:",
                ["Custom HTTP/SOCKS proxy", "TOR (127.0.0.1:9050)"]
            )
            
            if proxy_choice == 1:
                self.config.proxy = input(f"{Fore.YELLOW}Enter proxy URL:{Style.RESET_ALL} ").strip()
            else:
                self.config.proxy = 'socks5://127.0.0.1:9050'
                self.config.tor = True
        
        if self._yes_no("Add authentication?"):
            auth_choice = self._menu(
                "Authentication method:",
                ["Cookie", "Authorization header", "Both"]
            )
            
            if auth_choice in [1, 3]:
                self.config.auth_cookie = input(f"{Fore.YELLOW}Enter cookie:{Style.RESET_ALL} ").strip()
            
            if auth_choice in [2, 3]:
                self.config.auth_header = input(f"{Fore.YELLOW}Enter authorization header:{Style.RESET_ALL} ").strip()
        
        # Step 6: Execute
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}SCAN CONFIGURATION{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"Target: {self.config.target_url}")
        print(f"Subdomains: {len(self.selected_subdomains)}")
        print(f"Tests: {', '.join(self.selected_tests)}")
        if self.config.proxy:
            print(f"Proxy: {self.config.proxy}")
        if self.config.auth_cookie:
            print(f"Auth: Cookie configured")
        
        print()
        if not self._yes_no("Proceed with scan?"):
            print(f"{Fore.YELLOW}Scan cancelled{Style.RESET_ALL}")
            return
        
        # Execute scan
        await self._execute_scan()
    
    def _menu(self, prompt: str, options: List[str]) -> int:
        """Display menu and get selection"""
        print(f"{Fore.CYAN}{prompt}{Style.RESET_ALL}")
        for i, option in enumerate(options, 1):
            print(f"  {i}) {option}")
        
        while True:
            try:
                choice = int(input(f"{Fore.YELLOW}Select [1-{len(options)}]:{Style.RESET_ALL} ").strip())
                if 1 <= choice <= len(options):
                    return choice
            except (ValueError, KeyboardInterrupt):
                pass
            print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")
    
    def _yes_no(self, prompt: str) -> bool:
        """Yes/No prompt"""
        while True:
            response = input(f"{Fore.YELLOW}{prompt} (y/n):{Style.RESET_ALL} ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
    
    async def _execute_scan(self):
        """Execute selected tests"""
        print(f"\n{Fore.CYAN}[*] Starting Scan{Style.RESET_ALL}\n")
        
        results = {
            'target': self.config.target_url,
            'scan_date': datetime.now().isoformat(),
            'mode': 'interactive',
            'subdomains': self.selected_subdomains,
            'tests_run': list(self.selected_tests),
            'alive_hosts': [],
            'endpoints': [],
            'takeovers': [],
            'nuclei_results': None
        }
        
        try:
            # Alive host verification
            if 'alive' in self.selected_tests:
                print(f"{Fore.CYAN}[*] Running alive host verification...{Style.RESET_ALL}")
                httpx_prober = HttpxProber(self.config)
                results['alive_hosts'] = await httpx_prober.probe(self.selected_subdomains)
                print(f"{Fore.GREEN}✓ Found {len(results['alive_hosts'])} alive hosts{Style.RESET_ALL}")
            else:
                results['alive_hosts'] = [{'url': f"https://{s}", 'host': s} for s in self.selected_subdomains]
            
            # Takeover detection
            if 'takeover' in self.selected_tests:
                print(f"\n{Fore.CYAN}[*] Checking for subdomain takeovers...{Style.RESET_ALL}")
                results['takeovers'] = await TakeoverDetector.scan_subdomains(self.selected_subdomains)
                
                if results['takeovers']:
                    print(f"{Fore.RED}⚠ Found {len(results['takeovers'])} potential takeovers!{Style.RESET_ALL}")
                    for t in results['takeovers']:
                        print(f"  {t['subdomain']} -> {t['cname']} ({t['service']})")
                else:
                    print(f"{Fore.GREEN}✓ No takeovers detected{Style.RESET_ALL}")
            
            # Endpoint discovery
            if 'crawl' in self.selected_tests:
                print(f"\n{Fore.CYAN}[*] Discovering endpoints...{Style.RESET_ALL}")
                base_urls = [h['url'] for h in results['alive_hosts'][:50]]
                
                katana = KatanaCrawler(self.config)
                results['endpoints'] = await katana.crawl(base_urls)
                print(f"{Fore.GREEN}✓ Discovered {len(results['endpoints'])} endpoints{Style.RESET_ALL}")
            
            # Playwright deep crawl
            if 'playwright' in self.selected_tests:
                print(f"\n{Fore.CYAN}[*] Deep JS crawling with Playwright...{Style.RESET_ALL}")
                playwright = PlaywrightCrawler(self.config)
                if await playwright.initialize():
                    base_urls = [h['url'] for h in results['alive_hosts'][:10]]
                    all_endpoints = []
                    for url in base_urls:
                        eps, _ = await playwright.crawl_url(url)
                        all_endpoints.extend(eps)
                    results['endpoints'].extend(all_endpoints)
                    results['endpoints'] = list(set(results['endpoints']))
                    await playwright.close()
                    print(f"{Fore.GREEN}✓ Total endpoints: {len(results['endpoints'])}{Style.RESET_ALL}")
            
            # Nuclei scanning
            if 'nuclei' in self.selected_tests:
                print(f"\n{Fore.CYAN}[*] Running Nuclei vulnerability scan...{Style.RESET_ALL}")
                nuclei = NucleiScanner(self.config)
                await nuclei.update_templates()
                
                all_targets = [h['url'] for h in results['alive_hosts']] + results['endpoints']
                nuclei_output = await nuclei.scan(list(set(all_targets)))
                
                if nuclei_output:
                    results['nuclei_results'] = str(nuclei_output)
                    try:
                        with open(nuclei_output) as f:
                            findings = [json.loads(line) for line in f if line.strip()]
                        print(f"{Fore.GREEN}✓ Nuclei found {len(findings)} vulnerabilities{Style.RESET_ALL}")
                        
                        by_severity = defaultdict(int)
                        for finding in findings:
                            severity = finding.get('info', {}).get('severity', 'unknown')
                            by_severity[severity] += 1
                        
                        for severity, count in by_severity.items():
                            color = {'critical': Fore.RED, 'high': Fore.MAGENTA, 
                                   'medium': Fore.YELLOW, 'low': Fore.BLUE}.get(severity, Fore.WHITE)
                            print(f"  {color}{severity.capitalize()}: {count}{Style.RESET_ALL}")
                    except:
                        pass
            
            # Save results
            print(f"\n{Fore.CYAN}[*] Saving results...{Style.RESET_ALL}")
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = self.config.output_dir / f"interactive_scan_{timestamp}.json"
            
            async with aiofiles.open(output_file, 'w') as f:
                await f.write(json.dumps(results, indent=2, default=str))
            
            print(f"{Fore.GREEN}✓ Results saved to: {output_file}{Style.RESET_ALL}")
            
            # Summary
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}SCAN COMPLETE{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
            
            print(f"Subdomains tested: {len(self.selected_subdomains)}")
            print(f"Alive hosts: {len(results['alive_hosts'])}")
            print(f"Endpoints: {len(results['endpoints'])}")
            print(f"Takeovers: {Fore.RED if results['takeovers'] else Fore.GREEN}{len(results['takeovers'])}{Style.RESET_ALL}")
            
            if results['nuclei_results']:
                print(f"Nuclei: {Fore.GREEN}Scan complete{Style.RESET_ALL}")
            
            print(f"\nOutput: {output_file}")
            print()
        
        except Exception as e:
            logger.error(f"Scan error: {e}", exc_info=True)
            print(f"\n{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")



# ============================================================================
# TOOL DETECTION & CONFIGURATION
# ============================================================================

@dataclass
class ToolConfig:
    """Configuration for external tools"""
    subfinder: Optional[str] = None
    amass: Optional[str] = None
    katana: Optional[str] = None
    nuclei: Optional[str] = None
    httpx: Optional[str] = None
    playwright_available: bool = False
    
    def __post_init__(self):
        """Auto-detect installed tools"""
        self.subfinder = shutil.which('subfinder')
        self.amass = shutil.which('amass')
        self.katana = shutil.which('katana')
        self.nuclei = shutil.which('nuclei')
        self.httpx = shutil.which('httpx')
        
        # Check Playwright
        try:
            from playwright.async_api import async_playwright
            self.playwright_available = True
        except ImportError:
            self.playwright_available = False
    
    def get_summary(self) -> Dict[str, bool]:
        """Get tool availability summary"""
        return {
            'subfinder': self.subfinder is not None,
            'amass': self.amass is not None,
            'katana': self.katana is not None,
            'nuclei': self.nuclei is not None,
            'httpx': self.httpx is not None,
            'playwright': self.playwright_available
        }
    
    def print_status(self):
        """Print tool availability status"""
        print(f"\n{Fore.CYAN}[*] Tool Detection:{Style.RESET_ALL}")
        
        tools = [
            ('Subfinder', self.subfinder, 'RECOMMENDED - Fast subdomain enumeration'),
            ('Amass', self.amass, 'OPTIONAL - Deep subdomain enumeration (slower)'),
            ('Katana', self.katana, 'RECOMMENDED - JS-aware crawling'),
            ('Nuclei', self.nuclei, 'REQUIRED - Vulnerability scanning'),
            ('httpx', self.httpx, 'RECOMMENDED - Alive host verification'),
            ('Playwright', self.playwright_available, 'OPTIONAL - Heavy JS sites fallback')
        ]
        
        for name, status, desc in tools:
            if status:
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {name:12} - {desc}")
            else:
                print(f"  {Fore.YELLOW}✗{Style.RESET_ALL} {name:12} - {desc}")
        
        if not self.nuclei:
            print(f"\n{Fore.RED}[!] Nuclei is required for vulnerability scanning{Style.RESET_ALL}")
            print(f"    Install: go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")


@dataclass
class ScanConfig:
    """Scanner configuration"""
    target_url: str
    timeout: int = 20
    concurrency: int = 100
    max_depth: int = 3
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Proxy support
    proxy: Optional[str] = None
    tor: bool = False
    
    # Authentication
    auth_cookie: Optional[str] = None
    auth_header: Optional[str] = None
    
    # Feature flags
    use_subfinder: bool = True
    use_amass: bool = False  # Slower but more thorough
    use_katana: bool = True
    use_nuclei: bool = True
    use_httpx: bool = True
    use_playwright: bool = False  # Fallback for heavy JS
    
    takeover_check: bool = True
    
    # Paths
    output_dir: Path = Path('./reconic_output')
    wordlist_dir: Path = Path('./wordlists')
    nuclei_templates: Optional[Path] = None
    
    # Tool configuration
    tools: ToolConfig = field(default_factory=ToolConfig)


# ============================================================================
# SUBFINDER INTEGRATION
# ============================================================================

class SubfinderEnum:
    """Subfinder integration for fast subdomain enumeration"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.subfinder_path = config.tools.subfinder
    
    async def enumerate(self, domain: str) -> List[str]:
        """Run Subfinder for subdomain enumeration"""
        if not self.subfinder_path:
            logger.warning("Subfinder not available")
            return []
        
        logger.info(f"Running Subfinder on {domain}...")
        
        output_file = self.config.output_dir / f'subfinder_{domain}.txt'
        
        cmd = [
            self.subfinder_path,
            '-d', domain,
            '-o', str(output_file),
            '-all',  # Use all sources
            '-silent',
            '-t', '100',  # 100 threads
        ]
        
        # Add proxy if configured
        if self.config.proxy:
            cmd.extend(['-proxy', self.config.proxy])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if output_file.exists():
                subdomains = output_file.read_text().splitlines()
                logger.info(f"Subfinder found {len(subdomains)} subdomains")
                return subdomains
            
        except Exception as e:
            logger.error(f"Subfinder error: {e}")
        
        return []


# ============================================================================
# AMASS INTEGRATION (OPTIONAL)
# ============================================================================

class AmassEnum:
    """Amass integration for deep subdomain enumeration"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.amass_path = config.tools.amass
    
    async def enumerate(self, domain: str) -> List[str]:
        """Run Amass for deep enumeration (slower but thorough)"""
        if not self.amass_path:
            logger.warning("Amass not available")
            return []
        
        logger.info(f"Running Amass on {domain} (this may take 10-20 minutes)...")
        
        output_file = self.config.output_dir / f'amass_{domain}.txt'
        
        cmd = [
            self.amass_path,
            'enum',
            '-d', domain,
            '-o', str(output_file),
            '-passive',  # Passive mode for speed
        ]
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Amass can take a long time
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=1200)  # 20 min timeout
            
            if output_file.exists():
                subdomains = output_file.read_text().splitlines()
                logger.info(f"Amass found {len(subdomains)} subdomains")
                return subdomains
            
        except asyncio.TimeoutError:
            logger.warning("Amass timeout - using partial results")
            if output_file.exists():
                return output_file.read_text().splitlines()
        except Exception as e:
            logger.error(f"Amass error: {e}")
        
        return []


# ============================================================================
# HTTPX INTEGRATION (ALIVE HOST VERIFICATION)
# ============================================================================

class HttpxProber:
    """httpx integration for alive host verification"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.httpx_path = config.tools.httpx
    
    async def probe(self, hosts: List[str]) -> List[Dict]:
        """Probe hosts and return alive ones with metadata"""
        if not self.httpx_path:
            logger.warning("httpx not available, using basic probing")
            return await self._basic_probe(hosts)
        
        logger.info(f"Probing {len(hosts)} hosts with httpx...")
        
        # Write hosts to file
        hosts_file = self.config.output_dir / 'httpx_input.txt'
        async with aiofiles.open(hosts_file, 'w') as f:
            await f.write('\n'.join(hosts))
        
        output_file = self.config.output_dir / 'httpx_output.json'
        
        cmd = [
            self.httpx_path,
            '-l', str(hosts_file),
            '-o', str(output_file),
            '-json',
            '-silent',
            '-threads', '100',
            '-timeout', '10',
            '-status-code',
            '-title',
            '-tech-detect',
            '-follow-redirects',
        ]
        
        # Add proxy if configured
        if self.config.proxy:
            cmd.extend(['-http-proxy', self.config.proxy])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await proc.communicate()
            
            if output_file.exists():
                results = []
                async with aiofiles.open(output_file, 'r') as f:
                    content = await f.read()
                    for line in content.splitlines():
                        if line.strip():
                            try:
                                results.append(json.loads(line))
                            except:
                                pass
                
                logger.info(f"httpx found {len(results)} alive hosts")
                return results
        
        except Exception as e:
            logger.error(f"httpx error: {e}")
        
        return []
    
    async def _basic_probe(self, hosts: List[str]) -> List[Dict]:
        """Fallback basic probing without httpx"""
        logger.info(f"Basic probing {len(hosts)} hosts...")
        alive = []
        
        async def check_host(host: str):
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{host}"
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                        async with session.head(url, allow_redirects=True) as resp:
                            if resp.status < 500:
                                return {
                                    'url': url,
                                    'host': host,
                                    'status_code': resp.status,
                                    'scheme': scheme
                                }
                except:
                    pass
            return None
        
        tasks = [check_host(h) for h in hosts]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        alive = [r for r in results if r and not isinstance(r, Exception)]
        logger.info(f"Found {len(alive)} alive hosts")
        return alive


# ============================================================================
# KATANA INTEGRATION (JS-AWARE CRAWLING)
# ============================================================================

class KatanaCrawler:
    """Katana integration for modern JS-aware crawling"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.katana_path = config.tools.katana
    
    async def crawl(self, urls: List[str]) -> List[str]:
        """Crawl URLs with Katana"""
        if not self.katana_path:
            logger.warning("Katana not available, using basic crawling")
            return []
        
        logger.info(f"Running Katana on {len(urls)} URLs...")
        
        # Write URLs to file
        urls_file = self.config.output_dir / 'katana_input.txt'
        async with aiofiles.open(urls_file, 'w') as f:
            await f.write('\n'.join(urls))
        
        output_file = self.config.output_dir / 'katana_output.txt'
        
        cmd = [
            self.katana_path,
            '-list', str(urls_file),
            '-output', str(output_file),
            '-silent',
            '-depth', str(self.config.max_depth),
            '-js-crawl',  # Enable JS crawling
            '-known-files', 'all',  # Find known files
            '-automatic-form-fill',  # Fill forms automatically
            '-headless',  # Use headless browser
            '-concurrency', '10',
        ]
        
        # Add proxy if configured
        if self.config.proxy:
            cmd.extend(['-proxy', self.config.proxy])
        
        # Add headers if auth configured
        if self.config.auth_cookie:
            cmd.extend(['-header', f'Cookie: {self.config.auth_cookie}'])
        if self.config.auth_header:
            cmd.extend(['-header', f'Authorization: {self.config.auth_header}'])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Katana can take time for JS-heavy sites
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)  # 10 min timeout
            
            if output_file.exists():
                endpoints = output_file.read_text().splitlines()
                unique_endpoints = list(set(endpoints))
                logger.info(f"Katana discovered {len(unique_endpoints)} endpoints")
                return unique_endpoints
        
        except asyncio.TimeoutError:
            logger.warning("Katana timeout - using partial results")
            if output_file.exists():
                return list(set(output_file.read_text().splitlines()))
        except Exception as e:
            logger.error(f"Katana error: {e}")
        
        return []


# ============================================================================
# PLAYWRIGHT FALLBACK (HEAVY JS SITES)
# ============================================================================

class PlaywrightCrawler:
    """Playwright fallback for extremely heavy JS sites"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.browser = None
    
    async def initialize(self):
        """Initialize Playwright browser"""
        if not self.config.tools.playwright_available:
            return False
        
        try:
            from playwright.async_api import async_playwright
            self.playwright = await async_playwright().start()
            self.browser = await self.playwright.chromium.launch(headless=True)
            logger.info("Playwright browser initialized")
            return True
        except Exception as e:
            logger.error(f"Playwright initialization failed: {e}")
            return False
    
    async def crawl_url(self, url: str) -> Tuple[List[str], List[str]]:
        """Crawl single URL with full JS rendering"""
        if not self.browser:
            return [], []
        
        endpoints = []
        api_calls = []
        
        try:
            page = await self.browser.new_page()
            
            # Intercept network requests
            async def handle_request(request):
                api_calls.append(request.url)
            
            page.on("request", handle_request)
            
            # Navigate and wait
            await page.goto(url, wait_until='networkidle', timeout=30000)
            
            # Extract all links
            links = await page.eval_on_selector_all('a[href]', 
                'elements => elements.map(el => el.href)')
            endpoints.extend(links)
            
            await page.close()
        
        except Exception as e:
            logger.debug(f"Playwright crawl error for {url}: {e}")
        
        return list(set(endpoints)), list(set(api_calls))
    
    async def close(self):
        """Close browser"""
        if self.browser:
            await self.browser.close()
            await self.playwright.stop()


# ============================================================================
# SUBDOMAIN TAKEOVER DETECTION
# ============================================================================

class TakeoverDetector:
    """Detect subdomain takeover vulnerabilities"""
    
    FINGERPRINTS = {
        'github.io': ['There isn\'t a GitHub Pages site here', 'For root URLs'],
        'herokuapp.com': ['No such app', 'herokucdn.com/error-pages'],
        'amazonaws.com': ['NoSuchBucket', 'The specified bucket does not exist'],
        'azurewebsites.net': ['404 Web Site not found', 'Error 404'],
        'cloudfront.net': ['The request could not be satisfied', 'ERROR: The request could not be satisfied'],
        'fastly.net': ['Fastly error: unknown domain'],
        'pantheonsite.io': ['404 error unknown site!'],
        'readme.io': ['Project doesnt exist... yet!'],
        'bitbucket.io': ['Repository not found'],
        'ghost.io': ['The thing you were looking for is no longer here'],
        'helpjuice.com': ['We could not find what you\'re looking for'],
        'helpscoutdocs.com': ['No settings were found for this company'],
        'cargo.site': ['If you\'re moving your domain away from Cargo'],
        'statuspage.io': ['You are being redirected'],
        'tumblr.com': ['Whatever you were looking for doesn\'t currently exist'],
        'wordpress.com': ['Do you want to register'],
        'unbounce.com': ['The requested URL was not found on this server'],
    }
    
    @staticmethod
    async def check_subdomain(subdomain: str) -> Optional[Dict]:
        """Check if subdomain is vulnerable to takeover"""
        try:
            answers = await dns.asyncresolver.resolve(subdomain, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            
            for service, fingerprints in TakeoverDetector.FINGERPRINTS.items():
                if service in cname:
                    try:
                        response = requests.get(f"http://{subdomain}", timeout=10, allow_redirects=True)
                        content = response.text
                        
                        for fingerprint in fingerprints:
                            if fingerprint.lower() in content.lower():
                                return {
                                    'subdomain': subdomain,
                                    'cname': cname,
                                    'service': service,
                                    'fingerprint': fingerprint,
                                    'status': response.status_code
                                }
                    except:
                        pass
        
        except (dns.asyncresolver.NXDOMAIN, dns.asyncresolver.NoAnswer):
            pass
        except Exception as e:
            logger.debug(f"Takeover check error for {subdomain}: {e}")
        
        return None
    
    @staticmethod
    async def scan_subdomains(subdomains: List[str]) -> List[Dict]:
        """Scan all subdomains for takeover vulnerabilities"""
        logger.info(f"Checking {len(subdomains)} subdomains for takeover...")
        
        results = await asyncio.gather(*[TakeoverDetector.check_subdomain(s) for s in subdomains], 
                                       return_exceptions=True)
        
        takeovers = [r for r in results if r and not isinstance(r, Exception)]
        
        if takeovers:
            logger.warning(f"Found {len(takeovers)} potential takeover vulnerabilities!")
        
        return takeovers


# ============================================================================
# NUCLEI INTEGRATION
# ============================================================================

class NucleiScanner:
    """Nuclei integration for vulnerability scanning"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.nuclei_path = config.tools.nuclei
    
    async def update_templates(self):
        """Update Nuclei templates"""
        if not self.nuclei_path:
            return
        
        logger.info("Updating Nuclei templates...")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.nuclei_path, '-update-templates', '-silent',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await proc.communicate()
            logger.info("Nuclei templates updated")
        except Exception as e:
            logger.error(f"Template update failed: {e}")
    
    async def scan(self, targets: List[str]) -> Optional[Path]:
        """Run Nuclei scan"""
        if not self.nuclei_path:
            logger.warning("Nuclei not available")
            return None
        
        targets_file = self.config.output_dir / 'nuclei_targets.txt'
        async with aiofiles.open(targets_file, 'w') as f:
            await f.write('\n'.join(targets[:2000]))  # Reasonable limit
        
        output_file = self.config.output_dir / 'nuclei_results.json'
        
        logger.info(f"Running Nuclei on {len(targets)} targets...")
        
        cmd = [
            self.nuclei_path,
            '-l', str(targets_file),
            '-o', str(output_file),
            '-json',
            '-silent',
            '-rate-limit', '150',
            '-c', '50',
            '-severity', 'critical,high,medium',
        ]
        
        if self.config.nuclei_templates and self.config.nuclei_templates.exists():
            cmd.extend(['-t', str(self.config.nuclei_templates)])
        
        if self.config.proxy:
            cmd.extend(['-proxy', self.config.proxy])
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await proc.communicate()
            
            if output_file.exists():
                logger.info(f"Nuclei scan complete")
                return output_file
        
        except Exception as e:
            logger.error(f"Nuclei error: {e}")
        
        return None


# ============================================================================
# MAIN SCANNER
# ============================================================================

class ReconicScanner:
    """Main reconnaissance orchestrator"""
    
    def __init__(self, config: ScanConfig):
        self.config = config
        self.domain = tldextract.extract(config.target_url)
        self.base_domain = f"{self.domain.domain}.{self.domain.suffix}"
        
        config.output_dir.mkdir(parents=True, exist_ok=True)
    
    async def run(self):
        """Execute full reconnaissance workflow"""
        logger.info(f"Starting Reconic v8.0: {self.config.target_url}")
        
        results = {
            'target': self.config.target_url,
            'scan_date': datetime.now().isoformat(),
            'tools_used': self.config.tools.get_summary(),
            'subdomains': [],
            'alive_hosts': [],
            'endpoints': [],
            'takeovers': [],
            'nuclei_results': None
        }
        
        try:
            # Phase 1: Subdomain Enumeration
            print(f"\n{Fore.CYAN}[*] Phase 1: Subdomain Enumeration{Style.RESET_ALL}")
            
            all_subdomains = set()
            
            if self.config.use_subfinder and self.config.tools.subfinder:
                subfinder = SubfinderEnum(self.config)
                subs = await subfinder.enumerate(self.base_domain)
                all_subdomains.update(subs)
                print(f"  {Fore.GREEN}✓ Subfinder: {len(subs)} subdomains{Style.RESET_ALL}")
            
            if self.config.use_amass and self.config.tools.amass:
                amass = AmassEnum(self.config)
                subs = await amass.enumerate(self.base_domain)
                all_subdomains.update(subs)
                print(f"  {Fore.GREEN}✓ Amass: {len(subs)} subdomains{Style.RESET_ALL}")
            
            results['subdomains'] = sorted(list(all_subdomains))
            print(f"{Fore.GREEN}Total unique subdomains: {len(all_subdomains)}{Style.RESET_ALL}")
            
            # Phase 2: Alive Host Verification
            print(f"\n{Fore.CYAN}[*] Phase 2: Alive Host Verification{Style.RESET_ALL}")
            
            if self.config.use_httpx and self.config.tools.httpx:
                httpx_prober = HttpxProber(self.config)
                alive = await httpx_prober.probe(list(all_subdomains))
                results['alive_hosts'] = alive
                print(f"{Fore.GREEN}✓ httpx: {len(alive)} alive hosts{Style.RESET_ALL}")
            else:
                results['alive_hosts'] = [{'url': f"https://{s}", 'host': s} for s in all_subdomains]
            
            # Phase 3: Subdomain Takeover Detection
            print(f"\n{Fore.CYAN}[*] Phase 3: Subdomain Takeover Detection{Style.RESET_ALL}")
            
            if self.config.takeover_check:
                takeovers = await TakeoverDetector.scan_subdomains(list(all_subdomains)[:200])
                results['takeovers'] = takeovers
                
                if takeovers:
                    print(f"{Fore.RED}⚠ Found {len(takeovers)} potential takeovers!{Style.RESET_ALL}")
                    for t in takeovers:
                        print(f"  {t['subdomain']} -> {t['cname']} ({t['service']})")
                else:
                    print(f"{Fore.GREEN}✓ No takeovers detected{Style.RESET_ALL}")
            
            # Phase 4: Crawling & Endpoint Discovery
            print(f"\n{Fore.CYAN}[*] Phase 4: Endpoint Discovery{Style.RESET_ALL}")
            
            base_urls = [h['url'] for h in results['alive_hosts'][:50]]  # Reasonable limit
            
            if self.config.use_katana and self.config.tools.katana:
                katana = KatanaCrawler(self.config)
                endpoints = await katana.crawl(base_urls)
                results['endpoints'] = endpoints
                print(f"{Fore.GREEN}✓ Katana: {len(endpoints)} endpoints{Style.RESET_ALL}")
            
            elif self.config.use_playwright and self.config.tools.playwright_available:
                print(f"{Fore.YELLOW}Using Playwright fallback (slower){Style.RESET_ALL}")
                playwright = PlaywrightCrawler(self.config)
                if await playwright.initialize():
                    all_endpoints = []
                    for url in base_urls[:10]:  # Limit for Playwright
                        eps, _ = await playwright.crawl_url(url)
                        all_endpoints.extend(eps)
                    await playwright.close()
                    results['endpoints'] = list(set(all_endpoints))
                    print(f"{Fore.GREEN}✓ Playwright: {len(results['endpoints'])} endpoints{Style.RESET_ALL}")
            
            # Phase 5: Nuclei Vulnerability Scanning
            print(f"\n{Fore.CYAN}[*] Phase 5: Nuclei Vulnerability Scanning{Style.RESET_ALL}")
            
            if self.config.use_nuclei and self.config.tools.nuclei:
                nuclei = NucleiScanner(self.config)
                await nuclei.update_templates()
                
                all_targets = base_urls + results['endpoints']
                nuclei_output = await nuclei.scan(list(set(all_targets)))
                
                if nuclei_output:
                    results['nuclei_results'] = str(nuclei_output)
                    try:
                        with open(nuclei_output) as f:
                            findings = [json.loads(line) for line in f if line.strip()]
                        print(f"{Fore.GREEN}✓ Nuclei: {len(findings)} vulnerabilities found{Style.RESET_ALL}")
                        
                        # Count by severity
                        by_severity = defaultdict(int)
                        for finding in findings:
                            severity = finding.get('info', {}).get('severity', 'unknown')
                            by_severity[severity] += 1
                        
                        for severity, count in by_severity.items():
                            color = {
                                'critical': Fore.RED,
                                'high': Fore.MAGENTA,
                                'medium': Fore.YELLOW,
                                'low': Fore.BLUE
                            }.get(severity, Fore.WHITE)
                            print(f"  {color}{severity.capitalize()}: {count}{Style.RESET_ALL}")
                    except Exception as e:
                        logger.debug(f"Error parsing Nuclei results: {e}")
            
            # Save Results
            print(f"\n{Fore.CYAN}[*] Saving Results{Style.RESET_ALL}")
            await self._save_results(results)
            
            print(f"\n{Fore.GREEN}✓ Reconnaissance complete!{Style.RESET_ALL}")
            self._print_summary(results)
        
        except KeyboardInterrupt:
            logger.warning("Scan interrupted")
            print(f"\n{Fore.YELLOW}[!] Scan cancelled{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=True)
            print(f"\n{Fore.RED}[!] Fatal error: {e}{Style.RESET_ALL}")
    
    async def _save_results(self, results: Dict):
        """Save results to JSON"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_file = self.config.output_dir / f"recon_{timestamp}.json"
        
        async with aiofiles.open(output_file, 'w') as f:
            await f.write(json.dumps(results, indent=2, default=str))
        
        logger.info(f"Results saved: {output_file}")
    
    def _print_summary(self, results: Dict):
        """Print comprehensive summary"""
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}RECONNAISSANCE SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
        
        print(f"{Fore.CYAN}Assets Discovered:{Style.RESET_ALL}")
        print(f"  Subdomains: {len(results['subdomains'])}")
        print(f"  Alive hosts: {len(results['alive_hosts'])}")
        print(f"  Endpoints: {len(results['endpoints'])}")
        
        print(f"\n{Fore.CYAN}Security Findings:{Style.RESET_ALL}")
        print(f"  Takeovers: {Fore.RED if results['takeovers'] else Fore.GREEN}{len(results['takeovers'])}{Style.RESET_ALL}")
        
        if results['nuclei_results']:
            print(f"  Nuclei scan: {Fore.GREEN}Complete{Style.RESET_ALL}")
        else:
            print(f"  Nuclei scan: {Fore.YELLOW}Skipped{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}Tools Used:{Style.RESET_ALL}")
        for tool, used in results['tools_used'].items():
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if used else f"{Fore.YELLOW}✗{Style.RESET_ALL}"
            print(f"  {status} {tool}")
        
        print(f"\n{Fore.YELLOW}Next Steps:{Style.RESET_ALL}")
        print(f"1. Review takeovers (if any) - submit immediately")
        print(f"2. Review Nuclei findings in: {self.config.output_dir}/nuclei_results.json")
        print(f"3. Import endpoints into Burp Suite for manual testing")
        print(f"4. Run deeper scans with FFUF/Feroxbuster")
        print(f"5. Test interesting parameters with SQLMap")
        
        print(f"\n{Fore.CYAN}Output directory: {self.config.output_dir}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")


# ============================================================================
# CLI
# ============================================================================

def print_banner():
    """Print modern professional ASCII art banner"""
    banner = f"""
{Fore.CYAN}
    ____                        _      
   / __ \\___  _________  ____  (_)____
  / /_/ / _ \\/ ___/ __ \\/ __ \\/ / ___/
 / _, _/  __/ /__/ /_/ / / / / / /__  
/_/ |_|\\___/\\___/\\____/_/ /_/_/\\___/  
                                       
{Fore.WHITE}Automated Reconnaissance Framework{Fore.CYAN}
{Fore.CYAN} - Created by Othman Kamal
{Style.RESET_ALL}
{Style.RESET_ALL} {Fore.CYAN}{Style.RESET_ALL}Subfinder/Amass - subdomain enumeration{Style.RESET_ALL}
{Style.RESET_ALL} {Fore.CYAN}{Style.RESET_ALL}Katana - JS-aware crawling{Style.RESET_ALL}
{Style.RESET_ALL} {Fore.CYAN}{Style.RESET_ALL}Nuclei - 10,000+ vulnerability templates{Style.RESET_ALL}
{Style.RESET_ALL} {Fore.CYAN}{Style.RESET_ALL}httpx - Fast alive host verification{Style.RESET_ALL}
{Style.RESET_ALL} {Fore.CYAN}{Style.RESET_ALL}Playwright - Fallback for heavy JS sites{Style.RESET_ALL}
{Fore.YELLOW}Available Modes:{Style.RESET_ALL}
  {Fore.CYAN}•{Style.RESET_ALL} {Fore.WHITE}Automated{Style.RESET_ALL}   - Full scan with all available tools
  {Fore.CYAN}•{Style.RESET_ALL} {Fore.WHITE}Interactive{Style.RESET_ALL} - Step-by-step guided configuration

{Fore.CYAN}This framework orchestrates proven tools - it doesn't reinvent them.{Style.RESET_ALL}
"""
    print(banner)


def check_installation():
    """Check if recommended tools are installed"""
    tools = ToolConfig()
    
    print(f"\n{Fore.CYAN}[*] Tool Detection:{Style.RESET_ALL}\n")
    
    tool_info = [
        ('Subfinder', tools.subfinder, 'RECOMMENDED', 'Fast subdomain enumeration'),
        ('Amass', tools.amass, 'OPTIONAL', 'Deep subdomain enumeration (slower)'),
        ('Katana', tools.katana, 'RECOMMENDED', 'JS-aware crawling'),
        ('Nuclei', tools.nuclei, 'REQUIRED', 'Vulnerability scanning'),
        ('httpx', tools.httpx, 'RECOMMENDED', 'Alive host verification'),
        ('Playwright', tools.playwright_available, 'OPTIONAL', 'Heavy JS sites fallback')
    ]
    
    for name, status, level, desc in tool_info:
        status_icon = f"{Fore.GREEN}✓{Style.RESET_ALL}" if status else f"{Fore.YELLOW}✗{Style.RESET_ALL}"
        level_color = Fore.RED if level == 'REQUIRED' else Fore.YELLOW if level == 'RECOMMENDED' else Fore.BLUE
        print(f"  {status_icon} {name:12} [{level_color}{level}{Style.RESET_ALL}] - {desc}")
    
    # Check if critical tools are missing
    missing_critical = []
    if not tools.nuclei:
        missing_critical.append("Nuclei")
    
    if missing_critical:
        print(f"\n{Fore.RED}[!] Critical tools missing: {', '.join(missing_critical)}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Quick Install:{Style.RESET_ALL}")
        print(f"  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest")
        print(f"  go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
        print(f"  go install github.com/projectdiscovery/katana/cmd/katana@latest")
        print(f"  go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print()
        
        response = input(f"Continue anyway? (yes/no): ").strip().lower()
        if response != 'yes':
            sys.exit(1)
    
    return tools


def main():
    """Main entry point"""
    print_banner()
    
    # Check tool installation
    tools = check_installation()   
    
    if len(sys.argv) < 2:
        print(f"\n{Fore.CYAN}╔═══════════════════════════════════════════════════════════════════╗")
        print(f"║                          USAGE MODES                              ║")
        print(f"╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}1. Interactive Mode (Recommended for beginners):{Style.RESET_ALL}")
        print(f"   {sys.argv[0]} --interactive")
        print(f"   {Fore.CYAN}→ Guided configuration{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}→ Select specific subdomains and tests{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}→ Perfect for targeted testing{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}2. Automated Mode:{Style.RESET_ALL}")
        print(f"   {sys.argv[0]} <target_url> [options]")
        print(f"   {Fore.CYAN}→ Full automated scan{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}→ Uses all available tools{Style.RESET_ALL}")
        print(f"   {Fore.CYAN}→ Perfect for comprehensive reconnaissance{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Examples:{Style.RESET_ALL}\n")
        print(f"  # Interactive mode")
        print(f"  {sys.argv[0]} --interactive\n")
        print(f"  # Automated fast scan")
        print(f"  {sys.argv[0]} https://example.com\n")
        print(f"  # Automated deep scan with Amass")
        print(f"  {sys.argv[0]} https://example.com --use-amass\n")
        print(f"  # Authenticated scan")
        print(f"  {sys.argv[0]} https://app.example.com --auth-cookie 'session=abc123'\n")
        
        print(f"{Fore.CYAN}For full options: {sys.argv[0]} --help{Style.RESET_ALL}\n")
        sys.exit(1)
    
    # Check for interactive mode
    if '--interactive' in sys.argv or '-i' in sys.argv:
        config = ScanConfig(target_url="", tools=tools)
        config.output_dir.mkdir(parents=True, exist_ok=True)
        
        interactive = InteractiveMode(config, tools)
        
        try:
            asyncio.run(interactive.run())
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[!] Interactive mode cancelled{Style.RESET_ALL}")
        sys.exit(0)
    
    # Automated mode
    target_url = sys.argv[1]
    
    if target_url in ['--help', '-h']:
        print(f"\n{Fore.CYAN}AUTOMATED MODE OPTIONS:{Style.RESET_ALL}\n")
        
        print(f"{Fore.YELLOW}Basic Options:{Style.RESET_ALL}")
        print(f"  --timeout N            Request timeout (default: 20)")
        print(f"  --concurrency N        Concurrent requests (default: 100)")
        print(f"  --depth N              Crawl depth (default: 3)")
        print(f"  --output-dir DIR       Output directory (default: ./reconic_output)\n")
        
        print(f"{Fore.YELLOW}Tool Control:{Style.RESET_ALL}")
        print(f"  --no-subfinder         Disable Subfinder")
        print(f"  --use-amass            Enable Amass (slower, more thorough)")
        print(f"  --no-katana            Disable Katana crawler")
        print(f"  --use-playwright       Enable Playwright fallback")
        print(f"  --no-httpx             Disable httpx probing")
        print(f"  --no-nuclei            Disable Nuclei scanning")
        print(f"  --no-takeover          Skip takeover detection\n")
        
        print(f"{Fore.YELLOW}Proxy/Authentication:{Style.RESET_ALL}")
        print(f"  --proxy URL            HTTP/SOCKS proxy")
        print(f"  --tor                  Use TOR (127.0.0.1:9050)")
        print(f"  --auth-cookie COOKIE   Authentication cookie")
        print(f"  --auth-header HEADER   Authorization header\n")
        
        print(f"{Fore.YELLOW}Advanced:{Style.RESET_ALL}")
        print(f"  --nuclei-templates DIR Custom Nuclei templates directory")
        print(f"  --interactive, -i      Launch interactive mode\n")
        
        sys.exit(0)
    
    if not target_url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Invalid URL. Must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)
    
    # Build configuration
    config = ScanConfig(target_url=target_url, tools=tools)
    
    # Parse arguments
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        
        if arg == '--timeout' and i + 1 < len(sys.argv):
            config.timeout = int(sys.argv[i + 1])
            i += 2
        elif arg == '--concurrency' and i + 1 < len(sys.argv):
            config.concurrency = int(sys.argv[i + 1])
            i += 2
        elif arg == '--depth' and i + 1 < len(sys.argv):
            config.max_depth = int(sys.argv[i + 1])
            i += 2
        elif arg == '--output-dir' and i + 1 < len(sys.argv):
            config.output_dir = Path(sys.argv[i + 1])
            i += 2
        elif arg == '--proxy' and i + 1 < len(sys.argv):
            config.proxy = sys.argv[i + 1]
            print(f"{Fore.GREEN}[*] Using proxy: {config.proxy}{Style.RESET_ALL}")
            i += 2
        elif arg == '--tor':
            config.proxy = 'socks5://127.0.0.1:9050'
            config.tor = True
            print(f"{Fore.GREEN}[*] Routing through TOR{Style.RESET_ALL}")
            i += 1
        elif arg == '--auth-cookie' and i + 1 < len(sys.argv):
            config.auth_cookie = sys.argv[i + 1]
            print(f"{Fore.GREEN}[*] Authentication cookie configured{Style.RESET_ALL}")
            i += 2
        elif arg == '--auth-header' and i + 1 < len(sys.argv):
            config.auth_header = sys.argv[i + 1]
            print(f"{Fore.GREEN}[*] Authorization header configured{Style.RESET_ALL}")
            i += 2
        elif arg == '--nuclei-templates' and i + 1 < len(sys.argv):
            config.nuclei_templates = Path(sys.argv[i + 1])
            i += 2
        elif arg == '--no-subfinder':
            config.use_subfinder = False
            print(f"{Fore.YELLOW}[*] Subfinder disabled{Style.RESET_ALL}")
            i += 1
        elif arg == '--use-amass':
            config.use_amass = True
            print(f"{Fore.YELLOW}[*] Amass enabled (will be slower){Style.RESET_ALL}")
            i += 1
        elif arg == '--no-katana':
            config.use_katana = False
            print(f"{Fore.YELLOW}[*] Katana disabled{Style.RESET_ALL}")
            i += 1
        elif arg == '--use-playwright':
            config.use_playwright = True
            print(f"{Fore.YELLOW}[*] Playwright enabled{Style.RESET_ALL}")
            i += 1
        elif arg == '--no-httpx':
            config.use_httpx = False
            print(f"{Fore.YELLOW}[*] httpx disabled{Style.RESET_ALL}")
            i += 1
        elif arg == '--no-nuclei':
            config.use_nuclei = False
            print(f"{Fore.YELLOW}[*] Nuclei disabled{Style.RESET_ALL}")
            i += 1
        elif arg == '--no-takeover':
            config.takeover_check = False
            print(f"{Fore.YELLOW}[*] Takeover detection disabled{Style.RESET_ALL}")
            i += 1
        else:
            print(f"{Fore.RED}[!] Unknown argument: {arg}{Style.RESET_ALL}")
            sys.exit(1)
    
    # Authorization
    print(f"\n{Fore.RED}╔═══════════════════════════════════════════════════════════════════╗")
    print(f"║                    AUTHORIZATION REQUIRED                         ║")
    print(f"╚═══════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}This tool performs active security testing.{Style.RESET_ALL}")
    print(f"Only use on targets where you have explicit written permission.")
    print(f"Unauthorized testing is illegal.\n")
    
    print(f"Target: {Fore.CYAN}{target_url}{Style.RESET_ALL}")
    print(f"Domain: {Fore.CYAN}{tldextract.extract(target_url).registered_domain}{Style.RESET_ALL}\n")
    
    response = input(f"I have authorization to test this target (type 'yes'): ").strip().lower()
    
    if response != 'yes':
        print(f"\n{Fore.YELLOW}[*] Scan cancelled.{Style.RESET_ALL}")
        sys.exit(0)
    
    print(f"\n{Fore.GREEN}[✓] Authorization confirmed. Starting automated scan...{Style.RESET_ALL}")
    
    # Run scanner
    scanner = ReconicScanner(config)
    
    try:
        asyncio.run(scanner.run())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted{Style.RESET_ALL}")
        sys.exit(0)


if __name__ == "__main__":
    main() #