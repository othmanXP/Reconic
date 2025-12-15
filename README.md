# Reconic - Automated Reconnaissance Framework

```
    ____                        _      
   / __ \___  _________  ____  (_)____
  / /_/ / _ \/ ___/ __ \/ __ \/ / ___/
 / _, _/  __/ /__/ /_/ / / / / / /__  
/_/ |_|\___/\___/\____/_/ /_/_/\___/  
                                       
Automated Reconnaissance Framework
Created by Othman Kamal
```

**Reconic** is a powerful reconnaissance orchestrator designed for bug bounty hunters and security professionals. It intelligently combines the **best-in-class ProjectDiscovery tools** into a seamless, guided workflow without reinventing the wheel.

---

## Key Features

### Subdomain Enumeration
- **Primary**: **Subfinder** (fast, all sources)
- **Optional**: **Amass** (deep, thorough — slower)

### Alive Host Verification
- **httpx** with tech detection, titles, status codes, and redirect following

### Endpoint Discovery
- **Katana** — best-in-class JS-aware crawling with headless support, form filling, and known file discovery
- **Playwright** fallback for extremely heavy JavaScript applications

### Vulnerability Scanning
- **Nuclei** with automatic template updates and 10,000+ community templates

### Subdomain Takeover Detection
- Built-in fingerprinting for 17+ popular services:
  - GitHub Pages, Heroku, AWS S3, Azure
  - Cloudfront, Fastly, Pantheon, ReadMe
  - Bitbucket, Ghost, HelpJuice, HelpScout
  - Cargo, StatusPage, Tumblr, WordPress, Unbounce

### Stealth & Authentication
- Full proxy support (HTTP/SOCKS)
- TOR routing (`--tor`)
- Cookie & Authorization header authentication

### Two Powerful Modes
- **Automated Mode** — One-command full reconnaissance
- **Interactive Mode** (`--interactive`) — Step-by-step control for targeted testing

---

## NOTE

> **This tool orchestrates proven tools — it does not replace manual testing.**  
> Real bounties come from **Burp Suite**, creative thinking, and manual verification.  
> Reconic gives you the best starting point possible.

---

## 📦 Installation

### 1. Python Dependencies

```bash
pip install aiohttp aiofiles tldextract beautifulsoup4 dnspython colorama PyYAML requests playwright
playwright install chromium
```

### 2. External Tools (Highly Recommended)

```bash
# Requires Go 1.21+
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Optional: Deep enumeration (slower but thorough)
go install -v github.com/owasp-amass/amass/v4/...@master

# Add to PATH
export PATH=$PATH:$HOME/go/bin
```

### 3. Verify Installation

```bash
python reconic.py
```

The tool will automatically detect which external tools are installed and show their status.

---

## Usage

### Automated Mode (Recommended for full recon)

```bash
python reconic.py https://example.com
```

### Interactive Mode (Perfect for targeted testing)

```bash
python reconic.py --interactive
```

This launches a guided wizard that lets you:
- Choose enumeration methods (Subfinder, Amass, or both)
- Select specific subdomains to test
- Pick which tests to run (alive check, crawling, takeover, Nuclei)
- Configure proxy/authentication
- Review configuration before execution

---

## Command Line Options

### Basic Options
```bash
--timeout N            Request timeout (default: 20)
--concurrency N        Concurrent requests (default: 100)
--depth N              Crawl depth (default: 3)
--output-dir DIR       Output directory (default: ./reconic_output)
```

### Tool Control
```bash
--no-subfinder         Disable Subfinder
--use-amass            Enable Amass (slower, more thorough)
--no-katana            Disable Katana crawler
--use-playwright       Enable Playwright fallback
--no-httpx             Disable httpx probing
--no-nuclei            Disable Nuclei scanning
--no-takeover          Skip takeover detection
```

### Proxy/Authentication
```bash
--proxy URL            HTTP/SOCKS proxy
--tor                  Use TOR (127.0.0.1:9050)
--auth-cookie COOKIE   Authentication cookie
--auth-header HEADER   Authorization header
```

### Advanced
```bash
--nuclei-templates DIR Custom Nuclei templates directory
--interactive, -i      Launch interactive mode
```

---

## Common Examples

### Basic automated scan
```bash
python reconic.py https://example.com
```

### Deep scan with Amass (takes 10-20 minutes)
```bash
python reconic.py https://example.com --use-amass
```

### Authenticated scan with cookies
```bash
python reconic.py https://app.example.com --auth-cookie 'session=abc123'
```

### Stealth mode via TOR
```bash
python reconic.py https://example.com --tor
```

### Custom Nuclei templates
```bash
python reconic.py https://example.com --nuclei-templates ./my-templates
```

### Quick subdomain enum only (no scanning)
```bash
python reconic.py https://example.com --no-katana --no-nuclei
```

### Full interactive workflow
```bash
python reconic.py --interactive
# Then follow the guided prompts
```

---

## Output

All results are saved to `./reconic_output/`:

```
reconic_output/
├── recon_20251215_143022.json      # Full structured results
├── httpx_output.json                # Alive hosts with metadata
├── katana_output.txt                # Discovered endpoints
├── nuclei_results.json              # Vulnerability findings
├── subfinder_example.com.txt        # Subdomain enumeration results
└── interactive_scan_*.json          # Interactive mode results
```

### Results Structure

The main JSON output contains:
- `target` - Target URL
- `scan_date` - Timestamp
- `tools_used` - Which tools were available/used
- `subdomains` - All discovered subdomains
- `alive_hosts` - Live hosts with HTTP metadata
- `endpoints` - Crawled endpoints
- `takeovers` - Potential takeover vulnerabilities
- `nuclei_results` - Path to Nuclei scan results

---

## Workflow Phases

Reconic executes reconnaissance in five organized phases:

### Phase 1: Subdomain Enumeration
- Runs Subfinder (fast, passive sources)
- Optionally runs Amass (deep, active enumeration)
- Deduplicates and sorts results

### Phase 2: Alive Host Verification
- Uses httpx to probe all discovered subdomains
- Captures status codes, titles, technologies
- Follows redirects and filters CDN responses

### Phase 3: Subdomain Takeover Detection
- DNS CNAME resolution
- Service fingerprinting
- HTTP response analysis
- **Critical findings flagged immediately**

### Phase 4: Endpoint Discovery
- Katana crawls alive hosts with JS rendering
- Extracts all links, forms, API endpoints
- Optionally uses Playwright for heavy JS sites

### Phase 5: Nuclei Vulnerability Scanning
- Updates templates automatically
- Scans hosts + discovered endpoints
- Filters by severity (critical/high/medium)
- Organized output by vulnerability type

---

## Next Steps After Reconic

1. **Review takeover findings** — Submit immediately if valid
2. **Import endpoints into Burp Suite** for manual testing
3. **Review Nuclei findings** — Verify high/critical vulnerabilities
4. **Run deeper fuzzing** with ffuf or Feroxbuster on interesting paths
5. **Test parameters** with SQLMap or custom injection scripts
6. **Screenshot alive hosts** for visual reconnaissance
7. **Check historical URLs** with gau/waybackurls

---

## Security & Ethics

### Authorization Required
```
╔═══════════════════════════════════════════════════════════════════╗
║                    AUTHORIZATION REQUIRED                         ║
╚═══════════════════════════════════════════════════════════════════╝

This tool performs active security testing.
Only use on targets where you have explicit written permission.
Unauthorized testing is illegal.
```

### Best Practices
- Always get written authorization before testing
- Respect rate limits and target infrastructure
- Use `--tor` or proxies for sensitive testing
- Start with `--no-nuclei` on production systems
- Review findings before reporting
- Never test critical infrastructure without approval

---

## Contributing

Contributions welcome! Focus areas:

### High Priority
- Additional historical URL sources (gau, waybackurls integration)
- Screenshot integration (httpx -screenshot)
- Burp/BBRF export formats
- More takeover fingerprints
- Report generation (HTML/PDF)

### Medium Priority
- GitHub/GitLab recon integration
- Google dorking module
- Certificate transparency logs
- Port scanning integration
- Technology stack analysis

### Enhancement Ideas
- Cloud bucket enumeration (S3, Azure, GCP)
- API endpoint fuzzing templates
- Automated credential checking
- Notification system (Slack/Discord)
- Multi-target support

To contribute:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

---


## Changelog

### Current
- Initial release
- Subfinder & Amass integration
- Katana JS-aware crawling
- httpx alive host verification
- Nuclei vulnerability scanning
- Subdomain takeover detection
- Interactive mode
- Proxy & TOR support
- Authentication support

---

## Credits

### Tools Integrated
- [ProjectDiscovery](https://projectdiscovery.io/) - Subfinder, Katana, Nuclei, httpx
- [OWASP Amass](https://github.com/owasp-amass/amass)
- [Playwright](https://playwright.dev/)

---

## Disclaimer

**IMPORTANT**: Only use this tool on targets you have explicit written permission to test. Unauthorized scanning is illegal and unethical. The author is not responsible for any misuse or damage caused by this tool.

This tool is provided "as is" without warranty of any kind. Always verify findings manually before reporting.

---

**Made for hunters, by hunters.** 🏆  
Happy hunting!

