#!/usr/bin/env python3
import requests
from bs4 import BeautifulSoup
import re
import socket
import json
import sys
import time
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional, Tuple


class WebScanner:

    def __init__(self, target_url: str, timeout: int = 10):
        # TODO: Pentest safety - add an explicit authorized scope allowlist before any requests are sent.
        # Advice: For client work, require approved domains/subdomains and refuse to scan anything outside
        # that scope. This helps prevent accidental testing of third-party systems.
        self.target = target_url.rstrip('/')
        self.base_domain = urlparse(self.target).netloc
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            # TODO: Pentest transparency - replace the browser-like User-Agent with an assessment identifier.
            # Advice: Use something like "AuthorizedSecurityAssessment/1.0 contact=security@example.com"
            # when the client has approved identifiable testing traffic.
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def get_http_info(self) -> Dict:
        # TODO: Efficiency - cache the first successful GET response and reuse it across methods.
        # Advice: This script currently requests the same target several times. Reusing one response
        # lowers traffic volume and makes scans quieter in client monitoring logs.
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            return {
                'status_code': resp.status_code,
                'headers': dict(resp.headers),
                'content_type': resp.headers.get('Content-Type', ''),
                'server': resp.headers.get('Server', 'Unknown'),
                'content_length': len(resp.content),
                'response_time_ms': round(resp.elapsed.total_seconds() * 1000, 2)
            }
        except requests.RequestException as e:
            return {'error': str(e)}

    def get_meta_tags(self) -> Dict[str, str]:

        # TODO: Reporting - flag sensitive meta tags or accidental environment hints if found.
        # Advice: Meta data is usually informational, but client reports can mention exposed generator
        # versions, internal app names, staging labels, or unusual indexing instructions.
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            metas = {}
            for tag in soup.find_all('meta'):
                name = tag.get('name', tag.get('property', ''))
                content = tag.get('content', '')
                if name and content:
                    metas[name] = content
            return metas
        except Exception as e:
            return {'error': str(e)}

    def detect_technologies(self) -> List[str]:
        # TODO: Accuracy - add confidence levels instead of treating every regex hit as confirmed.
        # Advice: Technology fingerprinting from HTML, headers, and cookies can create false positives.
        # Report these as "possible", "likely", or "confirmed" with evidence.
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            html = resp.text.lower()
            headers = {k.lower(): v.lower() for k, v in resp.headers.items()}

            techs = []

            cms_patterns = {
                'WordPress': r'wp-content|wordpress',
                'Joomla': r'joomla|com_joomla',
                'Drupal': r'drupal|sites/default/files',
                'Magento': r'magento|var/session',
                'Shopify': r'shopify|cdn.shopify.com',
                'Wix': r'wix\.com',
                'Squarespace': r'squarespace\.com',
            }

            for cms, pattern in cms_patterns.items():
                if re.search(pattern, html):
                    techs.append(f"CMS: {cms}")

            frameworks = {
                'React': r'react|react-dom',
                'Vue.js': r'vue\.js|vue-app',
                'Angular': r'angular|ng-version',
                'Bootstrap': r'bootstrap',
                'Tailwind CSS': r'tailwindcss',
            }

            for fw, pattern in frameworks.items():
                if re.search(pattern, html):
                    techs.append(f"Framework: {fw}")

            server_patterns = {
                'Apache': r'apache',
                'Nginx': r'nginx',
                'IIS': r'iis|ms-iis',
                'Cloudflare': r'cloudflare',
                'AWS': r'amazon|aws',
            }

            for srv, pattern in server_patterns.items():
                if re.search(pattern, headers.get('server', '')):
                    techs.append(f"Server: {srv}")

            set_cookie = headers.get('set-cookie', '')
            cookie_patterns = {
                'PHP': r'phpsessid|PHPSESSID',
                'ASP.NET': r'asp\.net_sessionid',
                # TODO: Accuracy - a cookie named "session" does not prove Node.js.
                # Advice: Keep this as a weak signal only, or remove it unless combined with stronger evidence.
                'Node.js': r'session',
            }

            for tech, pattern in cookie_patterns.items():
                if re.search(pattern, set_cookie):
                    techs.append(f"Runtime: {tech}")

            soup = BeautifulSoup(resp.text, 'html.parser')
            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src'].lower()
                if 'jquery' in src and 'jQuery' not in techs:
                    techs.append("Library: jQuery")
                if 'lodash' in src and 'Lodash' not in techs:
                    techs.append("Library: Lodash")

            return list(set(techs))

        except Exception as e:
            return [f"Error detecting technologies: {e}"]

    def analyze_security_headers(self) -> Dict[str, str]:
        """Analyze security headers and their presence."""
        # TODO: Findings - evaluate header quality, not only whether each header exists.
        # Advice: A present header can still be weak. Examples:
        # - HSTS max-age too low or missing includeSubDomains
        # - CSP allowing unsafe-inline or unsafe-eval
        # - X-Frame-Options set to an invalid value
        # - Cache-Control missing on sensitive authenticated pages
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            critical_headers = [
                'strict-transport-security',
                'content-security-policy',
                'x-content-type-options',
                'x-frame-options',
                'x-xss-protection',
                'referrer-policy',
                'permissions-policy',
                'cache-control',
            ]

            results = {}
            for header in critical_headers:
                value = headers.get(header, 'MISSING')
                status = "existing" if value != 'MISSING' else "not existing"
                results[header.upper()] = f"{status} ({value})"

            return results
        except Exception as e:
            return {'error': str(e)}

    def scan_common_files(self, paths: Optional[List[str]] = None) -> Dict[str, int]:
        # TODO: Scope and noise - keep this path list client-approved and rate limited.
        # Advice: Even common path checks can trigger alerts. Add a configurable delay, max request count,
        # and a way to disable sensitive checks such as "/.env" unless explicitly authorized.
        if paths is None:
            paths = [
                '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
                '/favicon.ico', '/wp-login.php', '/admin/', '/login',
                '/api/', '/graphql', '/.env', '/config.json',
                '/manifest.json', '/sw.js', '/service-worker.js',
            ]

        results = {}
        for path in paths:
            url = f"{self.target}{path}" if not path.startswith('http') else path
            try:
                # TODO: Reliability - consider falling back to GET when HEAD is blocked or unsupported.
                # Advice: Some servers return misleading results for HEAD, especially 403 or 405.
                # A lightweight GET with streaming/size limits can reduce false negatives.
                resp = self.session.head(url, timeout=self.timeout)
                results[path] = resp.status_code
            except requests.RequestException:
                results[path] = 'ERROR'

        return results

    def dns_lookup(self) -> Dict[str, str]:

        # TODO: DNS coverage - consider collecting CNAME, MX, TXT, and NS records.
        # Advice: For authorized recon, these records help identify hosting providers, mail security,
        # SPF/DMARC posture, and third-party dependencies. Keep it passive unless scope allows more.
        try:
            ip_address = socket.gethostbyname(self.base_domain)
            return {
                'domain': self.base_domain,
                'ip_address': ip_address,
                'resolved_at': time.strftime('%Y-%m-%d %H:%M:%S')
            }
        except socket.gaierror as e:
            return {'error': str(e)}

    def get_ssl_info(self) -> Dict[str, str]:

        # TODO: Reliability - replace requests internals with Python's ssl/socket modules.
        # Advice: Accessing resp.connection.sock can break depending on connection pooling.
        # A direct TLS connection gives more reliable certificate details and expiry checks.
        try:
            resp = self.session.get(f"https://{self.base_domain}", timeout=self.timeout)
            cert = resp.connection.sock.getpeercert()

            return {
                'subject': dict(cert['subject']),
                'issuer': dict(cert['issuer']),
                'valid_from': str(cert['notBefore']),
                'valid_to': str(cert['notAfter']),
                'serial_number': hex(cert['serialNumber']),
            }
        except Exception as e:
            return {'error': f"ssl info unavailable: {e}"}

    def get_page_info(self) -> Dict[str, str]:

        # TODO: Client reporting - include evidence URLs with page metadata findings.
        # Advice: Page title and description are useful for identifying exposed admin panels,
        # staging sites, default pages, or accidentally indexed sensitive applications.
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')

            title = soup.title.string.strip() if soup.title else 'No Title'
            desc_tag = soup.find('meta', attrs={'name': 'description'})
            description = desc_tag['content'] if desc_tag and desc_tag.get('content') else 'No Description'

            return {
                'title': title,
                'description': description[:200],  
            }
        except Exception as e:
            return {'error': str(e)}

    def extract_links(self) -> Dict[str, List[str]]:

        # TODO: Crawler safety - enforce same-host/same-scope rules before following or reporting links.
        # Advice: Link extraction is passive here, but if you later add crawling, never follow external
        # links unless the client's written scope explicitly includes them.
        try:
            resp = self.session.get(self.target, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')

            internal_links = []
            external_links = []

            for link in soup.find_all('a', href=True):
                href = link['href']
                if not href.startswith(('http://', 'https://')):
                    href = urljoin(self.target, href)

                parsed = urlparse(href)
                if parsed.netloc == self.base_domain or not parsed.netloc:
                    internal_links.append(href)
                else:
                    external_links.append(href)

            return {
                'internal': list(set(internal_links))[:50],  
                'external': list(set(external_links))[:50],
            }
        except Exception as e:
            return {'error': str(e)}

    def full_scan(self) -> Dict:

        # TODO: Professional output - remove casual/insulting text before client use.
        # Advice: Assume console output may appear in screenshots, logs, reports, or demos.
        print(f"\n begin scanning baby this is your dumbass target {self.target}...\n")

        results = {}

        print("fetching http info")
        results['http_info'] = self.get_http_info()

        print("extracting meta tags")
        results['meta_tags'] = self.get_meta_tags()

        print("detecting technologies")
        results['technologies'] = self.detect_technologies()

        print("analyzing security headers")
        results['security_headers'] = self.analyze_security_headers()

        print("scanning common files and directories")
        results['common_files'] = self.scan_common_files()

        print("performing dns lookup")
        results['dns_info'] = self.dns_lookup()

        print("checking ssl certificate")
        results['ssl_info'] = self.get_ssl_info()

        print("extracting page info")
        results['page_info'] = self.get_page_info()

        print("extracting links")
        results['links'] = self.extract_links()

        return results

def pretty_print_report(report: Dict):

    # TODO: Reporting - separate raw observations from security findings.
    # Advice: Client-ready output should include severity, evidence, impact, recommendation,
    # affected URL, and confidence. Raw data is useful as an appendix, not the whole report.
    print("\n" + "=" * 60)
    print("web scan report")
    print("=" * 60)

    http = report.get('http_info', {})
    if 'error' not in http:
        print(f"\n http response:")
        print(f"   status code: {http['status_code']}")
        print(f"   server:      {http['server']}")
        print(f"   content-type:{http['content_type']}")
        print(f"   size:        {http['content_length']} bytes")
        print(f"   response time: {http['response_time_ms']} ms")

    page = report.get('page_info', {})
    if 'error' not in page:
        print(f"\n page info:")
        print(f"   title:       {page['title']}")
        print(f"   description: {page['description']}")

    techs = report.get('technologies', [])
    if 'error' not in techs and techs:
        print(f"\n detected technologies:")
        # TODO: Console compatibility - replace non-ASCII bullets with "-" for Windows terminals.
        # Advice: The current output may display as mojibake depending on terminal encoding.
        for t in techs:
            print(f"   • {t}")

    headers = report.get('security_headers', {})
    if 'error' not in headers:
        print(f"\n security headers:")
        for header, status in headers.items():
            print(f"   [{status}] {header}")

    dns = report.get('dns_info', {})
    if 'error' not in dns:
        print(f"\n dns information:")
        print(f"   domain:  {dns['domain']}")
        print(f"   ip addr: {dns['ip_address']}")

    ssl = report.get('ssl_info', {})
    if 'error' not in ssl:
        print(f"\n ssl certificate:")
        for key, value in ssl.items():
            print(f"   {key}: {value}")

    files = report.get('common_files', {})
    if 'error' not in files:
        found = [f"{k} ({v})" for k, v in files.items() if v == 200]
        missing = [f"{k}" for k, v in files.items() if v != 200 and v != 'ERROR']
        print(f"\n common files:")
        if found:
            print(f"   found ({len(found)}):")
            for f in found[:15]:
                print(f"      • {f}")
        if missing:
            print(f"   missing ({len(missing)}):")
            for m in missing[:10]:
                print(f"      • {m}")

    links = report.get('links', {})
    if 'error' not in links:
        print(f"\n links:")
        print(f"   internal:  {len(links['internal'])} unique")
        print(f"   external:  {len(links['external'])} unique")

    meta = report.get('meta_tags', {})
    if 'error' not in meta and meta:
        print(f"\n meta tags:")
        for key, value in list(meta.items())[:10]:
            print(f"   {key}: {value}")

    print("\n" + "=" * 60)


def main():

    # TODO: CLI usability - add argparse options for scope, delay, timeout, JSON output path, and no-interactive mode.
    # Advice: Repeatable pentest workflows should be scriptable, for example:
    # python webscanner.py https://example.com --scope example.com --delay 0.5 --json report.json
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        # TODO: Professional output - replace insulting prompt text before any client-facing use.
        target = input("enter target url you dumbass (e.g., https://example.com): ").strip()

    # TODO: URL validation - reject malformed targets and unsupported schemes before scanning.
    # Advice: Clear validation avoids accidental requests to wrong hosts or confusing report output.
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"

    scanner = WebScanner(target)
    report = scanner.full_scan()
    pretty_print_report(report)

    save = input("\n save report as json? (y/n): ").strip().lower()
    if save == 'y':
        filename = f"scan_{urlparse(target).netloc}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        # TODO: Professional output - replace casual/insulting save confirmation text.
        print(f" yuppie yuppie yupp your dumbass report saved to {filename}")


if __name__ == '__main__':
    main()
