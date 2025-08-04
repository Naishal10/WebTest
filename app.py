#!/usr/bin/env python3
"""
Website Security Integration Testing Tool
IMPORTANT: Only use this tool on websites you own or have explicit permission to test.
Unauthorized security testing is illegal and unethical.
"""

import requests
import re
import ssl
import socket
from urllib.parse import urlparse, urljoin
import json
from datetime import datetime
import concurrent.futures
import argparse
import sys
from typing import List, Dict, Any, Tuple
import warnings
warnings.filterwarnings('ignore', category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

class SecurityTester:
    def __init__(self, target_url: str, verbose: bool = False):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target_url)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Security-Test-Tool/1.0 (Integration Testing)'
        })
        self.verbose = verbose
        self.results = {
            'url': self.target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': [],
            'warnings': [],
            'info': []
        }

    def log(self, message: str, level: str = 'INFO'):
        if self.verbose or level in ['ERROR', 'WARNING']:
            print(f"[{level}] {message}")

    def add_finding(self, severity: str, category: str, title: str, description: str, details: Dict = None):
        finding = {
            'severity': severity,
            'category': category,
            'title': title,
            'description': description,
            'details': details or {}
        }
        
        if severity == 'HIGH':
            self.results['vulnerabilities'].append(finding)
        elif severity == 'MEDIUM':
            self.results['warnings'].append(finding)
        else:
            self.results['info'].append(finding)

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
                    
                    # Check protocol version
                    if protocol in ['TLSv1', 'TLSv1.1']:
                        self.add_finding('HIGH', 'SSL/TLS', 'Outdated TLS Version',
                                       f'Server supports outdated {protocol}',
                                       {'protocol': protocol})
                    
                    # Check certificate validity
                    if cert:
                        self.log(f"SSL/TLS Protocol: {protocol}", 'INFO')
        except Exception as e:
            self.add_finding('HIGH', 'SSL/TLS', 'SSL/TLS Error',
                           f'SSL/TLS configuration error: {str(e)}')

    def test_security_headers(self):
        """Test for security headers"""
        self.log("Testing security headers...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            headers = response.headers
            
            security_headers = {
                'Strict-Transport-Security': ('HIGH', 'Missing HSTS header'),
                'X-Content-Type-Options': ('MEDIUM', 'Missing X-Content-Type-Options header'),
                'X-Frame-Options': ('MEDIUM', 'Missing X-Frame-Options header (Clickjacking protection)'),
                'Content-Security-Policy': ('MEDIUM', 'Missing Content-Security-Policy header'),
                'X-XSS-Protection': ('LOW', 'Missing X-XSS-Protection header'),
                'Referrer-Policy': ('LOW', 'Missing Referrer-Policy header'),
                'Permissions-Policy': ('LOW', 'Missing Permissions-Policy header')
            }
            
            for header, (severity, message) in security_headers.items():
                if header not in headers:
                    self.add_finding(severity, 'Headers', f'Missing {header}', message)
                else:
                    self.log(f"Found {header}: {headers[header][:50]}...", 'INFO')
            
            # Check for information disclosure headers
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in info_headers:
                if header in headers:
                    self.add_finding('LOW', 'Headers', f'Information Disclosure: {header}',
                                   f'Header reveals server information: {headers[header]}',
                                   {'header': header, 'value': headers[header]})
            
        except Exception as e:
            self.log(f"Error testing headers: {str(e)}", 'ERROR')

    def test_common_paths(self):
        """Test for exposed sensitive paths"""
        self.log("Testing common sensitive paths...")
        
        sensitive_paths = [
            '/.git/', '/.env', '/.gitignore', '/config.php', '/wp-config.php',
            '/.htaccess', '/.htpasswd', '/robots.txt', '/sitemap.xml',
            '/admin/', '/administrator/', '/phpmyadmin/', '/adminer/',
            '/.DS_Store', '/backup/', '/backups/', '/temp/', '/tmp/',
            '/test/', '/tests/', '/.svn/', '/.hg/', '/node_modules/',
            '/package.json', '/composer.json', '/web.config'
        ]
        
        found_paths = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for path in sensitive_paths:
                url = urljoin(self.target_url, path)
                futures.append(executor.submit(self._check_path, url, path))
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_paths.append(result)
        
        if found_paths:
            self.add_finding('HIGH', 'Paths', 'Exposed Sensitive Paths',
                           'Sensitive files/directories are publicly accessible',
                           {'paths': found_paths})

    def _check_path(self, url: str, path: str) -> Dict:
        try:
            response = self.session.get(url, timeout=5, allow_redirects=False)
            if response.status_code == 200:
                self.log(f"Found exposed path: {path}", 'WARNING')
                return {'path': path, 'status': response.status_code, 'size': len(response.content)}
        except:
            pass
        return None

    def test_xss_basic(self):
        """Basic XSS vulnerability testing"""
        self.log("Testing for basic XSS vulnerabilities...")
        
        # Test payloads (basic, non-harmful)
        xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            "';alert(1);//",
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>'
        ]
        
        try:
            # Test GET parameters
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response.text)
            
            for form in forms:
                for payload in xss_payloads:
                    if self._test_form_xss(form, payload):
                        self.add_finding('HIGH', 'XSS', 'Potential XSS Vulnerability',
                                       f'Form at {form.get("action", "/")} may be vulnerable to XSS',
                                       {'form': form, 'payload': payload})
                        break
        except Exception as e:
            self.log(f"Error during XSS testing: {str(e)}", 'ERROR')

    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        
        for match in form_pattern.finditer(html):
            form_html = match.group(0)
            form_data = {
                'action': re.search(r'action=["\']([^"\']*)["\']', form_html),
                'method': re.search(r'method=["\']([^"\']*)["\']', form_html),
                'inputs': re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html)
            }
            
            forms.append({
                'action': form_data['action'].group(1) if form_data['action'] else '/',
                'method': form_data['method'].group(1).upper() if form_data['method'] else 'GET',
                'inputs': form_data['inputs']
            })
        
        return forms

    def _test_form_xss(self, form: Dict, payload: str) -> bool:
        """Test a form for XSS vulnerability"""
        try:
            url = urljoin(self.target_url, form['action'])
            data = {input_name: payload for input_name in form['inputs']}
            
            if form['method'] == 'POST':
                response = self.session.post(url, data=data, timeout=5)
            else:
                response = self.session.get(url, params=data, timeout=5)
            
            # Check if payload is reflected in response
            if payload in response.text:
                return True
        except:
            pass
        return False

    def test_sql_injection_basic(self):
        """Basic SQL injection testing"""
        self.log("Testing for basic SQL injection vulnerabilities...")
        
        sql_payloads = [
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "' OR '1'='1' --",
            "1' OR '1' = '1",
            "1 UNION SELECT NULL--"
        ]
        
        error_patterns = [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySQLSyntaxErrorException',
            r'PostgreSQL.*ERROR',
            r'ORA-[0-9]{5}',
            r'Microsoft.*ODBC.*SQL',
            r'SQLite.*error',
            r'sqlite3.OperationalError'
        ]
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response.text)
            
            for form in forms:
                for payload in sql_payloads:
                    result = self._test_form_sqli(form, payload, error_patterns)
                    if result:
                        self.add_finding('HIGH', 'SQL Injection', 'Potential SQL Injection',
                                       f'Form at {form.get("action", "/")} may be vulnerable to SQL injection',
                                       {'form': form, 'payload': payload, 'error': result})
                        break
        except Exception as e:
            self.log(f"Error during SQL injection testing: {str(e)}", 'ERROR')

    def _test_form_sqli(self, form: Dict, payload: str, error_patterns: List[str]) -> str:
        """Test a form for SQL injection"""
        try:
            url = urljoin(self.target_url, form['action'])
            data = {input_name: payload for input_name in form['inputs']}
            
            if form['method'] == 'POST':
                response = self.session.post(url, data=data, timeout=5)
            else:
                response = self.session.get(url, params=data, timeout=5)
            
            # Check for SQL errors in response
            for pattern in error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return pattern
        except:
            pass
        return None

    def test_csrf_protection(self):
        """Test for CSRF protection"""
        self.log("Testing CSRF protection...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            forms = self._extract_forms(response.text)
            
            csrf_patterns = [
                r'csrf[_-]?token',
                r'authenticity[_-]?token',
                r'__RequestVerificationToken',
                r'csrfmiddlewaretoken',
                r'_token'
            ]
            
            for form in forms:
                if form['method'] == 'POST':
                    has_csrf = False
                    form_html = response.text
                    
                    for pattern in csrf_patterns:
                        if re.search(pattern, form_html, re.IGNORECASE):
                            has_csrf = True
                            break
                    
                    if not has_csrf:
                        self.add_finding('MEDIUM', 'CSRF', 'Missing CSRF Protection',
                                       f'POST form at {form.get("action", "/")} lacks CSRF token',
                                       {'form': form})
        except Exception as e:
            self.log(f"Error testing CSRF: {str(e)}", 'ERROR')

    def test_cookie_security(self):
        """Test cookie security attributes"""
        self.log("Testing cookie security...")
        
        try:
            response = self.session.get(self.target_url, timeout=10)
            
            for cookie in response.cookies:
                issues = []
                
                if not cookie.secure and self.target_url.startswith('https://'):
                    issues.append('Missing Secure flag')
                
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    issues.append('Missing HttpOnly flag')
                
                if not cookie.has_nonstandard_attr('SameSite'):
                    issues.append('Missing SameSite attribute')
                
                if issues:
                    self.add_finding('MEDIUM', 'Cookies', f'Insecure Cookie: {cookie.name}',
                                   f'Cookie has security issues: {", ".join(issues)}',
                                   {'cookie': cookie.name, 'issues': issues})
        except Exception as e:
            self.log(f"Error testing cookies: {str(e)}", 'ERROR')

    def run_all_tests(self):
        """Run all security tests"""
        print(f"\n{'='*60}")
        print(f"Security Testing: {self.target_url}")
        print(f"{'='*60}\n")
        
        tests = [
            self.test_ssl_tls,
            self.test_security_headers,
            self.test_common_paths,
            self.test_xss_basic,
            self.test_sql_injection_basic,
            self.test_csrf_protection,
            self.test_cookie_security
        ]
        
        for test in tests:
            try:
                test()
            except Exception as e:
                self.log(f"Error in {test.__name__}: {str(e)}", 'ERROR')
        
        return self.results

    def print_results(self):
        """Print test results"""
        print(f"\n{'='*60}")
        print("SECURITY TEST RESULTS")
        print(f"{'='*60}\n")
        
        if self.results['vulnerabilities']:
            print(f"🔴 HIGH SEVERITY ISSUES ({len(self.results['vulnerabilities'])})")
            print("-" * 40)
            for vuln in self.results['vulnerabilities']:
                print(f"• {vuln['title']}")
                print(f"  Category: {vuln['category']}")
                print(f"  {vuln['description']}")
                if vuln.get('details'):
                    print(f"  Details: {json.dumps(vuln['details'], indent=4)}")
                print()
        
        if self.results['warnings']:
            print(f"🟡 MEDIUM SEVERITY ISSUES ({len(self.results['warnings'])})")
            print("-" * 40)
            for warn in self.results['warnings']:
                print(f"• {warn['title']}")
                print(f"  Category: {warn['category']}")
                print(f"  {warn['description']}")
                print()
        
        if self.results['info']:
            print(f"🔵 LOW SEVERITY/INFO ({len(self.results['info'])})")
            print("-" * 40)
            for info in self.results['info']:
                print(f"• {info['title']}")
                print(f"  {info['description']}")
                print()
        
        total_issues = len(self.results['vulnerabilities']) + len(self.results['warnings'])
        print(f"\nTotal Issues Found: {total_issues}")
        print(f"Scan completed at: {self.results['scan_time']}")

    def save_results(self, filename: str):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"\nResults saved to: {filename}")


def main():
    print("""
╔═══════════════════════════════════════════════════════════╗
║           Website Security Integration Tester              ║
║                                                           ║
║  ⚠️  IMPORTANT: Only test websites you own or have        ║
║     explicit permission to test. Unauthorized testing     ║
║     is illegal and unethical.                            ║
╚═══════════════════════════════════════════════════════════╝
    """)
    
    parser = argparse.ArgumentParser(description='Website Security Integration Testing Tool')
    parser.add_argument('url', help='Target URL to test')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Save results to JSON file')
    parser.add_argument('--confirm', action='store_true', 
                       help='Confirm you have permission to test this website')
    
    args = parser.parse_args()
    
    if not args.confirm:
        print("\n❌ You must confirm you have permission to test this website.")
        print("   Add --confirm flag to proceed.")
        sys.exit(1)
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    try:
        tester = SecurityTester(args.url, verbose=args.verbose)
        results = tester.run_all_tests()
        tester.print_results()
        
        if args.output:
            tester.save_results(args.output)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Testing interrupted by user")
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()