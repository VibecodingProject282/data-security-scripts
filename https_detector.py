#!/usr/bin/env python3
"""
Base44 HTTPS SSL Certificate Detector

This script analyzes a GitHub repository to detect HTTPS URLs and check their SSL certificates
for security issues. It focuses on SSL/TLS configuration and certificate validation.

Usage:
    python https_detector.py <github_repo_url> [--timeout SECONDS]

Example:
    python https_detector.py https://github.com/username/repository
    python https_detector.py https://github.com/username/repository --timeout 30
"""

import re
import ssl
import sys
import socket
import argparse
from typing import List, Dict, Optional
from urllib.parse import urlparse
from datetime import datetime
from utils import get_line_context
from github_client import GitHubClient


class HTTPSDetector:
    """Detects HTTPS URLs and validates their SSL certificates"""

    def __init__(self, timeout: int = 30):
        self.github_client = GitHubClient(timeout)
        self.https_issues = []
        self.timeout = timeout
    
    def detect_https_urls(self, content: str, file_path: str) -> List[Dict]:
        """Detect HTTPS URLs in content"""
        https_issues = []
        found_urls = set()  # Track URLs to avoid duplicates
        
        # HTTPS-specific URL patterns
        https_patterns = [
            # Standard HTTPS URLs
            r'(https://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)',
            # HTTPS URLs in quotes or strings
            r'["\']((https://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?))["\']',
            # HTTPS URLs in configurations
            r'(?:url|endpoint|base_url|api_url|host)\s*[:=]\s*["\']?(https://[^"\'\s<>]+)["\']?',
            # HTTPS URLs in comments or documentation
            r'(?://|#|\*)\s*.*?(https://[^\s<>"\']+)',
        ]
        
        for pattern in https_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Extract the URL (handle different capture groups)
                url = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Clean up the URL
                url = url.strip('\'"')
                
                # Skip if we've already processed this URL
                if url in found_urls:
                    continue
                found_urls.add(url)
                line_number = content[:match.start()].count('\n') + 1
                
                # Analyze HTTPS URL and its SSL certificate
                ssl_issues = self.analyze_https_url(url, line_number, file_path, content)
                https_issues.extend(ssl_issues)
        
        return https_issues
    
    def analyze_https_url(self, url: str, line_number: int, file_path: str, content: str) -> List[Dict]:
        """Analyze HTTPS URL and check SSL certificate"""
        issues = []
        parsed_url = urlparse(url)
        
        if parsed_url.scheme.lower() != 'https':
            return issues
        
        hostname = parsed_url.hostname
        port = parsed_url.port or 443
        
        if not hostname:
            return issues
        
        # Check SSL certificate
        ssl_result = self.check_ssl_certificate(hostname, port)
        
        # Handle SSL verification errors
        if isinstance(ssl_result, str):
            # SSL error occurred
            issues.append(self.create_ssl_issue(
                url, line_number, file_path, content,
                'HTTPS SSL Certificate Issue',
                'HIGH',
                ssl_result,
                'Fix SSL certificate configuration or update certificate'
            ))
        elif isinstance(ssl_result, dict):
            # SSL connection successful, check for other issues
            if ssl_result.get('expired'):
                issues.append(self.create_ssl_issue(
                    url, line_number, file_path, content,
                    'Expired SSL Certificate',
                    'CRITICAL',
                    f'SSL certificate expired on {ssl_result["expiry_date"]}',
                    'Update the SSL certificate immediately'
                ))
            
            if ssl_result.get('expires_soon'):
                issues.append(self.create_ssl_issue(
                    url, line_number, file_path, content,
                    'SSL Certificate Expires Soon',
                    'HIGH',
                    f'SSL certificate expires on {ssl_result["expiry_date"]}',
                    'Plan certificate renewal to avoid service disruption'
                ))
            
            if ssl_result.get('weak_cipher'):
                issues.append(self.create_ssl_issue(
                    url, line_number, file_path, content,
                    'Weak SSL Cipher Suite',
                    'MEDIUM',
                    f'Using weak cipher: {ssl_result["cipher_suite"]}',
                    'Configure stronger cipher suites (TLS 1.2+ recommended)'
                ))
            
            if ssl_result.get('insecure_protocol'):
                issues.append(self.create_ssl_issue(
                    url, line_number, file_path, content,
                    'Insecure TLS Protocol',
                    'HIGH',
                    f'Using insecure protocol: {ssl_result["protocol_version"]}',
                    'Upgrade to TLS 1.2 or higher'
                ))
        
        return issues
    
    def create_ssl_issue(self, url: str, line_number: int, file_path: str, content: str,
                        issue_type: str, severity: str, description: str, recommendation: str) -> Dict:
        """Create an SSL-related security issue"""
        return {
            'type': issue_type,
            'severity': severity,
            'url': url,
            'line': line_number,
            'file': file_path,
            'issue': description,
            'recommendation': recommendation,
            'context': get_line_context(content, line_number)
        }
    
    def check_ssl_certificate(self, hostname: str, port: int = 443):
        """Check SSL certificate for security issues. Returns Dict for valid certs, str for errors, None for connection issues"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    if not cert:
                        return "SSL certificate information not available"
                    
                    ssl_info = {
                        'hostname': hostname,
                        'port': port,
                        'cert': cert,
                        'cipher_suite': cipher[0] if cipher else None,
                        'protocol_version': version,
                        'expired': False,
                        'expires_soon': False,
                        'weak_cipher': False,
                        'insecure_protocol': False
                    }
                    
                    # Check certificate expiry
                    if 'notAfter' in cert:
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        ssl_info['expiry_date'] = expiry_date.strftime('%Y-%m-%d')
                        
                        now = datetime.now()
                        days_until_expiry = (expiry_date - now).days
                        
                        if days_until_expiry < 0:
                            ssl_info['expired'] = True
                        elif days_until_expiry < 30:
                            ssl_info['expires_soon'] = True
                    
                    # Check for weak ciphers
                    if cipher and cipher[0]:
                        weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT']
                        if any(weak in cipher[0] for weak in weak_ciphers):
                            ssl_info['weak_cipher'] = True
                    
                    # Check for insecure protocols
                    if version:
                        insecure_versions = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
                        if version in insecure_versions:
                            ssl_info['insecure_protocol'] = True
                    
                    return ssl_info
                    
        except ssl.SSLCertVerificationError as e:
            return f"SSL certificate verification failed: {str(e)}"
        except ssl.SSLError as e:
            return f"SSL error: {str(e)}"
        except socket.timeout:
            return f"Connection timeout while checking SSL certificate"
        except socket.gaierror:
            return f"DNS resolution failed for hostname: {hostname}"
        except ConnectionRefusedError:
            return f"Connection refused on port {port}"
        except OSError as e:
            return f"Network error: {str(e)}"
        except Exception as e:
            return f"Unexpected error checking SSL certificate: {str(e)}"
    
    def scan_file_for_https(self, file_path: str, relative_path: str, repo_manager) -> List[Dict]:
        """Scan a single local file for HTTPS URLs and SSL issues"""
        https_issues = []
        
        # Get file content from local file
        content = repo_manager.read_file(file_path)
        if not content:
            return https_issues
        
        # Detect HTTPS URLs and SSL issues
        https_issues.extend(self.detect_https_urls(content, relative_path))
        
        # Add file path to each issue
        for issue in https_issues:
            issue['file'] = relative_path
        
        return https_issues
    
    def detect_https_security_issues(self, repo_url: str) -> List[Dict]:
        """Main detection method for HTTPS/SSL security issues"""
        try:
            # Parse GitHub URL
            owner, repo = self.github_client.parse_github_url(repo_url)
            
            # Download repository locally using context manager
            with self.github_client.download_repo_as_zip(owner, repo) as repo_manager:
                if not repo_manager:
                    return []
                
                # Get code files from local repository
                code_files = repo_manager.get_code_files()
                
                if not code_files:
                    return []
                
                # Scan each file
                all_issues = []
                for file_path in code_files:
                    relative_path = repo_manager.get_relative_path(file_path)
                    issues = self.scan_file_for_https(file_path, relative_path, repo_manager)
                    all_issues.extend(issues)
                
                self.https_issues = all_issues
                return all_issues
            
        except Exception as e:
            return []
    
    def print_results(self, issues: List[Dict]):
        """Print analysis results"""
        if not issues:
            print("✅ No HTTPS/SSL security issues detected")
        else:
            print(f"🚨 Found {len(issues)} HTTPS/SSL security issues:")
            
            # Group issues by severity
            by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': []}
            for issue in issues:
                by_severity[issue['severity']].append(issue)
            
            # Print by severity
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM']:
                if by_severity[severity]:
                    print(f"\n🔴 {severity} severity ({len(by_severity[severity])} issues):")
                    for issue in by_severity[severity]:
                        print(f"  📄 {issue['file']} (line {issue['line']})")
                        print(f"     URL: {issue['url']}")
                        print(f"     Issue: {issue['issue']}")
                        print(f"     Recommendation: {issue['recommendation']}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect HTTPS/SSL security issues in Base44 applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python https_detector.py https://github.com/username/repository
        python https_detector.py https://github.com/username/repository --timeout 30
        
        This tool will:
        - Find all HTTPS URLs in the codebase
        - Check SSL certificate validity and security
        - Identify weak cipher suites and protocols
        - Report certificate expiration issues
        """
    )
    
    parser.add_argument('repo_url', help='GitHub repository URL')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for API requests and SSL checks (default: 30)')

    args = parser.parse_args()
    
    # Create detector and run analysis
    detector = HTTPSDetector(timeout=args.timeout)
    issues = detector.detect_https_security_issues(args.repo_url)
    
    # Print results
    detector.print_results(issues)
    
    # Exit with appropriate code
    if issues:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
