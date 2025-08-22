#!/usr/bin/env python3
"""
Base44 URL Security Detector

This script analyzes a GitHub repository to detect HTTP/HTTPS URLs in code files
and validates SSL certificates for HTTPS URLs. It helps identify potential security
issues related to insecure communications.

Usage:
    python url_detector.py <github_repo_url> [--timeout SECONDS]

Example:
    python url_detector.py https://github.com/username/repository
    python url_detector.py https://github.com/username/repository --timeout 30
"""

import re
import sys
import ssl
import socket
import argparse
import requests
from typing import Tuple, Optional, List, Dict
from urllib.parse import urlparse
from utils import is_code_file, get_line_context, is_false_positive
from github_client import GitHubClient


class URLDetector:
    """Detects HTTP/HTTPS URLs and validates SSL certificates in Base44 applications"""

    def __init__(self, timeout: int = 30):
        self.github_client = GitHubClient(timeout)
        self.url_issues = []
        self.timeout = timeout
    
    def detect_urls(self, content: str, file_path: str) -> List[Dict]:
        """Detect HTTP and HTTPS URLs in content"""
        url_issues = []
        found_urls = set()  # Track URLs to avoid duplicates
        
        # URL patterns - comprehensive regex for HTTP/HTTPS URLs
        url_patterns = [
            # Standard HTTP/HTTPS URLs
            r'(https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)',
            # URLs in quotes or strings
            r'["\']((https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?))["\']',
            # URLs in configurations or environment variables
            r'(?:url|endpoint|base_url|api_url|host)\s*[:=]\s*["\']?(https?://[^"\'\s<>]+)["\']?',
        ]
        
        for pattern in url_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Extract the URL (handle different capture groups)
                url = match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Clean up the URL (remove quotes if present)
                url = url.strip('\'"')
                
                # Skip if we've already processed this URL
                if url in found_urls:
                    continue
                found_urls.add(url)
                
                # Skip if it's clearly not a real URL (common test patterns)
                if self.is_false_positive_url(url): # remove
                    continue
                
                line_number = content[:match.start()].count('\n') + 1
                
                # Check URL security
                issue = self.analyze_url_security(url, line_number, file_path, content)
                if issue:
                    url_issues.append(issue)
        
        return url_issues
    
    def is_false_positive_url(self, url: str) -> bool:
        """Check if URL is a false positive (test URLs, examples, etc.)"""
        false_positive_patterns = [
            'https://api.base44.com',  # Base44's own secure API
            # Only exclude very specific example patterns
            'http://example.com',
            'https://example.com',
            'http://www.example.com',
            'https://www.example.com',
        ]
        
        url_lower = url.lower()
        # Only filter out exact matches or very specific patterns
        return any(url_lower.startswith(pattern) for pattern in false_positive_patterns)
    
    def analyze_url_security(self, url: str, line_number: int, file_path: str, content: str) -> Optional[Dict]:
        """Analyze URL security and return issue if found"""
        parsed_url = urlparse(url)
        scheme = parsed_url.scheme.lower()
        hostname = parsed_url.hostname
        
        if not hostname:
            return None
        
        if scheme == 'http':
            # HTTP URLs are insecure
            return {
                'type': 'Insecure HTTP URL',
                'severity': 'HIGH',
                'url': url,
                'line': line_number,
                'file': file_path,
                'issue': 'Communication with this URL is not encrypted and may be intercepted',
                'context': get_line_context(content, line_number)
            }
        
        elif scheme == 'https':
            # Check SSL certificate validity
            ssl_issue = self.check_ssl_certificate(hostname, parsed_url.port or 443)
            if ssl_issue:
                return {
                    'type': 'HTTPS SSL Certificate Issue',
                    'severity': 'HIGH',
                    'url': url,
                    'line': line_number,
                    'file': file_path,
                    'issue': ssl_issue,
                    'context': get_line_context(content, line_number)
                }
        
        return None
    
    def check_ssl_certificate(self, hostname: str, port: int = 443) -> Optional[str]:
        """Check SSL certificate validity for a hostname"""
        try:
            # Create SSL context with default settings
            context = ssl.create_default_context()
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # If we get here, the certificate is valid
                    cert = ssock.getpeercert()
                    return None
                    
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
        except Exception as e:
            return f"Unexpected error checking SSL certificate: {str(e)}"
    
    def scan_file_for_urls(self, file_path: str, relative_path: str, repo_manager) -> List[Dict]:
        """Scan a single local file for URL security issues"""
        url_issues = []
        
        # Get file content from local file
        content = repo_manager.read_file(file_path)
        if not content:
            return url_issues
        
        # Detect URLs and security issues
        url_issues.extend(self.detect_urls(content, relative_path))
        
        # Add file path to each issue
        for issue in url_issues:
            issue['file'] = relative_path
        
        return url_issues
    
    def detect_url_security_issues(self, repo_url: str) -> List[Dict]:
        """Main detection method for URL security issues"""
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
                    issues = self.scan_file_for_urls(file_path, relative_path, repo_manager)
                    all_issues.extend(issues)
                
                self.url_issues = all_issues
                return all_issues
            
        except Exception as e:
            print(f"❌ Error during analysis: {str(e)}")
            return []
    
    def print_results(self, repo_url: str, issues: List[Dict]):
        """Print analysis results in a formatted way"""
        if not issues:
            print("✅ No URL security issues detected")
        else:
            print(f"🚨 Found {len(issues)} URL security issues:")
            
            # Group issues by file
            issues_by_file = {}
            for issue in issues:
                file_path = issue['file']
                if file_path not in issues_by_file:
                    issues_by_file[file_path] = []
                issues_by_file[file_path].append(issue)
            
            # Print results grouped by file
            for file_path, file_issues in issues_by_file.items():
                print(f"\n📄 {file_path}:")
                for issue in file_issues:
                    print(f"  🔴 {issue['type']}: {issue['url']} (line {issue['line']})")
                    print(f"     Issue: {issue['issue']}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect URL security issues in Base44 applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python url_detector.py https://github.com/username/repository
        python url_detector.py https://github.com/username/repository --timeout 30
        
        This tool will:
        - Detect HTTP URLs and warn about insecure communication
        - Validate SSL certificates for HTTPS URLs
        - Report any certificate validation issues
        """
    )
    
    parser.add_argument('repo_url', help='GitHub repository URL')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for API requests and SSL checks (default: 30)')

    args = parser.parse_args()
    
    # Create detector and run analysis
    detector = URLDetector(timeout=args.timeout)
    issues = detector.detect_url_security_issues(args.repo_url)
    
    # Print results
    detector.print_results(args.repo_url, issues)
    
    # Exit with appropriate code
    if issues:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()