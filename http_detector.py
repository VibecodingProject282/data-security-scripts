#!/usr/bin/env python3
"""
Base44 HTTP URL Detector

This script analyzes a GitHub repository to detect insecure HTTP URLs in code files.
It focuses specifically on finding unencrypted HTTP communication that could be intercepted.

Usage:
    python http_detector.py <github_repo_url> [--timeout SECONDS]

Example:
    python http_detector.py https://github.com/username/repository
    python http_detector.py https://github.com/username/repository --timeout 30
"""

import re
import sys
import argparse
from typing import List, Dict, Optional
from urllib.parse import urlparse
from utils import get_line_context
from github_client import GitHubClient


class HTTPDetector:
    """Detects insecure HTTP URLs in Base44 applications"""

    def __init__(self, timeout: int = 30):
        self.github_client = GitHubClient(timeout)
        self.http_issues = []
    
    def detect_http_urls(self, content: str, file_path: str) -> List[Dict]:
        """Detect HTTP URLs in content"""
        http_issues = []
        found_urls = set()  # Track URLs to avoid duplicates
        
        # HTTP-specific URL patterns
        http_patterns = [
            # Standard HTTP URLs
            r'(http://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)',
            # HTTP URLs in quotes or strings
            r'["\']((http://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*)?(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?))["\']',
            # HTTP URLs in configurations
            r'(?:url|endpoint|base_url|api_url|host)\s*[:=]\s*["\']?(http://[^"\'\s<>]+)["\']?',
            # HTTP URLs in comments or documentation
            r'(?://|#|\*)\s*.*?(http://[^\s<>"\']+)',
        ]
        
        for pattern in http_patterns:
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
                
                # Create HTTP security issue
                issue = self.create_http_issue(url, line_number, file_path, content)
                if issue:
                    http_issues.append(issue)
        
        return http_issues
    
    def create_http_issue(self, url: str, line_number: int, file_path: str, content: str) -> Optional[Dict]:
        """Create an HTTP security issue"""
        parsed_url = urlparse(url)
        
        if parsed_url.scheme.lower() != 'http':
            return None
        
        return {
            'type': 'Insecure HTTP URL',
            'severity': 'CRITICAL',
            'url': url,
            'line': line_number,
            'file': file_path,
            'issue': f'HTTP communication is not encrypted and may be intercepted by attackers',
            'recommendation': f'Replace with HTTPS: {url.replace("http://", "https://", 1)}',
            'context': get_line_context(content, line_number)
        }
    
    def scan_file_for_http(self, file_path: str, relative_path: str, repo_manager) -> List[Dict]:
        """Scan a single local file for HTTP URLs"""
        http_issues = []
        
        # Get file content from local file
        content = repo_manager.read_file(file_path)
        if not content:
            return http_issues
        
        # Detect HTTP URLs
        http_issues.extend(self.detect_http_urls(content, relative_path))
        
        # Add file path to each issue
        for issue in http_issues:
            issue['file'] = relative_path
        
        return http_issues
    
    def detect_http_security_issues(self, repo_url: str) -> List[Dict]:
        """Main detection method for HTTP security issues"""
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
                    issues = self.scan_file_for_http(file_path, relative_path, repo_manager)
                    all_issues.extend(issues)
                
                self.http_issues = all_issues
                return all_issues
            
        except Exception as e:
            print(f"❌ Error during HTTP analysis: {str(e)}")
            return []
    
    def print_results(self, repo_url: str, issues: List[Dict]):
        """Print analysis results"""
        if not issues:
            print("✅ No insecure HTTP URLs detected")
        else:
            print(f"🚨 Found {len(issues)} insecure HTTP URLs:")
            
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
                        print(f"     Recommendation: {issue['recommendation']}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect insecure HTTP URLs in Base44 applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python http_detector.py https://github.com/username/repository
        python http_detector.py https://github.com/username/repository --timeout 30
        
        This tool will:
        - Find all HTTP URLs in the codebase
        - Classify them by security risk level
        - Suggest HTTPS replacements
        """
    )
    
    parser.add_argument('repo_url', help='GitHub repository URL')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for API requests (default: 30)')

    args = parser.parse_args()
    
    try:
        # Validate timeout parameter
        if args.timeout <= 0:
            print("Error: Timeout must be a positive number")
            sys.exit(1)
            
        # Create detector and run analysis
        detector = HTTPDetector(timeout=args.timeout)
        issues = detector.detect_http_security_issues(args.repo_url)
        
        # Print results
        detector.print_results(args.repo_url, issues)
        
        # Exit with appropriate code
        if issues:
            sys.exit(1)
        else:
            sys.exit(0)
            
    except ValueError as e:
        print(f"Configuration error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
