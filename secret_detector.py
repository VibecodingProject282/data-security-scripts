#!/usr/bin/env python3
"""
Base44 Secret Detector

This script analyzes a GitHub repository to detect hardcoded API keys, tokens, and other secrets
in Base44 applications. It scans through all code files recursively to find potential security issues.

Usage:
    python secret_detector.py <github_repo_url> [--timeout SECONDS]

Example:
    python secret_detector.py https://github.com/username/repository
    python secret_detector.py https://github.com/username/repository --timeout 30
"""

import re
import sys
import json
import argparse
from typing import Tuple, Optional, List, Dict
from utils import is_code_file, get_line_context, is_false_positive
from github_client import GitHubClient


class SecretDetector:
    """Detects hardcoded secrets in Base44 applications"""

    def __init__(self, timeout: int = 30):
        self.github_client = GitHubClient(timeout)
        self.secrets_found = []
    
    # def detect_api_keys(self, content: str, file_path: str) -> List[Dict]:
    #     """Detect API keys in content"""
    #     secrets = []
        
    #     # Pattern for API keys (high entropy strings)
    #     api_key_patterns = [
    #         # API key with common prefixes
    #         r'["\'](sk_[a-zA-Z0-9]{32,})["\']',  # Stripe
    #         r'["\'](pk_[a-zA-Z0-9]{32,})["\']',  # Stripe public
    #         r'["\'](AIza[a-zA-Z0-9]{35})["\']',  # Google API
    #     ]
        
    #     for pattern in api_key_patterns:
    #         matches = re.finditer(pattern, content)
    #         for match in matches:
    #             secret_value = match.group(1)
                
    #             # Skip if it's clearly not a secret (common patterns)
    #             if is_false_positive(secret_value):
    #                 continue
                
    #             line_number = content[:match.start()].count('\n') + 1
    #             secrets.append({
    #                 'type': 'API Key',
    #                 'value': secret_value[:20] + '...' if len(secret_value) > 20 else secret_value,
    #                 'line': line_number,
    #                 'pattern': pattern,
    #                 'context': get_line_context(content, line_number)
    #             })
        
    #     return secrets
    
    def detect_tokens(self, content: str, file_path: str) -> List[Dict]:
        """Detect various types of tokens"""
        secrets = []
        
        # Token patterns
        token_patterns = [
            # JWT tokens
            r'(eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})',
            # OAuth tokens
            r'(ya29\.[a-zA-Z0-9_-]+)',  # Google OAuth
            # Access tokens
            r'(access_token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\'])',
            r'(token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{32,})["\'])',
        ]
        
        for pattern in token_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                secret_value = match.group(1)
                
                # Skip if it's clearly not a secret
                if is_false_positive(secret_value): # remove
                    continue
                
                line_number = content[:match.start()].count('\n') + 1
                secrets.append({
                    'type': 'Token',
                    'value': secret_value[:20] + '...' if len(secret_value) > 20 else secret_value,
                    'line': line_number,
                    'pattern': pattern,
                    'context': get_line_context(content, line_number)
                })
        
        return secrets
    
    def detect_environment_variables(self, content: str, file_path: str) -> List[Dict]:
        """Detect hardcoded environment variables"""
        secrets = []
        
        # Environment variable patterns
        env_patterns = [
            r'(REACT_APP_[A-Z_]+["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,}))',
            r'(VITE_[A-Z_]+["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,}))',
            r'(NEXT_PUBLIC_[A-Z_]+["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,}))',
            r'([A-Z_]+_API_KEY["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,}))',
            r'([A-Z_]+_SECRET["\']?\s*[:=]\s*["\']?([a-zA-Z0-9]{16,}))',
        ]

        for pattern in env_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                var_value = match.group(2)
                
                # Skip if it's clearly not a secret
                if is_false_positive(var_value):
                    continue
                
                line_number = content[:match.start()].count('\n') + 1
                secrets.append({
                    'type': 'Environment Variable',
                    'value': f"{var_name} = {var_value[:20]}..." if len(var_value) > 20 else f"{var_name} = {var_value}",
                    'line': line_number,
                    'pattern': pattern,
                    'context': get_line_context(content, line_number)
                })
        
        return secrets
    

    
    def scan_file_for_secrets(self, owner: str, repo: str, file_path: str) -> List[Dict]:
        """Scan a single file for secrets"""
        secrets = []
        
        # Get file content
        content = self.github_client.get_file_content(owner, repo, file_path)
        if not content:
            return secrets
        
        # Detect different types of secrets
        # secrets.extend(self.detect_api_keys(content, file_path))
        secrets.extend(self.detect_tokens(content, file_path))
        secrets.extend(self.detect_environment_variables(content, file_path))
        
        # Add file path to each secret
        for secret in secrets:
            secret['file'] = file_path
        
        return secrets
    
    def detect_secrets(self, repo_url: str) -> List[Dict]:
        """Main method to detect secrets in the repository"""
        try:
            owner, repo = self.github_client.parse_github_url(repo_url)
            print(f"🔍 Scanning repository: {owner}/{repo}")
            
            # Get code files
            code_files = self.github_client.get_code_files(owner, repo)
            if not code_files:
                print("❌ Could not retrieve repository file tree")
                return []
            
            print(f"💻 Found {len(code_files)} code files to scan")
            
            # Scan each code file
            all_secrets = []
            for i, file_path in enumerate(code_files, 1):
                #########################################################################
                if file_path != "src/pages/Products.jsx": # Skip specific file for testing, remove this line in production
                    continue
                
                print(f"🔍 Scanning file {i}/{len(code_files)}: {file_path}")
                
                try:
                    secrets = self.scan_file_for_secrets(owner, repo, file_path)
                    if secrets:
                        all_secrets.extend(secrets)
                        print(f"🚨 Found {len(secrets)} potential secrets in {file_path}")
                except Exception as e:
                    print(f"⚠️  Error scanning {file_path}: {e}")
                
                # Add small delay to avoid rate limiting
                import time
                time.sleep(0.1)
            
            return all_secrets
            
        except Exception as e:
            print(f"❌ Error analyzing repository: {e}")
            return []
    
    def print_results(self, repo_url: str, secrets: List[Dict]):
        """Print analysis results"""
        print(f"\n{'='*60}")
        print(f"🔐 SECRET DETECTOR RESULTS")
        print(f"{'='*60}")
        print(f"Repository: {repo_url}")
        
        if not secrets:
            print(f"✅ No hardcoded secrets detected!")
            print(f"🎉 The codebase appears to be secure from hardcoded secrets.")
        else:
            print(f"🚨 FOUND {len(secrets)} POTENTIAL SECRETS!")
            print(f"⚠️  CRITICAL SECURITY ISSUE DETECTED!")
            
            # Group secrets by file
            secrets_by_file = {}
            for secret in secrets:
                file_path = secret['file']
                if file_path not in secrets_by_file:
                    secrets_by_file[file_path] = []
                secrets_by_file[file_path].append(secret)
            
            # Print results grouped by file
            for file_path, file_secrets in secrets_by_file.items():
                print(f"\n📄 File: {file_path}")
                print(f"{'-' * 50}")
                
                for secret in file_secrets:
                    print(f"🔴 Type: {secret['type']}")
                    print(f"   Value: {secret['value']}")
                    print(f"   Line: {secret['line']}")
                    print(f"   Pattern: {secret['pattern']}")
                    print(f"   Context:")
                    for line in secret['context'].split('\n'):
                        print(f"     {line}")
                    print()
        
        print(f"{'='*60}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect hardcoded secrets in Base44 applications',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python secret_detector.py https://github.com/username/repository
        python secret_detector.py https://github.com/username/repository --timeout 30
        """
    )
    
    parser.add_argument('repo_url', help='GitHub repository URL')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for API requests (default: 30)')

    args = parser.parse_args()
    
    # Create detector and run analysis
    detector = SecretDetector(timeout=args.timeout)
    secrets = detector.detect_secrets(args.repo_url)
    
    # Print results
    detector.print_results(args.repo_url, secrets)
    
    # Exit with appropriate code
    if secrets:
        print(f"\n🔴 Exiting with code 1 - {len(secrets)} secrets found")
        sys.exit(1)
    else:
        print(f"\n🟢 Exiting with code 0 - No secrets found")
        sys.exit(0)


if __name__ == "__main__":
    main()
