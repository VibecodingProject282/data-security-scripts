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
from utils import get_line_context
from github_client import GitHubClient


class SecretDetector:
    """Detects hardcoded secrets in Base44 applications"""

    def __init__(self, timeout: int = 30):
        self.github_client = GitHubClient(timeout)
        self.secrets_found = []
    
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
            # OPENAI API keys
            r'(sk-[A-Za-z0-9]{32,64})',
        ]
        
        for pattern in token_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                secret_value = match.group(1)
                
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
                
                line_number = content[:match.start()].count('\n') + 1
                secrets.append({
                    'type': 'Environment Variable',
                    'value': f"{var_name} = {var_value[:20]}..." if len(var_value) > 20 else f"{var_name} = {var_value}",
                    'line': line_number,
                    'pattern': pattern,
                    'context': get_line_context(content, line_number)
                })
        
        return secrets
    

    
    def scan_file_for_secrets(self, file_path: str, relative_path: str, repo_manager) -> List[Dict]:
        """Scan a single local file for secrets"""
        secrets = []
        
        # Get file content from local file
        content = repo_manager.read_file(file_path)
        if not content:
            return secrets
        
        # Detect different types of secrets
        secrets.extend(self.detect_tokens(content, relative_path))
        secrets.extend(self.detect_environment_variables(content, relative_path))
        
        # Add file path to each secret
        for secret in secrets:
            secret['file'] = relative_path
        
        return secrets
    
    def detect_secrets(self, repo_url: str) -> List[Dict]:
        """Main method to detect secrets in the repository"""
        try:
            if not repo_url or not isinstance(repo_url, str):
                return []
                
            owner, repo = self.github_client.parse_github_url(repo_url)
            
            # Download repository locally using context manager
            with self.github_client.download_repo_as_zip(owner, repo) as repo_manager:
                if not repo_manager:
                    return []
                
                # Get ALL files from local repository (not just code files)
                all_files = repo_manager.find_files()
                
                if not all_files:
                    return []
                
                # Scan each file
                all_secrets = []
                for file_path in all_files:
                    relative_path = repo_manager.get_relative_path(file_path)
                    try:
                        secrets = self.scan_file_for_secrets(file_path, relative_path, repo_manager)
                        if secrets:
                            all_secrets.extend(secrets)
                    except Exception as e:
                        continue
                
                return all_secrets
            
        except ValueError as e:
            return []
        except Exception as e:
            return []
    
    def print_results(self, secrets: List[Dict]):
        """Print analysis results"""
        if not secrets:
            print("✅ No hardcoded secrets detected")
        else:
            print(f"🚨 Found {len(secrets)} potential secrets:")
            
            # Group secrets by file
            secrets_by_file = {}
            for secret in secrets:
                file_path = secret['file']
                if file_path not in secrets_by_file:
                    secrets_by_file[file_path] = []
                secrets_by_file[file_path].append(secret)
            
            # Print results grouped by file
            for file_path, file_secrets in secrets_by_file.items():
                print(f"\n📄 {file_path}:")
                for secret in file_secrets:
                    print(f"  🔴 {secret['type']}: {secret['value']} (line {secret['line']})")


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
    
    try:
        # Validate timeout parameter
        if args.timeout <= 0:
            print("Error: Timeout must be a positive number")
            sys.exit(1)
            
        # Create detector and run analysis
        detector = SecretDetector(timeout=args.timeout)
        secrets = detector.detect_secrets(args.repo_url)
        
        # Print results
        detector.print_results(secrets)
        
        # Exit with appropriate code
        if secrets:
            sys.exit(1)
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
