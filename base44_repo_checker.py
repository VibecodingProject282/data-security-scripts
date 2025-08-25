#!/usr/bin/env python3
"""
Base44 Repository Detector

This script analyzes a GitHub repository to determine if it was created by Base44.
It focuses on the strongest indicators for maximum accuracy with minimal code.

Usage:
    python base44_detector.py <github_repo_url> [--timeout SECONDS]

Example:
    python base44_detector.py https://github.com/username/repository
    python base44_detector.py https://github.com/username/repository --timeout 30
"""

import sys
import json
import argparse
from typing import Tuple, Optional, List
from github_client import GitHubClient


class Base44Detector:
    """Professional detector that checks the strongest Base44 indicators"""
    
    def __init__(self, timeout: int = 10):
        self.github_client = GitHubClient(timeout)
        self.project_id = None
    
    def check_base44_indicators(self, owner: str, repo: str) -> dict:
        """Check for strong Base44 indicators using local file download"""
        indicators = {}
        
        # Download repository locally using context manager
        # Initialize all indicators to False
        indicators = {
            'has_base44_sdk': False,
            'has_base44_app_name': False,
            'has_base44_client': False,
            'has_base44_readme': False,
            'has_base44_logo': False,
            'has_base44_title': False
        }

        try:
            with self.github_client.download_repo_as_zip(owner, repo) as repo_manager:
                if not repo_manager:
                    return {'error': 'Could not download repository'}

                # Helper to read file content safely
                def get_file_content(filename):
                    try:
                        file = repo_manager.find_file_by_name(filename)
                        return repo_manager.read_file(file) if file else None
                    except Exception as e:
                        print(f"Warning: Error reading {filename}: {e}")
                        return None

                # 1. Check package.json for @base44/sdk and name
                content = get_file_content("package.json")
                if content:
                    try:
                        pkg_data = json.loads(content)
                        dependencies = pkg_data.get('dependencies', {})
                        indicators['has_base44_sdk'] = '@base44/sdk' in dependencies
                        indicators['has_base44_app_name'] = pkg_data.get('name') == 'base44-app'
                    except json.JSONDecodeError as e:
                        print(f"Warning: Invalid JSON in package.json: {e}")

                # 2. Check base44Client.js
                content = get_file_content("base44Client.js")
                if content:
                    indicators['has_base44_client'] = (
                        '@base44/sdk' in content and 
                        'createClient' in content and
                        'appId' in content
                    )
                    try:
                        self.project_id = content.split('appId: "')[1].split('"')[0]
                    except (IndexError, AttributeError):
                        self.project_id = None
                else:
                    self.project_id = None

                # 3. Check README.md
                content = get_file_content("README.md")
                if content:
                    indicators['has_base44_readme'] = (
                        'This app was created automatically by Base44' in content and
                        'app@base44.com' in content
                        )

                # 4. Check index.html
                content = get_file_content("index.html")
                if content:
                    indicators['has_base44_logo'] = 'https://base44.com/logo_v2.svg' in content
                    indicators['has_base44_title'] = 'Base44 APP' in content

        except Exception as e:
            print(f"Error checking Base44 indicators: {e}")
            return {'error': str(e)}

        return indicators
    
    def detect_base44_repository(self, repo_url: str) -> Tuple[bool, float, dict]:
        """
        Detect if repository was created by Base44
        
        Returns:
            Tuple of (is_base44, confidence_score, indicators)
        """
        try:
            if not repo_url or not isinstance(repo_url, str):
                return False, 0.0, {'error': 'Invalid repository URL'}
                
            owner, repo = self.github_client.parse_github_url(repo_url)
            
            indicators = self.check_base44_indicators(owner, repo)
            
            if 'error' in indicators:
                return False, 0.0, indicators
            
            # Calculate confidence (simple average of indicators)
            confidence = sum(indicators.values()) / len(indicators)
            
            # Consider it Base44 if at least 1 indicator is present
            is_base44 = confidence > 0.1
            
            return is_base44, confidence, indicators
            
        except ValueError as e:
            return False, 0.0, {'error': f'Invalid repository URL: {e}'}
        except Exception as e:
            return False, 0.0, {'error': str(e)}
    
    def print_results(self, repo_url: str, is_base44: bool, confidence: float, indicators: dict):
        """Print analysis results"""
        if 'error' in indicators:
            print(f"❌ Error: {indicators['error']}")
            return
        
        if is_base44:
            print(f"✅ Base44 project detected (confidence: {confidence:.1%})")
            if self.project_id:
                print(f"Project ID: {self.project_id}")
        else:
            print(f"❌ Not a Base44 project (confidence: {confidence:.1%})")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect if a GitHub repository was created by Base44',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
        Examples:
        python base44_detector.py https://github.com/username/repository
        python base44_detector.py https://github.com/username/repository --timeout 30
        """
    )
    
    parser.add_argument('repo_url', help='GitHub repository URL')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds for recursive file search (default: 10)')

    args = parser.parse_args()
    
    try:
        # Validate timeout parameter
        if args.timeout <= 0:
            print("Error: Timeout must be a positive number")
            sys.exit(1)
            
        # Analyze repository
        detector = Base44Detector(timeout=args.timeout)
        is_base44, confidence, indicators = detector.detect_base44_repository(args.repo_url)
        
        # Print results
        detector.print_results(args.repo_url, is_base44, confidence, indicators)
        
        # Exit with appropriate code
        sys.exit(0 if is_base44 else 1)
        
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
