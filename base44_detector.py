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
        """Check for strong Base44 indicators"""
        indicators = {}
        
        # 1. Check package.json for @base44/sdk and name
        package_json = self.github_client.get_file_content_recursive(owner, repo, "package.json")
        if package_json:
            try:
                pkg_data = json.loads(package_json)
                dependencies = pkg_data.get('dependencies', {})
                indicators['has_base44_sdk'] = '@base44/sdk' in dependencies
                indicators['has_base44_app_name'] = pkg_data.get('name') == 'base44-app'
            except json.JSONDecodeError:
                indicators['has_base44_sdk'] = False
                indicators['has_base44_app_name'] = False
        else:
            print(f"No package.json found for {owner}/{repo}")
            indicators['has_base44_sdk'] = False
            indicators['has_base44_app_name'] = False
        
        # 2. Check base44Client.js
        base44_client = self.github_client.get_file_content_recursive(owner, repo, "src/api/base44Client.js")
        if base44_client is None:
            print(f"No base44Client.js found for {owner}/{repo}")
            self.project_id = None
        else:
            indicators['has_base44_client'] = (
            '@base44/sdk' in base44_client and 
            'createClient' in base44_client and
            'appId' in base44_client
            )
            self.project_id = base44_client.split('appId: "')[1].split('"')[0]
        
        # 3. Check README.md
        readme = self.github_client.get_file_content_recursive(owner, repo, "README.md")
        if readme is None:
            print(f"No README.md found for {owner}/{repo}")
            indicators['has_base44_readme'] = False
        else:
            indicators['has_base44_readme'] = (
            'This app was created automatically by Base44' in readme and
            'app@base44.com' in readme
        )
        
        # 4. Check index.html
        index_html = self.github_client.get_file_content_recursive(owner, repo, "index.html")
        if index_html is None:
            print(f"No index.html found for {owner}/{repo}")
            indicators['has_base44_logo'] = False
            indicators['has_base44_title'] = False
        else:
            indicators['has_base44_logo'] = (
            'https://base44.com/logo_v2.svg' in index_html
            )
            indicators['has_base44_title'] = (
                'Base44 APP' in index_html
            )
        
        return indicators
    
    def detect_base44_repository(self, repo_url: str) -> Tuple[bool, float, dict]:
        """
        Detect if repository was created by Base44
        
        Returns:
            Tuple of (is_base44, confidence_score, indicators)
        """
        try:
            owner, repo = self.github_client.parse_github_url(repo_url)
            print(f"Analyzing repository: {owner}/{repo}")
            
            indicators = self.check_base44_indicators(owner, repo)
            
            # Calculate confidence (simple average of indicators)
            confidence = sum(indicators.values()) / len(indicators)
            
            # Consider it Base44 if at least 1 indicator is present
            is_base44 = confidence > 0.1
            
            return is_base44, confidence, indicators
            
        except Exception as e:
            print(f"Error analyzing repository: {e}")
            return False, 0.0, {'error': str(e)}
    
    def print_results(self, repo_url: str, is_base44: bool, confidence: float, indicators: dict):
        """Print analysis results"""
        print(f"\n{'='*50}")
        print(f"BASE44 REPOSITORY DETECTOR")
        print(f"{'='*50}")
        print(f"Repository: {repo_url}")
        print(f"Result: {'✅ BASE44 PROJECT' if is_base44 else '❌ NOT BASE44'}")
        print(f"Confidence: {confidence:.1%}")
        print(f"Project ID: {self.project_id if self.project_id else 'Not found'}")
        
        if 'error' in indicators:
            print(f"❌ Error: {indicators['error']}")
            return
        
        print(f"\n🔍 INDICATORS:")
        indicator_names = {
            'has_base44_sdk': '@base44/sdk dependency',
            'has_base44_app_name': 'base44-app package name',
            'has_base44_client': 'base44Client.js file',
            'has_base44_readme': 'Base44 README signature',
            'has_base44_logo': 'Base44 logo in HTML',
            'has_base44_title': 'Base44 APP title'
        }
        
        for key, found in indicators.items():
            status = "✅" if found else "❌"
            name = indicator_names.get(key, key)
            print(f"  {status} {name}")
        
        print(f"{'='*50}")


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
    
    # Analyze repository
    detector = Base44Detector(timeout=args.timeout)
    is_base44, confidence, indicators = detector.detect_base44_repository(args.repo_url)
    
    # Print results
    detector.print_results(args.repo_url, is_base44, confidence, indicators)
    
    # Exit with appropriate code
    sys.exit(0 if is_base44 else 1)


if __name__ == "__main__":
    main()
