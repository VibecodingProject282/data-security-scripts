#!/usr/bin/env python3
"""
Base44 Anonymous Access Detector

This script analyzes Base44 projects to detect anonymous access vulnerabilities by:
1. Extracting project ID from the repository
2. Attempting to access entities without authentication
3. Identifying entities that allow anonymous data access
4. Reporting accessible entities as security vulnerabilities

Usage:
    python anonymous_app_detector.py --repo-url GITHUB_REPO_URL
"""

import sys
import argparse
import requests
from typing import List, Dict, Any
from github_client import GitHubClient


class AnonymousAppDetector:
    """Detects anonymous access vulnerabilities in Base44 projects"""

    def __init__(self, repo_url: str):
        self.repo_url = repo_url
        self.github_client = GitHubClient()
        
        # Extract owner and repo from URL
        owner, repo = self.github_client.parse_github_url(repo_url)
        self.owner = owner
        self.repo = repo
        
        # Get project ID without authentication
        self.app = self.github_client.get_base44_client_for_repo(owner, repo)
        if not self.app:
            raise ValueError(f"Could not find Base44 app in repository {repo_url}")

        self.session = requests.Session()
        self.timeout = 30
        self.accessible_entities = []
    
    def detect_anonymous_access(self) -> None:
        """Main method to detect anonymous access vulnerabilities"""
        print(f"🔍 Checking anonymous access for app: {self.app.project_id}")

        # Try to get entities without authentication
        response = self.app.get_base44_entities()

        if not isinstance(response, list):
            if response.get("error_code") == 403:  # Forbidden
                print("✅ No anonymous access detected")
            else:  # if it failed with a different error
                print("An Error occurred While fetching entities")
            return
        
        entities = response
        # Check each entity for data access
        for entity in entities:
            if self.app.check_base44_table_has_data(entity):
                self.accessible_entities.append(entity)
                print(f"🚨 Entity '{entity}' allows anonymous data access")
        
        if self.accessible_entities:
            print(f"\n🚨 Anonymous access vulnerability: {len(self.accessible_entities)} entities with accessible data")
        else:
            print("✅ No entities with anonymous data access found")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect anonymous access vulnerabilities in Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('repo_url', help='GitHub repository URL')

    args = parser.parse_args()
    
    try:
        # Create detector and run analysis
        detector = AnonymousAppDetector(args.repo_url)
        detector.detect_anonymous_access()
        
        # Exit with appropriate code
        if detector.accessible_entities:
            sys.exit(1)
        sys.exit(0)
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
