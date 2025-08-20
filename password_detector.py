#!/usr/bin/env python3
"""
Base44 Password Storage Vulnerability Detector

This script analyzes Base44 projects to detect potential insecure password storage by:
1. Finding database tables with data using limit=1 queries
2. Checking column names for "password" strings
3. Alerting about tables that might store passwords insecurely

Usage:
    python password_detector.py --token BEARER_TOKEN --repo-url GITHUB_REPO_URL
"""

import sys
import argparse
from typing import List, Optional, Tuple
from base44_client import Base44App
from github_client import GitHubClient


class PasswordDetector:
    """Detects potential insecure password storage in Base44 projects"""
    
    def __init__(self, bearer_token: str, repo_url: str):
        self.bearer_token = bearer_token
        self.github_client = GitHubClient()
        
        # Extract owner and repo from URL and get Base44 client
        owner, repo = self.github_client.parse_github_url(repo_url)
        self.app = self.github_client.get_base44_client_for_repo(owner, repo, bearer_token)
        
        if not self.app:
            raise ValueError(f"Could not find Base44 project ID in repository {repo_url}")
        
        self.project_id = self.app.project_id
        
        self.tables_with_passwords = []
    
    def check_password_columns(self, entity: str) -> bool:
        """Check if a table has columns containing 'password' in their names"""
        try:
            columns_name = self.app.get_entities_columns(entity)
            # Check if we got actual data
            if isinstance(columns_name, list) and len(columns_name) > 0:
                for column_name in columns_name:
                    if "password" in column_name.lower():
                        print(f"🚨 Found password column: '{column_name}' in table '{entity}'")
                        return True
        except Exception as e:
            print(f"Error checking password columns in table {entity}: {e}")
        return False

    def check_table_no_data(self, entity: str) -> None:
        """Check if a table has no data or we can't access it by trying to write an invalid Row to the table"""
        print(f"🚨 Table '{entity}' has no data or we can't access it by trying to write an invalid Row to the table")
        pass # future work: implement actual check

    def detect_password_vulnerabilities(self) -> None:
        """Main method to detect password storage vulnerabilities"""
        # Step 1: Get all entities
        entities = self.app.get_base44_entities()
        
        # Step 2: Check each entity for password columns
        for entity in entities:
            if self.app.check_base44_table_has_data(entity):
                if self.check_password_columns(entity):
                    self.tables_with_passwords.append(entity)
            else:
                #self.check_table_no_data(entity)
                pass
        
        # Step 3: Report findings
        if self.tables_with_passwords:
            print(f"🚨 Found password storage vulnerabilities in tables: {', '.join(self.tables_with_passwords)}")
        else:
            print("✅ No password storage vulnerabilities detected")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect potential insecure password storage in Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--token', required=True, help='Bearer token for Base44 API')
    parser.add_argument('--repo-url', required=True, help='GitHub repository URL')
    
    args = parser.parse_args()
    
    # Create detector and run analysis
    detector = PasswordDetector(args.token, args.repo_url)
    detector.detect_password_vulnerabilities()
    
    # Exit with appropriate code
    if detector.tables_with_passwords:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
