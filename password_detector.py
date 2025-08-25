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
        try:
            self.bearer_token = bearer_token
            self.github_client = GitHubClient()
            
            if not bearer_token or not isinstance(bearer_token, str):
                raise ValueError("Invalid bearer token provided")
            
            if not repo_url or not isinstance(repo_url, str):
                raise ValueError("Invalid repository URL provided")
            
            # Extract owner and repo from URL and get Base44 client
            owner, repo = self.github_client.parse_github_url(repo_url)
            self.app = self.github_client.get_base44_client_for_repo(owner, repo, bearer_token)
            
            if not self.app:
                raise ValueError(f"Could not find Base44 project ID in repository {repo_url}")
            
            self.project_id = self.app.project_id
            self.tables_with_passwords = []
            
        except Exception as e:
            print(f"Error initializing PasswordDetector: {e}")
            raise
    
    def check_password_columns(self, columns_names: List[str]) -> bool:
        """Check if there are columns containing 'password' in their names"""
        for column_name in columns_names:
            if "password" in column_name.lower():
                print(f"🚨 Found password column: '{column_name}'")
                return True
        return False

    def check_table_no_data(self, entity: str) -> None:
        """Check if a table has no data or we can't access it by trying to write an invalid Row to the table"""
        print(f"🚨 Table '{entity}' has no data or we can't access it by trying to write an invalid Row to the table")
        pass # future work: implement actual check

    def detect_password_vulnerabilities(self) -> None:
        """Main method to detect password storage vulnerabilities"""
        try:
            entities_columns = self.app.get_entities_columns()
            
            if not isinstance(entities_columns, dict):
                print("Error: Failed to retrieve entities and columns")
                return
            
            if not entities_columns:
                print("Warning: No entities found in the project")
                return
        
            for entity, columns in entities_columns.items():
                try:
                    if not isinstance(columns, list):
                        print(f"Warning: Invalid column data for entity {entity}")
                        continue
                        
                    if self.check_password_columns(columns):
                        self.tables_with_passwords.append(entity)
                except Exception as e:
                    print(f"Error checking entity {entity}: {e}")
                    continue
        
            if self.tables_with_passwords:
                print(f"🚨 Found password storage vulnerabilities in tables: {', '.join(self.tables_with_passwords)}")
            else:
                print("✅ No password storage vulnerabilities detected")
                
        except Exception as e:
            print(f"Error during password vulnerability detection: {e}")
            raise


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect potential insecure password storage in Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--token', required=True, help='Bearer token for Base44 API')
    parser.add_argument('--repo-url', required=True, help='GitHub repository URL')
    
    args = parser.parse_args()
    
    try:
        # Create detector and run analysis
        detector = PasswordDetector(args.token, args.repo_url)
        detector.detect_password_vulnerabilities()
        
        # Exit with appropriate code
        if detector.tables_with_passwords:
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
