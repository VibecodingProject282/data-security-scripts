#!/usr/bin/env python3
"""
Base44 IDOR Vulnerability Detector

This script analyzes Base44 projects to detect potential IDOR vulnerabilities by:
1. Finding database tables with data using limit=1 queries
2. Checking if these tables are referenced in the frontend code
3. Alerting about tables that might be vulnerable to IDOR attacks

Usage:
    python idor_detector.py --token BEARER_TOKEN --repo-url GITHUB_REPO_URL
"""

import re
import sys
import argparse
from typing import List, Optional, Tuple
from base44_client import Base44App
from github_client import GitHubClient


class IDORDetector:
    """Detects potential IDOR vulnerabilities in Base44 projects"""
    
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
            self.base44_app = self.github_client.get_base44_client_for_repo(owner, repo, bearer_token)
            
            if not self.base44_app:
                raise ValueError(f"Could not find Base44 project ID in repository {repo_url}")
            
            self.project_id = self.base44_app.project_id
            self.postman_tables = []
            
        except Exception as e:
            print(f"Error initializing IDORDetector: {e}")
            raise
    
    def search_tables_in_file(self, file_content: str, tables: List[str]) -> List[str]:
        """Search for table names in file content using import statements"""
        found_tables = []
        
        # Look for import statements like: import { Product } from "@/api/entities";
        import_pattern = r'import\s*{\s*([^}]+)\s*}\s*from\s*["\']@/api/entities["\']'
        matches = re.findall(import_pattern, file_content)
        
        for match in matches:
            # Split by comma and clean up whitespace
            entity_list = [entity.strip() for entity in match.split(',')]
            for entity in entity_list:
                if entity in tables:
                    found_tables.append(entity)
        
        return found_tables

    def check_frontend_references(self, repo_url: str, data_tables: List[str], all_tables: List[str]) -> Tuple[List[str], List[str]]:
        """Check which tables are referenced in the frontend code"""
        try:
            if not data_tables and not all_tables:
                return [], []
                
            owner, repo = self.github_client.parse_github_url(repo_url)
            
            # Download repository locally using context manager
            with self.github_client.download_repo_as_zip(owner, repo) as repo_manager:
                if not repo_manager:
                    return [], []
                
                # Find all JavaScript/TypeScript files in pages directory
                pages_files = repo_manager.find_files_in_directory('pages', ['.jsx', '.js', '.tsx', '.ts'])
                
                if not pages_files:
                    return [], []
                
                referenced_tables = set()
                
                for file_path in pages_files:
                    try:
                        file_content = repo_manager.read_file(file_path)
                        if file_content:
                            found_tables = self.search_tables_in_file(file_content, all_tables)
                            if found_tables:
                                referenced_tables.update(found_tables)
                    except Exception as e:
                        continue
                
                # Return tables that are NOT referenced in frontend
                high_risk_tables = [table for table in data_tables if table not in referenced_tables]
                low_risk_tables = [table for table in all_tables if table not in referenced_tables and table not in high_risk_tables]
                return high_risk_tables, low_risk_tables

        except Exception as e:
            return [], []
    
    def detect_idor_vulnerabilities(self, repo_url: str) -> bool:
        """Main method to detect IDOR vulnerabilities"""
        # Step 1: Find tables with data
        self.data_tables = self.base44_app.find_tables_with_data()   # high risk if not empty
        self.all_tables = self.base44_app.get_base44_entities()      # low risk if not empty

        if not self.all_tables:
            return False
        
        # Step 2: Check frontend references
        self.high_risk_tables, self.low_risk_tables = self.check_frontend_references(repo_url, self.data_tables, self.all_tables)
        
        # Return True if there are any risk tables
        return bool(self.high_risk_tables or self.low_risk_tables)
    
    def print_results(self):
        """Print the IDOR detection results"""
        if hasattr(self, 'high_risk_tables') and self.high_risk_tables:
            print(f"\n🚨 HIGH IDOR risk tables: {', '.join(self.high_risk_tables)}")
        if hasattr(self, 'low_risk_tables') and self.low_risk_tables:
            print(f"\n⚠️  LOW IDOR risk tables: {', '.join(self.low_risk_tables)}")
        
        # If no risks found, show success message
        if not (hasattr(self, 'high_risk_tables') and self.high_risk_tables) and not (hasattr(self, 'low_risk_tables') and self.low_risk_tables):
            print("✅ No IDOR vulnerabilities detected")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect potential IDOR vulnerabilities in Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--token', required=True, help='Bearer token for Base44 API')
    parser.add_argument('--repo-url', required=True, help='GitHub repository URL')
    
    args = parser.parse_args()
    
    try:
        # Create detector and run analysis
        detector = IDORDetector(args.token, args.repo_url)
        found = detector.detect_idor_vulnerabilities(args.repo_url)
        detector.print_results()

        # Exit with appropriate code
        if found:
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
