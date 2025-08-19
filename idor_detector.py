#!/usr/bin/env python3
"""
Base44 IDOR Vulnerability Detector

This script analyzes Base44 projects to detect potential IDOR vulnerabilities by:
1. Finding database tables with data using limit=1 queries
2. Checking if these tables are referenced in the frontend code
3. Alerting about tables that might be vulnerable to IDOR attacks

Usage:
    python idor_detector.py --project-id PROJECT_ID --token BEARER_TOKEN --repo-url GITHUB_REPO_URL
"""

import re
import sys
import argparse
from typing import List, Optional, Tuple
from base44_client import Base44App
from github_client import GitHubClient


class IDORDetector:
    """Detects potential IDOR vulnerabilities in Base44 projects"""
    
    def __init__(self, project_id: str, bearer_token: str):
        self.project_id = project_id
        self.bearer_token = bearer_token
        self.base44_app = Base44App(project_id, bearer_token)
        self.github_client = GitHubClient()

        self.postman_tables = []
    
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
    
    def check_frontend_references(self, repo_url: str, tables: List[str]) -> List[str]:
        """Check which tables are referenced in the frontend code"""
        try:
            owner, repo = self.github_client.parse_github_url(repo_url)
            print(f"\nAnalyzing GitHub repository: {owner}/{repo}")
            
            # Get repository tree to find pages directory
            tree_files = self.github_client.get_repository_tree(owner, repo)
            
            if not tree_files:
                print("❌ Could not access repository tree")
                return tables
            pages_files = [file_path for file_path in tree_files if 'pages' in file_path]
            if not pages_files:
                print("❌ No pages directory found")
                return tables
            
            print(f"Found {len(pages_files)} files in pages directory: {pages_files}")
            
            referenced_tables = set()
            
            for file_path in pages_files:
                if file_path.endswith(('.jsx', '.js', '.tsx', '.ts')):
                    file_content = self.github_client.get_file_content(owner, repo, file_path)
                    if file_content:
                        found_tables = self.search_tables_in_file(file_content, tables)
                        if found_tables:
                            print(f"📁 {file_path}: Found references to {found_tables}")
                            referenced_tables.update(found_tables)
            
            # Return tables that are NOT referenced in frontend
            unreferenced_tables = [table for table in tables if table not in referenced_tables]
            return unreferenced_tables
            
        except Exception as e:
            print(f"Error checking frontend references: {e}")
            return tables
    
    def detect_idor_vulnerabilities(self, repo_url: str) -> bool:
        """Main method to detect IDOR vulnerabilities"""
        print("🔍 Starting IDOR vulnerability detection...")
        
        # Step 1: Find tables with data
        self.postman_tables = self.base44_app.find_tables_with_data()
        
        if not self.postman_tables:
            print("❌ No tables with data found. Cannot proceed with IDOR detection.")
            return False

        print(f"\n📊 Found {len(self.postman_tables)} tables with data: {self.postman_tables}")
        
        # Step 2: Check frontend references
        unreferenced_tables = self.check_frontend_references(repo_url, self.postman_tables)
        
        # Step 3: Alert about potential IDOR vulnerabilities
        if unreferenced_tables:
            print(f"\n🚨 IDOR ATTACK POSSIBLE!")
            print(f"⚠️  The following tables have data but are NOT referenced in the frontend:")
            for table in unreferenced_tables:
                print(f"   • {table}")
            print(f"\n💡 These tables might be vulnerable to IDOR attacks as they:")
            print(f"   - Contain data (accessible via API)")
            print(f"   - Are not used in the frontend (no access controls visible)")
            print(f"   - Could be accessed directly via API endpoints")
        else:
            print(f"\n✅ No IDOR vulnerabilities detected!")
            print(f"All tables with data are properly referenced in the frontend code.")
        
        # Update postman_tables to only include vulnerable ones
        self.postman_tables = unreferenced_tables

        return bool(self.postman_tables)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect potential IDOR vulnerabilities in Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--project-id', required=True, help='Base44 Project ID') # remove
    parser.add_argument('--token', required=True, help='Bearer token for Base44 API') # remove, and one comment
    parser.add_argument('--repo-url', required=True, help='GitHub repository URL')
    
    args = parser.parse_args()
    
    # Create detector and run analysis
    detector = IDORDetector(args.project_id, args.token)
    found = detector.detect_idor_vulnerabilities(args.repo_url)

    # Exit with appropriate code
    if found:
        print(f"\n🔴 Exiting with code 1 - IDOR vulnerabilities found: {detector.postman_tables}")
        sys.exit(1)
    else:
        print(f"\n🟢 Exiting with code 0 - No IDOR vulnerabilities")
        sys.exit(0)


if __name__ == "__main__":
    main()
