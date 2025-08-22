#!/usr/bin/env python3
"""
Base44 Integrations Retriever

This script retrieves and displays all integrations available in a Base44 project by:
1. Connecting to the Base44 API with authentication
2. Fetching all available integration endpoints
3. Displaying the list of integrations

Usage:
    python get_integrations.py --token BEARER_TOKEN --repo-url GITHUB_REPO_URL
"""

import sys
import argparse
from typing import List
from base44_client import Base44App
from github_client import GitHubClient


class IntegrationsRetriever:
    """Retrieves and displays Base44 project integrations"""
    
    def __init__(self, bearer_token: str, repo_url: str):
        self.bearer_token = bearer_token
        self.github_client = GitHubClient()
        
        # Extract owner and repo from URL and get Base44 client
        owner, repo = self.github_client.parse_github_url(repo_url)
        self.app = self.github_client.get_base44_client_for_repo(owner, repo, bearer_token)
        
        if not self.app:
            raise ValueError(f"Could not find Base44 project ID in repository {repo_url}")
        
        self.project_id = self.app.project_id
        self.integrations = []
    
    def get_integrations(self) -> None:
        """Main method to retrieve and display integrations"""
        print(f"🔍 Fetching integrations for Base44 app: {self.project_id}")
        
        try:
            self.integrations = self.app.get_integrations()
            
            if self.integrations:
                print(f"📊 Found {len(self.integrations)} integrations:")
                for i, integration in enumerate(self.integrations, 1):
                    print(f"  {i}. {integration}")
            else:
                print("📭 No integrations found for this project")
                
        except Exception as e:
            print(f"❌ Error fetching integrations: {e}")
            sys.exit(1)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Retrieve and display integrations from Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--token', required=True, help='Bearer token for Base44 API')
    parser.add_argument('--repo-url', required=True, help='GitHub repository URL')
    
    args = parser.parse_args()
    
    try:
        # Create retriever and get integrations
        retriever = IntegrationsRetriever(args.token, args.repo_url)
        retriever.get_integrations()
        
        # Print summary
        if retriever.integrations:
            print(f"\n✅ Successfully retrieved {len(retriever.integrations)} integrations")
        else:
            print("\n✅ No integrations found (this is normal for projects without integrations)")
            
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
