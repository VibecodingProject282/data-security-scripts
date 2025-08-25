#!/usr/bin/env python3
"""
GitHub Repository Security Scanner

This script searches GitHub for public repositories based on a given search string
and performs comprehensive security analysis on each repository found.

Usage:
    python github_repo_scanner.py --search "search_term" [--limit NUMBER] [--token BEARER_TOKEN]

Example:
    python github_repo_scanner.py --search "react app" --limit 10
    python github_repo_scanner.py --search "express server" --limit 5 --token your_bearer_token

The script will:
1. Search GitHub for public repositories matching the search term
2. For each repository found:
   - Check if it's a Base44 project
   - Run static code analysis (secrets, HTTP URLs, HTTPS certificates)
   - Run authenticated analysis if bearer token provided (passwords, IDOR, integrations)
3. Generate a comprehensive security report
"""

import sys
import argparse
import requests
import time
import json
from typing import List, Dict, Optional, Any
from urllib.parse import quote

# Import all the security components
from security_orchestrator import SecurityOrchestrator
from github_client import GitHubClient


class GitHubRepoScanner:
    """
    Scanner class for searching and analyzing GitHub repositories
    
    This class provides functionality for searching GitHub repositories
    and performing comprehensive security analysis on each found repository.
    """

    def __init__(self, search_query: str, limit: int = 5, bearer_token: Optional[str] = None):
        """
        Initialize GitHubRepoScanner
        
        Args:
            search_query: Search term for finding repositories
            limit: Maximum number of repositories to analyze (default: 5)
            bearer_token: Optional bearer token for authenticated analysis
        """
        self.search_query = search_query
        self.limit = limit
        self.bearer_token = bearer_token
        self.github_client = GitHubClient()
        self.results = []
        
    def search_repositories(self) -> List[Dict[str, Any]]:
        """
        Search GitHub for public repositories matching the search query
        
        Returns:
            List of repository dictionaries containing repo information
        """
        print("=" * 80)
        print(f"🔍 SEARCHING GITHUB FOR: '{self.search_query}'")
        print(f"📊 Limit: {self.limit} repositories")
        print("=" * 80)
        
        # Prepare the search URL
        encoded_query = quote(self.search_query)
        url = f"https://api.github.com/search/repositories"
        params = {
            'q': self.search_query,
            'sort': 'stars',  # Sort by stars for more relevant results
            'order': 'desc',
            'per_page': min(self.limit, 100),  # GitHub API limit is 100 per page
            'type': 'Repositories'
        }
        
        headers = {}
        if self.github_client.github_token:
            headers['Authorization'] = f'token {self.github_client.github_token}'
            print("✅ Using GitHub token for higher rate limits")
        else:
            print("⚠️  No GitHub token found - using unauthenticated requests (lower rate limits)")
        
        try:
            response = requests.get(url, params=params, headers=headers, timeout=30)
            
            if response.status_code == 403:
                print("❌ GitHub API rate limit exceeded. Please wait or provide a GitHub token.")
                return []
            elif response.status_code == 422:
                print("❌ Invalid search query. Please check your search terms.")
                return []
            elif response.status_code != 200:
                print(f"❌ GitHub API error: {response.status_code}")
                print(f"Response: {response.text}")
                return []
            
            data = response.json()
            repositories = data.get('items', [])
            
            if not repositories:
                print("❌ No repositories found matching your search criteria.")
                return []
            
            print(f"✅ Found {len(repositories)} repositories")
            
            # Filter and format the results
            filtered_repos = []
            for repo in repositories[:self.limit]:
                repo_info = {
                    'name': repo['name'],
                    'full_name': repo['full_name'],
                    'html_url': repo['html_url'],
                    'clone_url': repo['clone_url'],
                    'description': repo.get('description', 'No description'),
                    'stars': repo['stargazers_count'],
                    'language': repo.get('language', 'Unknown'),
                    'updated_at': repo['updated_at']
                }
                filtered_repos.append(repo_info)
                
            return filtered_repos
            
        except requests.Timeout:
            print("❌ Request timeout. Please try again.")
            return []
        except requests.ConnectionError:
            print("❌ Failed to connect to GitHub API. Check your internet connection.")
            return []
        except Exception as e:
            print(f"❌ Error searching repositories: {e}")
            return []

    def analyze_repository(self, repo_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single repository for security vulnerabilities
        
        Args:
            repo_info: Repository information dictionary
            
        Returns:
            Dictionary containing analysis results
        """
        repo_url = repo_info['html_url']
        repo_name = repo_info['full_name']
        
        print("\n" + "=" * 50)
        print(f"ANALYZING REPOSITORY: {repo_name}")
        print(f"URL: {repo_url}")
        print(f"Description: {repo_info['description']}")
        print(f"Language: {repo_info['language']} | Stars: {repo_info['stars']}")
        print("=" * 50)
        
        analysis_result = {
            'repository': repo_info,
            'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'security_findings': {
                'base44_detected': False,
                'secrets_found': False,
                'http_urls_found': False,
                'https_issues_found': False,
                'password_vulnerabilities': False,
                'idor_vulnerabilities': False,
                'integrations_found': False
            },
            'errors': [],
            'analysis_completed': False
        }
        
        try:
            # Run security orchestrator
            orchestrator = SecurityOrchestrator(repo_url, self.bearer_token)
            
            # We'll capture the output by modifying the orchestrator slightly
            # For now, let's run it and capture what we can
            print("\n🚀 Starting security analysis...")
            
            # Check if it's a Base44 project
            is_base44 = orchestrator.run_base44_check()
            analysis_result['security_findings']['base44_detected'] = is_base44
            
            # Run static analysis
            orchestrator.run_static_analysis()
            
            # Run authenticated analysis if token provided
            if self.bearer_token:
                orchestrator.run_authenticated_analysis()
            
            analysis_result['analysis_completed'] = True
            
        except Exception as e:
            error_msg = f"Error analyzing repository {repo_name}: {e}"
            print(f"❌ {error_msg}")
            analysis_result['errors'].append(error_msg)
        
        return analysis_result

    def run_analysis(self) -> List[Dict[str, Any]]:
        """
        Run the complete analysis workflow
        
        Returns:
            List of analysis results for all repositories
        """
        # Search for repositories
        repositories = self.search_repositories()
        
        if not repositories:
            print("❌ No repositories to analyze. Exiting.")
            return []
        
        print(f"\n📋 REPOSITORIES TO ANALYZE:")
        for i, repo in enumerate(repositories, 1):
            print(f"{i:2d}. {repo['full_name']} ({repo['stars']} ⭐) - {repo['language']}")
            print(f"     {repo['description'][:100]}{'...' if len(repo['description']) > 100 else ''}")
        
        # Analyze each repository
        results = []
        for i, repo in enumerate(repositories, 1):
            print(f"\n📊 PROGRESS: Analyzing repository {i}/{len(repositories)}")
            
            # Add small delay to avoid hitting rate limits
            if i > 1:
                print("⏳ Waiting 2 seconds to avoid rate limits...")
                time.sleep(2)
            
            result = self.analyze_repository(repo)
            results.append(result)
            
        return results

    def generate_summary_report(self, results: List[Dict[str, Any]]):
        """
        Generate a summary report of all analysis results
        
        Args:
            results: List of analysis results
        """
        print("\n" + "=" * 50)
        print("SECURITY ANALYSIS SUMMARY REPORT")
        print("=" * 50)

        if not results:
            print("❌ No results to summarize.")
            return
        
        total_repos = len(results)
        completed_analyses = sum(1 for r in results if r['analysis_completed'])
        base44_repos = sum(1 for r in results if r['security_findings']['base44_detected'])
        
        print(f"📈 OVERALL STATISTICS:")
        print(f"   • Total repositories analyzed: {total_repos}")
        print(f"   • Successful analyses: {completed_analyses}")
        print(f"   • Base44 projects detected: {base44_repos}")
        
        print(f"\n📋 DETAILED RESULTS:")
        for i, result in enumerate(results, 1):
            repo = result['repository']
            findings = result['security_findings']
            
            print(f"\n{i:2d}. {repo['full_name']}")
            print(f"    URL: {repo['html_url']}")
            print(f"    Analysis Status: {'✅ Completed' if result['analysis_completed'] else '❌ Failed'}")
            
            if result['analysis_completed']:
                print(f"    Base44 Project: {'✅ Yes' if findings['base44_detected'] else '❌ No'}")
            
            if result['errors']:
                print(f"    Errors: {len(result['errors'])}")
                for error in result['errors']:
                    print(f"      - {error}")

        print(f"\n🔍 SEARCH QUERY: '{self.search_query}'")
        print(f"📅 ANALYSIS DATE: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")


def main():
    """Main function to run the GitHub repository scanner"""
    parser = argparse.ArgumentParser(
        description='Search and analyze GitHub repositories for security vulnerabilities',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python github_repo_scanner.py --search "react app" --limit 10
  python github_repo_scanner.py --search "express server" --limit 5 --token your_bearer_token
  python github_repo_scanner.py --search "django project" --limit 3

The script performs comprehensive security analysis including:
- Base44 project detection
- Secret detection (API keys, passwords, tokens)
- HTTP/HTTPS URL analysis
- Password vulnerability detection (with token)
- IDOR vulnerability detection (with token)
- Integration analysis (with token)
        """
    )
    
    parser.add_argument('--search', required=True, help='Search term for finding GitHub repositories')
    parser.add_argument('--limit', type=int, default=5, help='Maximum number of repositories to analyze (default: 5)')
    parser.add_argument('--token', help='Bearer token for authenticated analysis (optional)')
    
    args = parser.parse_args()
    
    # Validate limit
    if args.limit < 1:
        print("❌ Error: limit must be at least 1")
        sys.exit(1)
    
    if args.limit > 50:
        print("⚠️  Warning: analyzing more than 50 repositories may take a very long time")
        print("   and may hit GitHub API rate limits.")
        confirm = input("Do you want to continue? (y/N): ")
        if confirm.lower() != 'y':
            print("Analysis cancelled.")
            sys.exit(0)
    
    print("🔍 GitHub Repository Security Scanner")
    print("=" * 50)
    print(f"Search Query: '{args.search}'")
    print(f"Repository Limit: {args.limit}")
    print(f"Bearer Token: {'Provided' if args.token else 'Not provided'}")
    print("=" * 50)
    
    # Create scanner and run analysis
    scanner = GitHubRepoScanner(search_query=args.search, limit=args.limit, bearer_token=args.token)

    try:
        results = scanner.run_analysis()
        scanner.generate_summary_report(results)
        
    except KeyboardInterrupt:
        print("\n\n❌ Analysis interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
