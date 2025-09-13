#!/usr/bin/env python3
"""
The script will:
1. Search GitHub for public repositories matching the search term
2. For each repository found:
   - Check if it's a Base44 project
   - Run static code analysis (secrets, HTTP URLs, HTTPS certificates)
   - Run authenticated analysis if bearer token provided (passwords, IDOR, integrations)
3. Generate a comprehensive security report
4. Save individual analysis results as CSV file in the 'repo-scanner-results' folder
"""

import sys
import argparse
import requests
import time
import json
import os
import csv
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

    def __init__(self, search_query: str, limit: int = 5, bearer_token: Optional[str] = None, search_code: bool = False):
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
        self.search_code = search_code
        self.github_client = GitHubClient()
        self.results = []
        self.results_folder = "repo-scanner-results"
        # Generate unique CSV filename with timestamp for each run
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        self.csv_filename = f"security_analysis_results_{timestamp}.csv"
        self._ensure_results_directory()
        self._initialize_csv_file()
        
    def _ensure_results_directory(self):
        """Create the results directory if it doesn't exist"""
        if not os.path.exists(self.results_folder):
            os.makedirs(self.results_folder)
            print(f"✅ Created results directory: {self.results_folder}")
            
    def _initialize_csv_file(self):
        """Initialize CSV file with headers for this run"""
        csv_path = os.path.join(self.results_folder, self.csv_filename)
        
        # Define CSV headers according to requirements
        headers = [
            'URL',
            'analysis_timestamp', 
            'is_base44',
            'project_id',
            'secret_count',
            'http_count',
            'https_count',
            'password_vulnerability',
            'idor_tables_low',
            'idor_tables_high',
            'integration_count',
            'anonymous_access',
            'anonymous_tables'
        ]
        
        # Create new CSV file with headers for this run
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
            print(f"✅ Created new CSV file: {self.csv_filename}")
        except Exception as e:
            print(f"❌ Error creating CSV file: {e}")
        
    def _sanitize_filename(self, repo_name: str) -> str:
        """
        Sanitize repository name to create a valid filename
        
        Args:
            repo_name: Repository full name (e.g., 'owner/repo-name')
            
        Returns:
            Sanitized filename safe for the file system
        """
        # Replace problematic characters with safe alternatives
        sanitized = repo_name.replace('/', '_').replace('\\', '_')
        sanitized = sanitized.replace(':', '_').replace('*', '_')
        sanitized = sanitized.replace('?', '_').replace('"', '_')
        sanitized = sanitized.replace('<', '_').replace('>', '_')
        sanitized = sanitized.replace('|', '_')
        return sanitized
        
    def _save_repo_result_to_csv(self, analysis_result: Dict[str, Any]):
        """
        Append repository analysis result to CSV file
        
        Args:
            analysis_result: Dictionary containing the complete analysis results
        """
        csv_path = os.path.join(self.results_folder, self.csv_filename)
        
        try:
            repo_info = analysis_result['repository']
            findings = analysis_result['security_findings']
            
            # Count IDOR vulnerabilities by risk level
            idor_low = 0
            idor_high = 0
            if findings.get('idor_details'):
                for detail in findings['idor_details']:
                    if detail.get('risk', '').upper() == 'HIGH':
                        idor_high += 1
                    elif detail.get('risk', '').upper() == 'LOW':
                        idor_low += 1
            
            # Check if authenticated analysis was skipped
            anonymous_skipped = findings.get('anonymous_access_skipped', False)
            auth_skipped = findings.get('authenticated_analysis_skipped', False)
            
            # Prepare CSV row data
            row_data = [
                repo_info.get('html_url', ''),  # URL
                analysis_result.get('analysis_timestamp', ''),  # analysis_timestamp
                findings.get('base44_detected', False),  # is_base44
                findings.get('base44_project_id', ''),  # project_id (nullable)
                len(findings.get('secrets_details', [])),  # secret_count
                len(findings.get('http_details', [])),  # http_count
                len(findings.get('https_details', [])),  # https_count
                findings.get('password_vulnerabilities', False),  # password_vulnerability
                idor_low,  # idor_tables_low
                idor_high,  # idor_tables_high
                len(findings.get('integrations_details', [])),  # integration_count
                findings.get('anonymous_access_vulnerabilities', False),  # anonymous_access
                len(findings.get('anonymous_access_details', []))  # anonymous_tables
            ]
            
            # Append to CSV file
            with open(csv_path, 'a', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(row_data)
                
            print(f"   ✅ Added to CSV: {repo_info.get('full_name', 'Unknown')}")
            
        except Exception as e:
            print(f"❌ Error saving to CSV: {e}")
        
    def _save_repo_result(self, analysis_result: Dict[str, Any]):
        """
        Save individual repository analysis result to CSV file
        
        Args:
            analysis_result: Dictionary containing the complete analysis results
        """
        # Save to CSV instead of JSON
        self._save_repo_result_to_csv(analysis_result)
        
    def search_repositories(self) -> List[Dict[str, Any]]:
        """
        Search GitHub for public repositories matching the search query
        
        Returns:
            List of repository dictionaries containing repo information
        """
        print(f"🔍 Searching for '{self.search_query}' (limit: {self.limit})")
        
        # Prepare the search URL
        encoded_query = quote(self.search_query)
        url = f"https://api.github.com/search/repositories" if not self.search_code else "https://api.github.com/search/code"
        
        headers = {}
        if self.github_client.github_token:
            headers['Authorization'] = f'token {self.github_client.github_token}'
        
        all_repositories = []
        page = 1
        repos_per_page = 100  # GitHub API maximum per page
        
        try:
            while len(all_repositories) < self.limit:
                # Calculate how many repos to request for this page
                remaining_needed = self.limit - len(all_repositories)
                current_per_page = min(repos_per_page, remaining_needed)
                
                params = {
                    'q': self.search_query,
                    'sort': 'stars',  # Sort by stars for more relevant results
                    'order': 'desc',
                    'per_page': current_per_page,
                    'page': page,
                    'type': 'Repositories'
                }
                
                # print(f"📄 Fetching page {page} (requesting {current_per_page} repositories)...")
                
                response = requests.get(url, params=params, headers=headers, timeout=30)
                
                if response.status_code == 403:
                    print("❌ GitHub API rate limit exceeded. Please wait or provide a GitHub token.")
                    if len(all_repositories) > 0:
                        print(f"📊 Returning {len(all_repositories)} repositories found before rate limit.")
                    return all_repositories
                elif response.status_code == 422:
                    print("❌ Invalid search query. Please check your search terms.")
                    return []
                elif response.status_code != 200:
                    print(f"❌ GitHub API error: {response.status_code}")
                    print(f"Response: {response.text}")
                    if len(all_repositories) > 0:
                        print(f"📊 Returning {len(all_repositories)} repositories found before error.")
                    return all_repositories
                
                data = response.json()
                repositories = data.get('items', [])
                total_count = data.get('total_count', 0)
                
                if not repositories:
                    break
                
                # Filter and format the results for this page
                for repo in repositories:
                    if len(all_repositories) >= self.limit:
                        break
                    
                    full_name = repo['full_name'] if not self.search_code else repo['repository']['full_name']
                    html_url = repo['html_url'] if not self.search_code else repo['repository']['html_url']

                    repo_info = {
                        'full_name': full_name,
                        'html_url': html_url,
                    }
                    all_repositories.append(repo_info)    
                page += 1
            
            if len(all_repositories) == 0:
                print("❌ No repositories found matching your search criteria.")
            else:
                print(f"Search completed! Found {len(all_repositories)} repositories total")
                
            return all_repositories
            
        except requests.Timeout:
            print("❌ Request timeout. Please try again.")
            if len(all_repositories) > 0:
                print(f"📊 Returning {len(all_repositories)} repositories found before timeout.")
            return all_repositories
        except requests.ConnectionError:
            print("❌ Failed to connect to GitHub API. Check your internet connection.")
            return all_repositories
        except Exception as e:
            print(f"❌ Error searching repositories: {e}")
            if len(all_repositories) > 0:
                print(f"📊 Returning {len(all_repositories)} repositories found before error.")
            return all_repositories

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
        
        print(f"📊 Analyzing {repo_name}...")
        
        analysis_result = {
            'repository': repo_info,
            'analysis_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'security_findings': {
                'base44_detected': False,
                'base44_project_id': None,
                'secrets_found': False,
                'secrets_details': [],
                'http_urls_found': False,
                'http_details': [],
                'https_issues_found': False,
                'https_details': [],
                'password_vulnerabilities': False,
                'password_details': [],
                'idor_vulnerabilities': False,
                'idor_details': [],
                'integrations_found': False,
                'integrations_details': [],
                'anonymous_access_vulnerabilities': False,
                'anonymous_access_details': []
            },
            'errors': [],
            'analysis_completed': False
        }
        
        try:
            # Run security orchestrator
            orchestrator = SecurityOrchestrator(repo_url, self.bearer_token)
            
            # Check if it's a Base44 project
            is_base44 = orchestrator.run_base44_check()
            
            # If not a Base44 project, skip all other security checks
            if not is_base44:
                print("   Skipping Base44-specific checks")
                analysis_result['analysis_completed'] = True
            else:
                # Run static analysis
                orchestrator.run_static_analysis()
                
                # Run anonymous access check first
                orchestrator.run_anonymous_access_check()
                
                # Run authenticated analysis if token provided OR if anonymous access is detected
                orchestrator.run_authenticated_analysis()
            
            # Get all findings from the orchestrator
            findings = orchestrator.get_findings()
            
            # Update analysis result with actual findings
            analysis_result['security_findings'] = {
                'base44_detected': findings.get('base44_detected', False),
                'base44_project_id': findings.get('base44_project_id'),
                'secrets_found': findings.get('secrets_found', False),
                'secrets_details': findings.get('secrets_details', []),
                'http_urls_found': findings.get('http_urls_found', False),
                'http_details': findings.get('http_details', []),
                'https_issues_found': findings.get('https_issues_found', False),
                'https_details': findings.get('https_details', []),
                'password_vulnerabilities': findings.get('password_vulnerabilities', False),
                'password_details': findings.get('password_details', []),
                'idor_vulnerabilities': findings.get('idor_vulnerabilities', False),
                'idor_details': findings.get('idor_details', []),
                'integrations_found': findings.get('integrations_found', False),
                'integrations_details': findings.get('integrations_details', []),
                'anonymous_access_vulnerabilities': findings.get('anonymous_access_vulnerabilities', False),
                'anonymous_access_details': findings.get('anonymous_access_details', [])
            }
            
            analysis_result['analysis_completed'] = True
            
        except Exception as e:
            error_msg = f"Error analyzing repository {repo_name}: {e}"
            print(f"❌ {error_msg}")
            analysis_result['errors'].append(error_msg)
        
        # Save the analysis result to a file
        self._save_repo_result(analysis_result)
        
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
        
        # Analyze each repository
        results = []
        for i, repo in enumerate(repositories, 1):
            if len(repositories) > 1:
                print(f"\n[{i}/{len(repositories)}]", end=" ")
            
            # Add small delay to avoid hitting rate limits
            if i > 1:
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
        if not results:
            print("❌ No results to summarize.")
            return
        
        total_repos = len(results)
        base44_repos = sum(1 for r in results if r['security_findings']['base44_detected'])


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
    Results are appended to a single CSV file 'security_analysis_results.csv' in the 'repo-scanner-results' folder."""
    )
    
    parser.add_argument('--search', required=True, help='Search term for finding GitHub repositories')
    parser.add_argument('--limit', type=int, default=5, help='Maximum number of repositories to analyze (default: 5)')
    parser.add_argument('--token', help='Bearer token for authenticated analysis (optional)')
    parser.add_argument('--code', type=bool, default=False, help='Searching in code instead of repos (default: False)')
    
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
    
    print(f"🔍 Scanning GitHub repositories for '{args.search}' (limit: {args.limit})")
    
    # Create scanner and run analysis
    scanner = GitHubRepoScanner(search_query=args.search, limit=args.limit, bearer_token=args.token, search_code=args.code)

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
