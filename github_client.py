#!/usr/bin/env python3
"""
GitHub Client

This module provides the GitHubClient class for interacting with GitHub API endpoints,
including repository tree retrieval, file content fetching, and repository analysis.
"""

import requests
import base64
import time
import re
import os
import zipfile
import io
import shutil
from typing import Optional, List, Tuple
from urllib.parse import urlparse
from repo_manager import RepoFolderManager


class GitHubClient:
    """
    GitHub client class for repository operations
    
    This class provides functionality for interacting with GitHub repositories,
    including file tree retrieval, content fetching, and repository analysis.
    """
    
    def __init__(self, timeout: int = 30):
        """
        Initialize GitHubClient
        
        Args:
            timeout: Request timeout in seconds
        """
        self.session = requests.Session()
        self.timeout = timeout
        # read the GitHub token from the token.txt file
        self.github_token = self.read_github_token()
        
        # Create cache directory
        self.cache_dir = os.path.join(os.getcwd(), "downloaded-projects")
        os.makedirs(self.cache_dir, exist_ok=True)

        if self.github_token:
            self.session.headers.update({'Authorization': f'token {self.github_token}'})

    def read_github_token(self) -> Optional[str]:
        """Read GitHub token from token.txt file"""
        try:
            with open("token.txt", "r") as file:
                return file.read().strip()
        except Exception as e:
            print(f"Error reading GitHub token: {e}")
        return None

    def parse_github_url(self, url: str) -> Tuple[str, str]:
        """
        Parse GitHub URL to extract owner and repo name
        
        Args:
            url: GitHub repository URL
            
        Returns:
            Tuple of (owner, repo_name)
            
        Raises:
            ValueError: If URL is not a valid GitHub repository URL
        """
        pattern = r'https?://github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$'
        match = re.match(pattern, url.strip())
        if not match:
            raise ValueError(f"Invalid GitHub repository URL: {url}")
        return match.group(1), match.group(2)
    
    def get_repository_tree(self, owner: str, repo: str) -> List[str]:
        """
        Get the file tree of the repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            List of file paths in the repository
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return [item['path'] for item in data.get('tree', []) if item['type'] == 'blob']
            return []
        except Exception as e:
            print(f"Error getting repository tree: {e}")
            return []
    
    def get_file_content(self, owner: str, repo: str, file_path: str) -> Optional[str]:
        """
        Get file content from GitHub repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to the file
            
        Returns:
            File content as string, or None if not found
        """
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                data = response.json()
                return base64.b64decode(data['content']).decode('utf-8')
        except Exception as e:
            print(f"Error getting file {file_path}: {e}")
        return None
    
    def find_file_recursive(self, owner: str, repo: str, filename: str) -> Optional[str]:
        """
        Find file recursively in repository with timeout
        
        Args:
            owner: Repository owner
            repo: Repository name
            filename: Name of file to find
            
        Returns:
            Full path to the file if found, None otherwise
        """
        start_time = time.time()
        file_tree = self.get_repository_tree(owner, repo)
        
        for file_path in file_tree:
            # Check timeout
            if time.time() - start_time > self.timeout:
                print(f"⏰ Search timeout after {self.timeout}s while looking for {filename}")
                break
                
            if file_path.endswith('/' + filename) or file_path == filename:
                return file_path
        print(f"File {filename} not found in repository {owner}/{repo}")
        return None
    
    def get_file_content_recursive(self, owner: str, repo: str, file_path: str, recursive: bool = True) -> Optional[str]:
        """
        Get file content from GitHub repository with optional recursive search
        
        Args:
            owner: Repository owner
            repo: Repository name
            file_path: Path to the file
            recursive: Whether to search recursively if direct path fails
            
        Returns:
            File content as string, or None if not found
        """
        # First try direct path
        content = self.get_file_content(owner, repo, file_path)
        if content:
            return content
        
        # If direct path fails and recursive is enabled, search recursively
        if recursive:
            filename = file_path.split('/')[-1]  # Get just the filename
            found_path = self.find_file_recursive(owner, repo, filename)
            if found_path:
                return self.get_file_content(owner, repo, found_path)
        
        return None
    
    def get_code_files(self, owner: str, repo: str) -> List[str]:
        """
        Get all code files from the repository
        
        Args:
            owner: Repository owner
            repo: Repository name
            
        Returns:
            List of code file paths
        """
        from utils import is_code_file  # Import here to avoid circular import
        
        file_tree = self.get_repository_tree(owner, repo)
        return [f for f in file_tree if is_code_file(f)]
    
    def scan_files_with_progress(self, owner: str, repo: str, files: List[str], 
                                scan_func, delay: float = 0.1) -> List:
        """
        Scan multiple files with progress reporting
        
        Args:
            owner: Repository owner
            repo: Repository name
            files: List of files to scan
            scan_func: Function to call for each file (should take owner, repo, file_path)
            delay: Delay between requests to avoid rate limiting
            
        Returns:
            List of results from scan_func
        """
        results = []
        for i, file_path in enumerate(files, 1):
            print(f"🔍 Scanning file {i}/{len(files)}: {file_path}")
            
            try:
                result = scan_func(owner, repo, file_path)
                if result:
                    results.extend(result if isinstance(result, list) else [result])
                    print(f"✅ Found results in {file_path}")
            except Exception as e:
                print(f"⚠️  Error scanning {file_path}: {e}")
            
            # Add small delay to avoid rate limiting
            time.sleep(delay)
        
        return results

    def download_repo_as_zip(self, owner: str, repo: str, branch: str = "main") -> Optional[RepoFolderManager]:
        """
        Download repository as zip file and extract to cache directory.
        If already cached, return the cached version.
        Returns a RepoFolderManager instance for the repository, or None if failed.
        """
        # Create cache key from owner/repo
        cache_key = f"{owner}_{repo}_{branch}"
        cached_path = os.path.join(self.cache_dir, cache_key)
        
        # Check if already cached
        if os.path.exists(cached_path) and os.path.isdir(cached_path):
            # Find the actual repo folder inside the cache directory
            subfolders = [f for f in os.listdir(cached_path) if os.path.isdir(os.path.join(cached_path, f))]
            if subfolders:
                repo_path = os.path.join(cached_path, subfolders[0])
                return RepoFolderManager(repo_path, use_cache=True)
        
        # Download if not cached
        url = f"https://api.github.com/repos/{owner}/{repo}/zipball/{branch}"
        
        try:
            response = self.session.get(url, stream=True, timeout=self.timeout)
            if response.status_code == 200:
                # Create cache directory for this repo
                os.makedirs(cached_path, exist_ok=True)
                
                # Extract zip to cache directory
                with zipfile.ZipFile(io.BytesIO(response.content)) as z:
                    z.extractall(cached_path)
                
                # Find the extracted folder (GitHub creates a folder with format: owner-repo-commit)
                extracted_folders = [f for f in os.listdir(cached_path) if os.path.isdir(os.path.join(cached_path, f))]
                if extracted_folders:
                    repo_path = os.path.join(cached_path, extracted_folders[0])
                    return RepoFolderManager(repo_path, use_cache=True)
                    
        except Exception as e:
            print(f"Error downloading repository: {e}")
        
        return None

    def clear_cache(self):
        """Clear the downloaded-projects cache directory"""
        if os.path.exists(self.cache_dir):
            shutil.rmtree(self.cache_dir)
            os.makedirs(self.cache_dir, exist_ok=True)

    def get_cache_size(self) -> str:
        """Get human-readable cache directory size"""
        if not os.path.exists(self.cache_dir):
            return "0 B"
        
        total_size = 0
        for dirpath, dirnames, filenames in os.walk(self.cache_dir):
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                total_size += os.path.getsize(filepath)
        
        # Convert to human readable format
        for unit in ['B', 'KB', 'MB', 'GB']:
            if total_size < 1024.0:
                return f"{total_size:.1f} {unit}"
            total_size /= 1024.0
        return f"{total_size:.1f} TB"

    def get_base44_client_for_repo(self, owner: str, repo: str, token: str = "", timeout: int = 30):
        """
        Given a GitHub owner and repo, returns a Base44App client with the project_id found in base44Client.js.
        Uses cached repository to avoid API rate limits.
        """
        from base44_client import Base44App
        
        with self.download_repo_as_zip(owner, repo) as repo_manager:
            if not repo_manager:
                return None
                
            # Find base44Client.js file
            base44_file = repo_manager.find_file_by_name("base44Client.js")
            if base44_file:
                content = repo_manager.read_file(base44_file)
                if content:
                    # Try to extract project_id from appId: "..."
                    import re
                    match = re.search(r'appId:\s*"([^"]+)"', content)
                    if match:
                        project_id = match.group(1)
                        return Base44App(project_id, bearer_token=token, timeout=timeout)
            
        return None
