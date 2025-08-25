#!/usr/bin/env python3
"""
Repository Folder Manager

This module provides the RepoFolderManager class for managing local repository operations,
including file searching, reading, and directory management after downloading a repository.
"""

import os
import shutil
import tempfile
from typing import Optional, List


class RepoFolderManager:
    """
    Manager class for local repository operations
    
    This class provides functionality for working with downloaded repositories,
    including file searching, reading, and cleanup operations.
    """
    
    def __init__(self, repo_path: str, use_cache: bool = False):
        """
        Initialize RepoFolderManager
        
        Args:
            repo_path: Path to the extracted repository folder
            use_cache: Whether this is a cached directory (don't clean up)
        """
        self.repo_path = repo_path
        self.use_cache = use_cache
        # Only set temp_dir for cleanup if not using cache
        self.temp_dir = None if use_cache else (os.path.dirname(repo_path) if repo_path else None)
    
    def read_file(self, file_path: str) -> Optional[str]:
        """Read content from a local file"""
        try:
            if not file_path or not os.path.exists(file_path):
                return None
                
            if not os.path.isfile(file_path):
                return None
                
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except (IOError, OSError, UnicodeError) as e:
            print(f"Warning: Error reading file {file_path}: {e}")
            return None
        except Exception as e:
            print(f"Warning: Unexpected error reading file {file_path}: {e}")
            return None

    def find_files(self, pattern: str = None) -> List[str]:
        """Find files in repository. If pattern is provided, only return matching files."""
        if not self.repo_path or not os.path.exists(self.repo_path):
            return []
        
        if not os.path.isdir(self.repo_path):
            print(f"Warning: Repository path is not a directory: {self.repo_path}")
            return []
        
        files = []
        try:
            for root, dirs, filenames in os.walk(self.repo_path):
                for filename in filenames:
                    try:
                        file_path = os.path.join(root, filename)
                        if pattern is None or filename.endswith(pattern) or pattern in filename:
                            files.append(file_path)
                    except Exception as e:
                        print(f"Warning: Error processing file {filename}: {e}")
                        continue
        except Exception as e:
            print(f"Error: Failed to walk directory {self.repo_path}: {e}")
            return []
            
        return files

    def find_file_by_name(self, filename: str) -> Optional[str]:
        """Find a specific file by name in the repository"""
        files = self.find_files()
        for file_path in files:
            if os.path.basename(file_path) == filename:
                return file_path
        return None

    def get_relative_path(self, file_path: str) -> str:
        """Get relative path from repo root"""
        if not self.repo_path:
            return file_path
        return os.path.relpath(file_path, self.repo_path)

    def get_code_files(self) -> List[str]:
        """Get all code files from the repository"""
        if not self.repo_path:
            return []
            
        try:
            from utils import is_code_file
            all_files = self.find_files()
            return [f for f in all_files if is_code_file(self.get_relative_path(f))]
        except ImportError:
            # Fallback if utils is not available
            code_extensions = {'.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.cpp', '.c', '.cs', '.php', '.rb', '.go'}
            all_files = self.find_files()
            return [f for f in all_files if any(f.endswith(ext) for ext in code_extensions)]

    def find_files_in_directory(self, directory_name: str, file_extensions: List[str] = None) -> List[str]:
        """Find files in a specific directory (e.g., 'pages', 'src') with optional file extensions"""
        if not self.repo_path:
            return []
        
        files = []
        for file_path in self.find_files():
            relative_path = self.get_relative_path(file_path)
            if directory_name in relative_path:
                if file_extensions is None:
                    files.append(file_path)
                elif any(file_path.endswith(ext) for ext in file_extensions):
                    files.append(file_path)
        return files

    def cleanup(self):
        """Clean up temporary directory (only if not using cache)"""
        try:
            if not self.use_cache and self.temp_dir and os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            print(f"Warning: Error during cleanup of {self.temp_dir}: {e}")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit with automatic cleanup"""
        self.cleanup()
