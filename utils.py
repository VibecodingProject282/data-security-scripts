#!/usr/bin/env python3
"""
Common utilities for Base44 detection and analysis scripts

This module contains shared utility functions used across multiple
Base44 analysis scripts to reduce code duplication.
"""

import re
from typing import Tuple


def is_code_file(file_path: str) -> bool:
    """
    Check if file is a code file that might contain secrets or other relevant content
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if file is a code file, False otherwise
    """
    code_extensions = {
        '.js', '.jsx', '.ts', '.tsx', '.py', '.java', '.cpp', '.c', '.cs',
        '.php', '.rb', '.go', '.rs', '.swift', '.kt', '.scala', '.clj',
        '.json', '.yaml', '.yml', '.env', '.config', '.conf', '.ini',
        '.properties', '.xml', '.html', '.css', '.scss', '.sass'
    }
    
    # Check file extension
    if any(file_path.endswith(ext) for ext in code_extensions):
        return True
    
    # Check for common config files without extensions
    config_files = {
        'package.json', 'requirements.txt', 'pom.xml', 'build.gradle',
        'Gemfile', 'Cargo.toml', 'go.mod', 'composer.json', 'webpack.config.js',
        '.env', '.env.local', '.env.production', '.env.development',
        'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile'
    }
    
    filename = file_path.split('/')[-1]
    if filename in config_files:
        return True
    
    return False


def get_line_context(content: str, line_number: int) -> str:
    """
    Get the context around a specific line
    
    Args:
        content: File content as string
        line_number: Line number to get context for
        
    Returns:
        Context string with surrounding lines
    """
    lines = content.split('\n')
    if 0 < line_number <= len(lines):
        start = max(0, line_number - 2)
        end = min(len(lines), line_number + 1)
        context_lines = lines[start:end]
        return '\n'.join(context_lines)
    return ""


def is_false_positive(value: str) -> bool:
    """
    Check if a detected value is likely a false positive
    
    Args:
        value: Value to check
        
    Returns:
        True if likely a false positive, False otherwise
    """
    # Common false positives
    false_positives = [
        'example', 'test', 'demo', 'sample', 'placeholder', 'dummy',
        'your_api_key_here', 'your_token_here', 'your_secret_here',
        'base64', 'base44', 'github', 'google', 'facebook', 'twitter',
        'localhost', '127.0.0.1', '0.0.0.0', 'localhost:3000',
        'development', 'production', 'staging', 'test',
        'true', 'false', 'null', 'undefined', 'none',
        'admin', 'user', 'password', 'username', 'email'
    ]
    
    value_lower = value.lower()
    
    # Check if it contains common false positive words
    for fp in false_positives:
        if fp in value_lower:
            return True
    
    # Check if it's too short to be a real secret
    if len(value) < 16:
        return True
    
    # Check if it's mostly repeating characters
    if len(set(value)) < len(value) * 0.3:
        return True
    
    return False
