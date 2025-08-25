#!/usr/bin/env python3
"""
Common utilities for Base44 detection and analysis scripts

This module contains shared utility functions used across multiple
Base44 analysis scripts to reduce code duplication.
"""

import re
from typing import Tuple


def get_line_context(content: str, line_number: int) -> str:
    """
    Get the context around a specific line
    
    Args:
        content: File content as string
        line_number: Line number to get context for
        
    Returns:
        Context string with surrounding lines
    """
    try:
        if not content or not isinstance(content, str):
            return ""
        
        if not isinstance(line_number, int) or line_number <= 0:
            return ""
            
        lines = content.split('\n')
        if line_number > len(lines):
            return ""
            
        start = max(0, line_number - 2)
        end = min(len(lines), line_number + 1)
        context_lines = lines[start:end]
        return '\n'.join(context_lines)
    except Exception as e:
        print(f"Warning: Error getting line context: {e}")
        return ""
