#!/usr/bin/env python3
"""
Base44 Client

This module provides the Base44App class for interacting with Base44 API endpoints,
including fetching entities, checking table data, and retrieving project information.
"""

import requests
import time
from typing import Optional, List, Dict, Any


class Base44App:
    """
    Base44 application client class
    
    This class provides functionality for interacting with Base44 API endpoints,
    including entity management, table data retrieval, and project information.
    """
    
    def __init__(self, project_id: str, bearer_token: str, timeout: int = 30):
        """
        Initialize Base44App
        
        Args:
            project_id: Base44 project ID
            bearer_token: Bearer token for Base44 API authentication
            timeout: Request timeout in seconds
        """
        self.project_id = project_id
        self.bearer_token = bearer_token
        self.timeout = timeout
        self.session = requests.Session()
        self.base_url = f"https://base44.app/api/apps/{project_id}"
        self.headers = {'Authorization': f'Bearer {bearer_token}'}
    
    def get_base44_entities(self) -> List[str]:
        """
        Get all entities (tables) from the Base44 project
        
        Returns:
            List of entity names
        """
        try:
            # Use the same approach as gather_database.py
            url = f"{self.base_url}/entities/TEMP"
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            # Check if it's the expected "Entity TEMP not found" error
            try:
                data = response.json()
                if "message" in data and isinstance(data["message"], str) and data["message"].startswith("Entity TEMP not found"):
                    pass  # This is expected
                else:
                    print(f"Error fetching data from {url}:\n{e}")
                    print("Servers Response:\n", response.json() if response.content else "No content returned.")
                    return []
            except:
                print(f"Error fetching data from {url}:\n{e}")
                return []

        data = response.json()
        after_colon = data.get("message", "").split(':')[1]
        entities = [e.strip() for e in after_colon.split(',')]
        return entities
    
    def check_base44_table_has_data(self, entity: str) -> bool:
        """
        Check if a Base44 table has at least one row of data using limit=1
        
        Args:
            entity: Entity/table name
            
        Returns:
            True if table has data, False otherwise
        """
        try:
            url = f"{self.base_url}/entities/{entity}?limit=1"
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            # Check if we got actual data (not empty array or error)
            if isinstance(data, list) and len(data) > 0:
                return True
            return False
        except requests.RequestException as e:
            print(f"Error checking table {entity}: {e}")
            return False

    def find_tables_with_data(self) -> List[str]:
        """Find all tables that have at least one row of data"""
        entities = self.get_base44_entities()
        tables_with_data = []

        for entity in entities:
            if self.check_base44_table_has_data(entity):
                tables_with_data.append(entity)

        return tables_with_data

    def get_entities_columns(self, entity: str) -> List[str]:
        """Get all column names for a specific Base44 table/entity"""
        try:
            data = self.app.get_base44_table_data(entity, limit=1)
            
            # Check if we got actual data
            if isinstance(data, list) and len(data) > 0:
                # Get the first row to examine column names
                first_row = data[0]
                if isinstance(first_row, dict):
                    # Return all column names (keys)
                    return list(first_row.keys())
            return []
        except Exception as e:
            print(f"Error checking column names in table {entity}: {e}")
            return []

    def get_base44_table_data(self, entity: str, limit: int = 1) -> List[Dict]:
        """
        Get data from a Base44 table
        
        Args:
            entity: Entity/table name
            limit: Number of rows to fetch
            
        Returns:
            List of table rows as dictionaries
        """
        try:
            url = f"{self.base_url}/entities/{entity}?limit={limit}"
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            
            data = response.json()
            if isinstance(data, list):
                return data
            return []
        except requests.RequestException as e:
            print(f"Error getting data from table {entity}: {e}")
            return []
