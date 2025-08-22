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
        try:
            # Use THE new approach because the last one got patched!
            url = f"https://base44.app/api/apps/public/prod/by-id/{self.project_id}"
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as e:
            return {"error_code": e.response.status_code, "msg": e.response.json()}

        data = response.json()
        entities_dict = data.get("entities", {})
        entities = list(entities_dict.keys()) if isinstance(entities_dict, dict) else []
        return entities
    
    def check_base44_table_has_data(self, entity: str) -> bool:
        first_row = self.get_base44_table_data(entity, limit=1)
        if isinstance(first_row, list) and len(first_row) > 0:
            return True
        return False

    def find_tables_with_data(self) -> List[str]:
        entities = self.get_base44_entities()
        tables_with_data = []

        for entity in entities:
            if self.check_base44_table_has_data(entity):
                tables_with_data.append(entity)

        return tables_with_data

    def get_entities_columns(self) -> Dict[str, List[str]]:
        """Returns Dictionary mapping entity names to list of column names."""
        try:
            url = f"https://base44.app/api/apps/public/prod/by-id/{self.project_id}"
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            entities_dict = data.get("entities", {})
            result = {}
            if isinstance(entities_dict, dict):
                for entity_name, entity_info in entities_dict.items():
                    properties = entity_info.get("properties", {})
                    if isinstance(properties, dict):
                        result[entity_name] = list(properties.keys())
                    else:
                        print(f"Warning: 'properties' for entity {entity_name} is not a dict.")
                        result[entity_name] = []
            return result
        except Exception as e:
            print(f"Error fetching entities and columns: {e}")
            return {}

    def get_base44_table_data(self, entity: str, limit: int = 1) -> List[Dict]:
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

    def get_integrations(self) -> List[str]:
        try:
            url = f"{self.base_url}/integration-endpoints/schema"
            response = self.session.get(url, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()
            # Extract all endpoint names from all installed packages
            integrations = []
            for package in data.get("installed_packages", []):
                for endpoint in package.get("endpoints", []):
                    if "name" in endpoint:
                        integrations.append(endpoint["name"])
            return integrations
        except requests.RequestException as e:
            print(f"Error getting integrations: {e}")
            return []
