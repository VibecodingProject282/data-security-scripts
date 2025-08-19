#!/usr/bin/env python3
"""
Base44 Password Storage Vulnerability Detector

This script analyzes Base44 projects to detect potential insecure password storage by:
1. Finding database tables with data using limit=1 queries
2. Checking column names for "password" strings
3. Alerting about tables that might store passwords insecurely

Usage:
    python password_detector.py --project-id PROJECT_ID --token BEARER_TOKEN
"""

import sys
import argparse
from typing import List, Optional, Tuple
from base44_client import Base44App


class PasswordDetector:
    """Detects potential insecure password storage in Base44 projects"""
    
    def __init__(self, project_id: str, bearer_token: str):
        self.project_id = project_id
        self.bearer_token = bearer_token
        self.app = Base44App(project_id, bearer_token)
        
        self.tables_with_passwords = []
    
    def check_password_columns(self, entity: str) -> bool:
        """Check if a table has columns containing 'password' in their names"""
        try:
            columns_name = self.app.get_entities_columns(entity)
            # Check if we got actual data
            if isinstance(columns_name, list) and len(columns_name) > 0:
                for column_name in columns_name:
                    if "password" in column_name.lower():
                        print(f"🚨 Found password column: '{column_name}' in table '{entity}'")
                        return True
        except Exception as e:
            print(f"Error checking password columns in table {entity}: {e}")
        return False

    def check_table_no_data(self, entity: str) -> None:
        """Check if a table has no data or we can't access it by trying to write an invalid Row to the table"""
        print(f"🚨 Table '{entity}' has no data or we can't access it by trying to write an invalid Row to the table")
        pass # future work: implement actual check

    def detect_password_vulnerabilities(self) -> None:
        """Main method to detect password storage vulnerabilities"""
        print("🔍 Starting password storage vulnerability detection...")
        
        # Step 1: Get all entities
        entities = self.app.get_base44_entities()
        print(f"Found {len(entities)} entities, checking for password columns...")
        
        # Step 2: Check each entity for password columns
        for entity in entities:
            print(f"\nChecking entity: {entity}")
            
            if self.app.check_base44_table_has_data(entity): # else, we cant access the table (?)
                print(f"✅ Table '{entity}' has data")
                
                if self.check_password_columns(entity):
                    self.tables_with_passwords.append(entity)
                    print(f"🚨 Table '{entity}' contains password columns!")
                else:
                    print(f"✅ Table '{entity}' has no password columns")
            else:
                #self.check_table_no_data(entity)
                pass
        
        # Step 3: Report findings
        if self.tables_with_passwords:
            print(f"\n🚨 PASSWORD STORAGE VULNERABILITIES DETECTED!")
            print(f"⚠️  The following tables contain password columns:")
            for table in self.tables_with_passwords:
                print(f"   • {table}")
            print(f"\n💡 Security Recommendations:")
            print(f"   - Never store passwords in plain text")
            print(f"   - Use strong hashing algorithms (bcrypt, Argon2, PBKDF2)")
            print(f"   - Add salt to password hashes")
            print(f"   - Consider using a dedicated authentication service")
        else:
            print(f"\n✅ No password storage vulnerabilities detected!")
            print(f"All tables appear to store passwords securely or don't store passwords at all.")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Detect potential insecure password storage in Base44 projects',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('--project-id', required=True, help='Base44 Project ID')
    parser.add_argument('--token', required=True, help='Bearer token for Base44 API')
    
    args = parser.parse_args()
    
    # Create detector and run analysis
    detector = PasswordDetector(args.project_id, args.token)
    detector.detect_password_vulnerabilities()
    
    # Exit with appropriate code
    if detector.tables_with_passwords:
        print(f"\n🔴 Exiting with code 1 - Password vulnerabilities found in tables: {detector.tables_with_passwords}")
        sys.exit(1)
    else:
        print(f"\n🟢 Exiting with code 0 - No password vulnerabilities")
        sys.exit(0)


if __name__ == "__main__":
    main()
