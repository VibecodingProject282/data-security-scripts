#!/usr/bin/env python3
"""
Base44 Repository URL Extractor
Reads security scan results and prints GitHub URLs of repositories marked as base44 projects
"""

import csv
import sys
import os
import glob

def get_latest_csv():
    """Get the most recent CSV file from repo-scanner-results directory"""
    results_dir = "repo-scanner-results"
    if not os.path.exists(results_dir):
        return None
    
    csv_files = glob.glob(os.path.join(results_dir, "security_analysis_results_*.csv"))
    if not csv_files:
        return None
    
    # Return the most recent file based on filename (contains timestamp)
    return max(csv_files)

def extract_base44_urls(file_path):
    """Extract GitHub URLs of repositories marked as base44 projects"""
    
    base44_urls = []
    total_repos = 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                total_repos += 1
                
                # Check if this is a base44 project
                if row['is_base44'].lower() == 'true':
                    base44_urls.append(row['URL'])
    
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return
    
    # Print results
    print(f"📊 Found {len(base44_urls)} base44 repositories out of {total_repos} total repositories")
    print(f"📁 Source file: {os.path.basename(file_path)}")
    print()
    
    if base44_urls:
        print("🏗️  Base44 Project URLs:")
        print("=" * 50)
        for url in base44_urls:
            print(url)
    else:
        print("ℹ️  No base44 projects found in the scan results.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No argument provided, use latest CSV file
        csv_file = get_latest_csv()
        if not csv_file:
            print("❌ No CSV files found in repo-scanner-results directory")
            print("Usage: python base44_url_extractor.py [csv_file_path]")
            sys.exit(1)
        print(f"📁 Using latest file: {os.path.basename(csv_file)}")
        print()
    elif len(sys.argv) == 2:
        csv_file = sys.argv[1]
        if not os.path.exists(csv_file):
            print(f"❌ File not found: {csv_file}")
            print("Usage: python base44_url_extractor.py [csv_file_path]")
            sys.exit(1)
    else:
        print("Usage: python base44_url_extractor.py [csv_file_path]")
        print("  - No arguments: Uses the latest CSV file from repo-scanner-results directory")
        print("  - csv_file_path: Uses the specified CSV file")
        sys.exit(1)
    
    extract_base44_urls(csv_file)
