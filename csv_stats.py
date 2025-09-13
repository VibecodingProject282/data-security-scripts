#!/usr/bin/env python3
"""
CSV Statistics Analyzer
Analyzes security scan results and prints minimal statistics
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

def analyze_csv(file_path):
    """Analyze CSV file and print statistics"""
    
    stats = {
        'total_repos': 0,
        'base44_repos': 0,
        'repos_with_secrets': 0,
        'repos_with_http': 0,
        'repos_with_https': 0,
        'repos_with_passwords': 0,
        'repos_with_idor_low': 0,
        'repos_with_idor_high': 0,
        'repos_with_anonymous_access': 0,
        'repos_skipped_no_token': 0,
        'repos_skipped_no_project_id': 0
    }
    
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            reader = csv.DictReader(file)
            
            for row in reader:
                stats['total_repos'] += 1
                
                # Base44 projects
                if row['is_base44'].lower() == 'true':
                    stats['base44_repos'] += 1
                else:
                    continue # not a Base44 project, skip further checks
                
                # Security findings
                if int(row['secret_count']) > 0:
                    stats['repos_with_secrets'] += 1
                
                if int(row['http_count']) > 0:
                    stats['repos_with_http'] += 1
                
                if int(row['https_count']) > 1:
                    stats['repos_with_https'] += 1
                
                # Check if authenticated analysis was skipped
                password_val = row['password_vulnerability'].strip().lower()
                idor_low_val = row['idor_tables_low'].strip().lower()
                idor_high_val = row['idor_tables_high'].strip().lower()
                integration_val = row['integration_count'].strip().lower()

                if row['is_base44'].lower() == 'true' and not row['project_id'].strip():
                    stats['repos_skipped_no_project_id'] += 1
                    continue # no project ID, skip further checks

                if row['anonymous_access'].lower() == 'true':
                    stats['repos_with_anonymous_access'] += 1
                elif row['anonymous_access'].lower() == 'false':
                    stats['repos_skipped_no_token'] += 1
                    continue # no token, skip further checks
                    
                # Only count these if not skipped
                if password_val == 'true':
                    stats['repos_with_passwords'] += 1
                if int(idor_low_val) > 0:
                    stats['repos_with_idor_low'] += 1
                if int(idor_high_val) > 0:
                    stats['repos_with_idor_high'] += 1
                

    
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return
    except Exception as e:
        print(f"❌ Error reading file: {e}")
        return
    
    # Print statistics
    print(f"📊 Total repositories: {stats['total_repos']}")
    print(f"🏗️  Base44 projects: {stats['base44_repos']}")
    print(f"🔐 Repos with hard-coded secrets: {stats['repos_with_secrets']}")
    print(f"🌐 Repos with unsecure HTTP URLs: {stats['repos_with_http']}")
    print(f"🔒 Repos with unsecure HTTPS URLs (certificate issues): {stats['repos_with_https']}")
    print(f"🔑 Repos with password visibility issues: {stats['repos_with_passwords']}")
    print(f"⚠️  Repos with IDOR (low): {stats['repos_with_idor_low']}")
    print(f"🚨 Repos with IDOR (high): {stats['repos_with_idor_high']}")
    print(f"👤 Repos with anonymous access: {stats['repos_with_anonymous_access']}")

    print(f"\n⚠️  Projects skipped (no token provided): {stats['repos_skipped_no_token']}")
    print(f"⚠️  Projects skipped (no Base44 project ID found): {stats['repos_skipped_no_project_id']}")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # No argument provided, use latest CSV file
        csv_file = get_latest_csv()
        if not csv_file:
            print("❌ No CSV files found in repo-scanner-results directory")
            print("Usage: python csv_stats.py [csv_file_path]")
            sys.exit(1)
        print(f"📁 Using latest file: {os.path.basename(csv_file)}")
    elif len(sys.argv) == 2:
        csv_file = sys.argv[1]
    else:
        print("Usage: python csv_stats.py [csv_file_path]")
        sys.exit(1)
    
    analyze_csv(csv_file)
