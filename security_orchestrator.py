#!/usr/bin/env python3
"""
Security Orchestrator

This script orchestrates all security detection scripts for a given GitHub repository.
It first checks if the repository is a Base44 project, and then runs various security
scans in a logical order.

Usage:
    python security_orchestrator.py --repo-url GITHUB_REPO_URL [--token BEARER_TOKEN]

Example:
    python security_orchestrator.py --repo-url https://github.com/username/repository
    python security_orchestrator.py --repo-url https://github.com/username/repository --token your_bearer_token
"""

import sys
import argparse
from typing import Optional

# Import all the detector classes
from base44_repo_checker import Base44Detector
from secret_detector import SecretDetector
from http_detector import HTTPDetector
from https_detector import HTTPSDetector
from anonymous_app_detector import AnonymousAppDetector
from password_detector import PasswordDetector
from idor_detector import IDORDetector
from get_integrations import IntegrationsRetriever


class SecurityOrchestrator:
    """Orchestrates all security detection scripts"""

    def __init__(self, repo_url: str, bearer_token: Optional[str] = None):
        self.repo_url = repo_url
        self.bearer_token = bearer_token
        self.project_id = None
        self.is_base44 = False
        
    def run_base44_check(self) -> bool:
        """
        Run Base44 repository check first
        Returns True if it's a Base44 project, False otherwise
        """
        print("=" * 60)
        print("STEP 1: Base44 Repository Detection")
        print("=" * 60)
        
        try:
            detector = Base44Detector(timeout=10)
            is_base44, confidence, indicators = detector.detect_base44_repository(self.repo_url)
            
            if is_base44:
                print(f"✅ Repository is a Base44 project (confidence: {confidence:.2f})")
                self.project_id = detector.project_id
                if self.project_id:
                    print(f"📋 Project ID: {self.project_id}")
                self.is_base44 = True
                return True
            else:
                print("❌ Repository is NOT a Base44 project")
                if 'error' in indicators:
                    print(f"   Error: {indicators['error']}")
                return False
                
        except Exception as e:
            print(f"❌ Error during Base44 detection: {e}")
            return False

    def run_static_analysis(self):
        """Run static analysis that doesn't require authentication"""
        print("\n" + "=" * 60)
        print("STEP 2: Static Code Analysis (No Authentication Required)")
        print("=" * 60)
        
        # Secret Detection
        self._run_secret_detection()
        
        # HTTP URL Detection
        self._run_http_detection()
        
        # HTTPS Certificate Analysis
        self._run_https_detection()

    def run_authenticated_analysis(self):
        """Run analysis that requires Base44 authentication token"""
        if not self.bearer_token:
            print("\n" + "=" * 60)
            print("STEP 3: Authenticated Analysis - SKIPPED (No Bearer Token)")
            print("=" * 60)
            print("⚠️  Bearer token not provided. Skipping authenticated security checks:")
            print("   - Password storage vulnerability detection")
            print("   - IDOR vulnerability detection") 
            print("   - Integrations retrieval")
            return

        print("\n" + "=" * 60)
        print("STEP 3: Authenticated Analysis")
        print("=" * 60)
        
        # Password Storage Vulnerability Detection
        self._run_password_detection()
        
        # IDOR Vulnerability Detection
        self._run_idor_detection()
        
        # Integrations Retrieval
        self._run_integrations_retrieval()

    def run_anonymous_access_check(self):
        """Run anonymous access vulnerability check"""
        print("\n" + "=" * 60)
        print("STEP 4: Anonymous Access Vulnerability Check")
        print("=" * 60)
        
        try:
            detector = AnonymousAppDetector(self.repo_url)
            detector.detect_anonymous_access()
                
        except Exception as e:
            print(f"❌ Error during anonymous access detection: {e}")

    def _run_secret_detection(self):
        """Run secret detection"""
        print("\n🔍 Secret Detection")
        print("-" * 40)
        
        try:
            detector = SecretDetector(timeout=30)
            secrets = detector.detect_secrets(self.repo_url)
            
            if secrets:
                print(f"⚠️  Found {len(secrets)} potential secrets:")
                for secret in secrets:
                    secret_type = secret.get('type', 'Unknown')
                    file_path = secret.get('file', 'Unknown file')
                    line_num = secret.get('line', 'Unknown line')
                    match_text = secret.get('match', secret.get('value', 'Hidden'))
                    print(f"   - {secret_type} in {file_path}")
                    print(f"     Line {line_num}: {match_text}")
            else:
                print("✅ No hardcoded secrets found")
                
        except Exception as e:
            print(f"❌ Error during secret detection: {e}")

    def _run_http_detection(self):
        """Run HTTP URL detection"""
        print("\n🔍 HTTP URL Detection")
        print("-" * 40)
        
        try:
            detector = HTTPDetector(timeout=30)
            issues = detector.detect_http_security_issues(self.repo_url)
            
            if issues:
                print(f"⚠️  Found {len(issues)} insecure HTTP URLs:")
                for issue in issues:
                    url = issue.get('url', 'Unknown URL')
                    file_path = issue.get('file', 'Unknown file')
                    line_num = issue.get('line', 'Unknown line')
                    risk_level = issue.get('risk_level', issue.get('severity', 'Unknown'))
                    print(f"   - {url} in {file_path}")
                    print(f"     Line {line_num}: {risk_level} risk")
            else:
                print("✅ No insecure HTTP URLs found")
                
        except Exception as e:
            print(f"❌ Error during HTTP detection: {e}")

    def _run_https_detection(self):
        """Run HTTPS certificate analysis"""
        print("\n🔍 HTTPS Certificate Analysis")
        print("-" * 40)
        
        try:
            detector = HTTPSDetector(timeout=30)
            issues = detector.detect_https_security_issues(self.repo_url)
            
            if issues:
                print(f"⚠️  Found {len(issues)} HTTPS certificate issues:")
                for issue in issues:
                    url = issue.get('url', 'Unknown URL')
                    issue_type = issue.get('issue_type', issue.get('type', 'Unknown issue'))
                    severity = issue.get('severity', 'Unknown')
                    print(f"   - {url}: {issue_type}")
                    if severity != 'Unknown':
                        print(f"     Severity: {severity}")
            else:
                print("✅ No HTTPS certificate issues found")
                
        except Exception as e:
            print(f"❌ Error during HTTPS detection: {e}")

    def _run_password_detection(self):
        """Run password storage vulnerability detection"""
        print("\n🔍 Password Storage Vulnerability Detection")
        print("-" * 40)
        
        try:
            detector = PasswordDetector(self.bearer_token, self.repo_url)
            detector.detect_password_vulnerabilities()
        except Exception as e:
            print(f"❌ Error during password detection: {e}")

    def _run_idor_detection(self):
        """Run IDOR vulnerability detection"""
        print("\n🔍 IDOR Vulnerability Detection")
        print("-" * 40)
        
        try:
            detector = IDORDetector(self.bearer_token, self.repo_url)
            has_idor = detector.detect_idor_vulnerabilities(self.repo_url)      
        except Exception as e:
            print(f"❌ Error during IDOR detection: {e}")

    def _run_integrations_retrieval(self):
        """Run integrations retrieval"""
        print("\n🔍 Integrations Analysis")
        print("-" * 40)
        
        try:
            retriever = IntegrationsRetriever(self.bearer_token, self.repo_url)
            retriever.get_integrations()   
        except Exception as e:
            print(f"❌ Error during integrations retrieval: {e}")

    def run_all_scans(self):
        """Run all security scans in the correct order"""
        print("🚀 Starting Security Analysis")
        print("Repository:", self.repo_url)
        if self.bearer_token:
            print("Bearer Token: Provided")
        else:
            print("Bearer Token: Not provided (some checks will be skipped)")
        
        # Step 1: Check if it's a Base44 repository
        if not self.run_base44_check():
            print("\n❌ Repository is not a Base44 project. Ending analysis.")
            return False
        
        # Step 2: Run static analysis (no authentication required)
        self.run_static_analysis()
        
        # Step 3: Run authenticated analysis (requires bearer token)
        self.run_authenticated_analysis()
        
        # Step 4: Run anonymous access check
        self.run_anonymous_access_check()
        
        print("\n" + "=" * 60)
        print("✅ Security Analysis Complete")
        print("=" * 60)
        
        return True


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='Run comprehensive security analysis on a GitHub repository',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python security_orchestrator.py --repo-url https://github.com/username/repository
  python security_orchestrator.py --repo-url https://github.com/username/repository --token your_bearer_token
        """
    )
    
    parser.add_argument('--repo-url', required=True, help='GitHub repository URL')
    parser.add_argument('--token', help='Bearer token for authenticated Base44 API calls')
    
    args = parser.parse_args()
    
    try:
        orchestrator = SecurityOrchestrator(args.repo_url, args.token)
        success = orchestrator.run_all_scans()
        
        # Exit with appropriate code
        sys.exit(0 if success else 1)
        
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
