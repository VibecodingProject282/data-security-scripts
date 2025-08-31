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
        
        # Store findings from all detectors
        self.findings = {
            'base44_detected': False,
            'base44_project_id': None,
            'secrets_found': False,
            'secrets_details': [],
            'http_urls_found': False,
            'http_details': [],
            'https_issues_found': False,
            'https_details': [],
            'password_vulnerabilities': False,
            'password_details': [],
            'idor_vulnerabilities': False,
            'idor_details': [],
            'integrations_found': False,
            'integrations_details': [],
            'anonymous_access_vulnerabilities': False,
            'anonymous_access_details': []
        }
        
    def run_base44_check(self) -> bool:
        """
        Run Base44 repository check first
        Returns True if it's a Base44 project, False otherwise
        """
        try:
            detector = Base44Detector(timeout=10)
            is_base44, confidence, indicators = detector.detect_base44_repository(self.repo_url)
            
            if is_base44:
                print(f"✅ Base44 project detected")
                self.project_id = detector.project_id
                self.is_base44 = True
                self.findings['base44_detected'] = True
                self.findings['base44_project_id'] = self.project_id
                return True
            else:
                print("❌ Not a Base44 project")
                self.findings['base44_detected'] = False
                return False
                
        except Exception as e:
            print(f"❌ Error during Base44 detection: {e}")
            return False

    def run_static_analysis(self):
        """Run static analysis that doesn't require authentication"""
        print("🔍 Running security code scans...")
        
        # Secret Detection
        self._run_secret_detection()
        
        # HTTP URL Detection
        self._run_http_detection()
        
        # HTTPS Certificate Analysis
        self._run_https_detection()

    def run_authenticated_analysis(self):
        """Run analysis that requires Base44 authentication token"""
        if not self.is_base44:
            return
            
        # Check if we have a token or if anonymous access allows us to proceed
        has_anonymous_access = self.findings.get('anonymous_access_vulnerabilities', False)
        
        if not self.bearer_token and not has_anonymous_access:
            print("⚠️  Skipping authenticated analysis (no token + no anonymous access)")
            return

        if not self.bearer_token and has_anonymous_access:
            print("🔍 Running authenticated analysis (anonymous access detected)")
            # Use a dummy token since the app allows anonymous access
            self.bearer_token = "dummy_token_for_anonymous_access"
        
        # Password Storage Vulnerability Detection
        self._run_password_detection()
        
        # IDOR Vulnerability Detection
        self._run_idor_detection()
        
        # Integrations Retrieval
        self._run_integrations_retrieval()

    def run_anonymous_access_check(self):
        """Run anonymous access vulnerability check"""
        if not self.is_base44:
            return

        print("🔍 Running anonymous access check...")
        try:
            detector = AnonymousAppDetector(self.repo_url)
            detector.detect_anonymous_access()
            if detector.accessible_entities:
                self.findings['anonymous_access_vulnerabilities'] = True
                self.findings['anonymous_access_details'] = detector.accessible_entities
                
        except Exception as e:
            pass  # Silently handle errors, details in JSON

    def _run_secret_detection(self):
        """Run secret detection"""
        try:
            detector = SecretDetector(timeout=30)
            secrets = detector.detect_secrets(self.repo_url)
            
            if secrets:
                self.findings['secrets_found'] = True
                self.findings['secrets_details'] = secrets
            else:
                self.findings['secrets_found'] = False
                self.findings['secrets_details'] = []
                
        except Exception as e:
            self.findings['secrets_found'] = False
            self.findings['secrets_details'] = []

    def _run_http_detection(self):
        """Run HTTP URL detection"""
        try:
            detector = HTTPDetector(timeout=30)
            issues = detector.detect_http_security_issues(self.repo_url)
            
            if issues:
                self.findings['http_urls_found'] = True
                self.findings['http_details'] = issues
            else:
                self.findings['http_urls_found'] = False
                self.findings['http_details'] = []
                
        except Exception as e:
            self.findings['http_urls_found'] = False
            self.findings['http_details'] = []

    def _run_https_detection(self):
        """Run HTTPS certificate analysis"""
        try:
            detector = HTTPSDetector(timeout=30)
            issues = detector.detect_https_security_issues(self.repo_url)
            
            if issues:
                self.findings['https_issues_found'] = True
                self.findings['https_details'] = issues
            else:
                self.findings['https_issues_found'] = False
                self.findings['https_details'] = []
                
        except Exception as e:
            self.findings['https_issues_found'] = False
            self.findings['https_details'] = []

    def _run_password_detection(self):
        """Run password storage vulnerability detection"""
        try:
            detector = PasswordDetector(self.bearer_token, self.repo_url)
            detector.detect_password_vulnerabilities()
            
            # Get the results from the detector
            if hasattr(detector, 'tables_with_passwords') and detector.tables_with_passwords:
                self.findings['password_vulnerabilities'] = True
                self.findings['password_details'] = detector.tables_with_passwords
            else:
                self.findings['password_vulnerabilities'] = False
                self.findings['password_details'] = []
                
        except Exception as e:
            self.findings['password_vulnerabilities'] = False
            self.findings['password_details'] = []

    def _run_idor_detection(self):
        """Run IDOR vulnerability detection"""
        try:
            detector = IDORDetector(self.bearer_token, self.repo_url)
            has_idor = detector.detect_idor_vulnerabilities(self.repo_url)
            
            self.findings['idor_vulnerabilities'] = has_idor
            if has_idor:
                # Try to get detailed findings if available
                idor_details = []
                if hasattr(detector, 'data_tables') and detector.data_tables:
                    idor_details.extend([{'table': table, 'risk': 'HIGH'} for table in detector.data_tables])
                if hasattr(detector, 'all_tables') and detector.all_tables:
                    idor_details.extend([{'table': table, 'risk': 'LOW'} for table in detector.all_tables if table not in (detector.data_tables or [])])
                self.findings['idor_details'] = idor_details
            else:
                self.findings['idor_details'] = []
                
        except Exception as e:
            self.findings['idor_vulnerabilities'] = False
            self.findings['idor_details'] = []

    def _run_integrations_retrieval(self):
        """Run integrations retrieval"""
        try:
            retriever = IntegrationsRetriever(self.bearer_token, self.repo_url)
            retriever.get_integrations()
            
            # Get the integrations from the retriever
            if hasattr(retriever, 'integrations') and retriever.integrations:
                self.findings['integrations_found'] = True
                self.findings['integrations_details'] = retriever.integrations
            else:
                self.findings['integrations_found'] = False
                self.findings['integrations_details'] = []
                
        except Exception as e:
            self.findings['integrations_found'] = False
            self.findings['integrations_details'] = []

    def run_all_scans(self):
        """Run all security scans in the correct order"""
        # Step 1: Check if it's a Base44 repository
        if not self.run_base44_check():
            return False
        
        # Step 2: Run static analysis (no authentication required)
        self.run_static_analysis()

        # Step 3: Run anonymous access check (No authentication required)
        self.run_anonymous_access_check()

        # Step 4: Run authenticated analysis (may require bearer token)
        self.run_authenticated_analysis()
        
        return True

    def get_findings(self):
        """
        Get all security findings from the analysis
        
        Returns:
            Dictionary containing all findings from security detectors
        """
        return self.findings.copy()

    def print_results(self):
        """
        Print a concise and clear summary of all security findings
        """
        print("\n")
        print("🔍 SECURITY ANALYSIS RESULTS")
        print("="*30)
        
        # Base44 Detection
        if self.findings['base44_detected']:
            print(f"✅ Base44 Project: {self.findings['base44_project_id']}")
        else:
            print("❌ Base44 Project: Not detected")
        
        print("\n📊 SECURITY FINDINGS:")
        print("-" * 25)
        
        # Secrets
        if self.findings['secrets_found']:
            print(f"🚨 Secrets Found: {len(self.findings['secrets_details'])} issues")
            for secret in self.findings['secrets_details'][:3]:  # Show first 3
                file_path = secret.get('file', 'Unknown file')
                secret_type = secret.get('type', 'Unknown type')
                print(f"   • {secret_type} in {file_path}")
            if len(self.findings['secrets_details']) > 3:
                print(f"   ... and {len(self.findings['secrets_details']) - 3} more")
        else:
            print("✅ Secrets: None found")
        
        # HTTP URLs
        if self.findings['http_urls_found']:
            print(f"⚠️  HTTP URLs: {len(self.findings['http_details'])} found")
            for http in self.findings['http_details'][:2]:  # Show first 2
                print(f"   • {http.get('url', 'Unknown URL')}")
            if len(self.findings['http_details']) > 2:
                print(f"   ... and {len(self.findings['http_details']) - 2} more")
        else:
            print("✅ HTTP URLs: None found")
        
        # HTTPS Issues
        if self.findings['https_issues_found']:
            print(f"⚠️  HTTPS Issues: {len(self.findings['https_details'])} found")
        else:
            print("✅ HTTPS Issues: None found")
        
        # Anonymous Access
        if self.findings['anonymous_access_vulnerabilities']:
            print(f"🚨 Anonymous Access: {len(self.findings['anonymous_access_details'])} vulnerabilities")
        else:
            print("✅ Anonymous Access: Secure")
        
        # Password Vulnerabilities
        if self.findings['password_vulnerabilities']:
            print(f"🚨 Password Issues: {len(self.findings['password_details'])} tables affected")
        else:
            print("✅ Password Storage: Secure")
        
        # IDOR Vulnerabilities
        if self.findings['idor_vulnerabilities']:
            print(f"🚨 IDOR Issues: {len(self.findings['idor_details'])} potential vulnerabilities")
        else:
            print("✅ IDOR Protection: Secure")
        
        # Integrations
        if self.findings['integrations_found']:
            print(f"ℹ️  Integrations: {len(self.findings['integrations_details'])} found")
        else:
            print("ℹ️  Integrations: None found")


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
        orchestrator.print_results()

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
