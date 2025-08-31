# Data Security Scripts Documentation

This repository contains a comprehensive collection of security analysis tools designed to detect vulnerabilities and security issues in GitHub repositories, with a special focus on Base44 applications. The scripts are organized into utility modules and specialized detectors.

## Architecture Overview

The repository follows a modular architecture where utility scripts provide core functionality to specialized detector scripts. This design promotes code reuse and maintainability.

---

## Utility Scripts (Core Infrastructure)

### 1. `base44_client.py` - Base44 API Client
**Purpose**: Provides a comprehensive interface for interacting with Base44 application APIs.

**How it works**: 
- Implements the `Base44App` class that handles authentication via bearer tokens
- Connects to Base44 API endpoints to retrieve project information, entities, and table data
- Includes error handling for timeouts, connection issues, and authentication failures
- Supports both authenticated and unauthenticated requests for different security analysis scenarios

**Key Features**:
- Entity enumeration from Base44 projects
- Table data retrieval with customizable limits
- Project information gathering
- Robust error handling and timeout management

---

### 2. `github_client.py` - GitHub Repository Client
**Purpose**: Handles all GitHub repository operations including downloading, parsing, and file management.

**How it works**:
- Implements the `GitHubClient` class for comprehensive GitHub API interactions
- Downloads entire repositories as ZIP files for local analysis
- Parses GitHub URLs to extract owner and repository information
- Automatically detects Base44 projects within repositories
- Manages authentication using GitHub tokens from `token.txt`
- Implements caching mechanism to avoid redundant downloads

**Key Features**:
- Repository downloading and extraction
- File tree traversal and content retrieval
- Base44 project detection and client instantiation
- Rate limiting and error handling for GitHub API calls

---

### 3. `repo_manager.py` - Local Repository Manager
**Purpose**: Manages downloaded repository folders and provides file system operations.

**How it works**:
- Implements the `RepoFolderManager` class for local file operations
- Provides context management for temporary directories
- Handles file searching, reading, and cleanup operations
- Supports both cached and temporary repository storage
- Automatically cleans up temporary files after analysis

**Key Features**:
- File searching across repository structures
- Safe file reading with error handling
- Automatic cleanup of temporary directories
- Cache management for repeated analyses

---

### 4. `utils.py` - Common Utilities
**Purpose**: Provides shared utility functions used across multiple detector scripts.

**How it works**:
- Contains helper functions for common operations like getting line context
- Reduces code duplication across detector scripts
- Provides consistent error handling patterns

**Key Features**:
- Line context extraction for vulnerability reporting
- Common string manipulation utilities
- Standardized error handling helpers

---

## Security Detector Scripts

### 1. `anonymous_app_detector.py` - Anonymous Access Vulnerability Detector
**Purpose**: Detects Base44 projects that allow unauthorized anonymous access to sensitive data.

**How it works**:
- Extracts Base44 project ID from the target repository
- Attempts to access project entities without authentication
- Identifies which entities are accessible to anonymous users
- Reports accessible entities as potential security vulnerabilities

**Command Example**:
```bash
python anonymous_app_detector.py --repo-url https://github.com/username/base44-project
```

---

### 2. `secret_detector.py` - Hardcoded Secrets Detector
**Purpose**: Scans repository files to identify hardcoded API keys, tokens, and other sensitive credentials.

**How it works**:
- Downloads and analyzes all text files in the repository
- Uses regex patterns to identify various types of secrets (JWT tokens, OAuth tokens, API keys)
- Provides detailed reports including file locations and line numbers
- Includes context around each found secret for verification

**Command Example**:
```bash
python secret_detector.py https://github.com/username/repository --timeout 30
```

---

### 3. `password_detector.py` - Insecure Password Storage Detector
**Purpose**: Identifies Base44 database tables that may store passwords in an insecure manner.

**How it works**:
- Connects to Base44 project using authenticated API access
- Enumerates all database tables and their schemas
- Identifies tables with column names containing "password"
- Checks if these tables contain actual data that might include passwords
- Reports potentially insecure password storage practices

**Command Example**:
```bash
python password_detector.py --token YOUR_BEARER_TOKEN --repo-url https://github.com/username/base44-project
```

---

### 4. `idor_detector.py` - IDOR Vulnerability Detector
**Purpose**: Detects potential Insecure Direct Object Reference (IDOR) vulnerabilities in Base44 applications.

**How it works**:
- Identifies database tables that contain actual data
- Scans frontend code to find references to these tables
- Checks if table access is properly protected by authentication/authorization
- Reports tables that might be vulnerable to IDOR attacks through direct API access

**Command Example**:
```bash
python idor_detector.py --token YOUR_BEARER_TOKEN --repo-url https://github.com/username/base44-project
```

---

### 5. `http_detector.py` - Insecure HTTP URL Detector
**Purpose**: Identifies unencrypted HTTP URLs in code that could be vulnerable to man-in-the-middle attacks.

**How it works**:
- Scans all code files for HTTP URL patterns
- Identifies various forms of HTTP URLs (direct URLs, configuration values, comments)
- Analyzes the context to determine if the HTTP usage poses a security risk
- Reports potentially insecure HTTP communications

**Command Example**:
```bash
python http_detector.py https://github.com/username/repository --timeout 30
```

---

### 6. `https_detector.py` - SSL Certificate Validator
**Purpose**: Detects HTTPS URLs and validates their SSL certificates for security issues.

**How it works**:
- Scans code files for HTTPS URLs
- Performs real-time SSL certificate validation for discovered URLs
- Checks certificate expiration dates, issuer validity, and protocol versions
- Reports SSL/TLS configuration issues and certificate problems

**Command Example**:
```bash
python https_detector.py https://github.com/username/repository --timeout 30
```

---

### 7. `base44_repo_checker.py` - Base44 Project Detector
**Purpose**: Determines whether a GitHub repository was created using the Base44 platform.

**How it works**:
- Downloads the repository and analyzes its structure
- Looks for Base44-specific indicators (SDK usage, client configurations, logos, README patterns)
- Uses multiple detection heuristics to minimize false positives
- Provides confidence scoring for Base44 project identification

**Command Example**:
```bash
python base44_repo_checker.py https://github.com/username/repository --timeout 30
```

---

### 8. `get_integrations.py` - Base44 Integrations Enumerator
**Purpose**: Retrieves and displays all available integrations in a Base44 project.

**How it works**:
- Connects to Base44 API with authenticated access
- Enumerates all configured integrations and their endpoints
- Displays integration details for security assessment
- Helps identify potential attack surfaces through third-party integrations

**Command Example**:
```bash
python get_integrations.py --token YOUR_BEARER_TOKEN --repo-url https://github.com/username/base44-project
```

---

## Orchestration Scripts

### 1. `security_orchestrator.py` - Comprehensive Security Analysis
**Purpose**: Coordinates all security detectors to perform complete security analysis of a repository.

**How it works**:
- Runs Base44 detection first to determine analysis strategy
- Executes static analysis tools (secrets, HTTP/HTTPS) for all repositories
- Runs authenticated analysis tools (passwords, IDOR, integrations) for Base44 projects when token is provided
- Generates comprehensive security reports with categorized findings

**Command Example**:
```bash
python security_orchestrator.py --repo-url https://github.com/username/repository --token YOUR_BEARER_TOKEN
```

---

### 2. `github_repo_scanner.py` - Mass Repository Scanner
**Purpose**: Searches GitHub for repositories matching specific criteria and performs security analysis on each.

**How it works**:
- Uses GitHub Search API to find repositories based on search terms
- Iterates through search results and performs comprehensive security analysis
- Generates aggregated security reports across multiple repositories
- Supports rate limiting and batch processing for large-scale analysis

**Command Example**:
```bash
python github_repo_scanner.py --search "react app" --limit 10 --token YOUR_BEARER_TOKEN
```

---

## Configuration Files

- **`token.txt`**: Contains GitHub personal access token for API authentication
- **`requirements.txt`**: Lists all Python dependencies required by the scripts

## Usage Patterns

### For Single Repository Analysis:
1. Use `security_orchestrator.py` for comprehensive analysis
2. Use individual detectors for specific vulnerability types

### For Multiple Repository Analysis:
1. Use `github_repo_scanner.py` for bulk scanning
2. Configure search terms to target specific types of projects

### For Base44-Specific Analysis:
1. Ensure you have a valid bearer token for authenticated analysis
2. Use Base44-specific detectors (`password_detector.py`, `idor_detector.py`, `get_integrations.py`)

## Security Considerations

- Always use secure authentication tokens
- Be mindful of API rate limits when scanning multiple repositories
- Review findings manually as automated tools may produce false positives
- Store tokens securely and never commit them to version control
