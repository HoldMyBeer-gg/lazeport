"""Jira integration service."""
import json
import logging
import re
from typing import Dict, List, Optional

import httpx

log = logging.getLogger(__name__)


def _sanitize_error_message(msg: str) -> str:
    """Remove potential tokens/secrets from error messages.
    
    Strips out:
    - Long alphanumeric strings (likely tokens)
    - Base64-looking strings
    - Authorization headers
    - API keys
    """
    if not msg:
        return "Unknown error"
    
    # Remove anything that looks like a token (20+ alphanumeric/special chars)
    msg = re.sub(r'[A-Za-z0-9_\-+/=]{20,}', '[REDACTED]', msg)
    
    # Remove authorization/bearer patterns
    msg = re.sub(r'(authorization|bearer|token|api[_-]?key)[\s:=]+[^\s]+', r'\1: [REDACTED]', msg, flags=re.IGNORECASE)
    
    return msg


class JiraClient:
    """Simple Jira REST API client."""
    
    def __init__(self, url: str, email: str, api_token: str):
        """
        Initialize Jira client.
        
        Args:
            url: Jira instance URL (e.g., https://yourorg.atlassian.net)
            email: User email for authentication
            api_token: API token from Atlassian account settings
        """
        self.url = url.rstrip('/')
        self.auth = (email, api_token)
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        }
    
    def test_connection(self) -> tuple[bool, str]:
        """Test if credentials work. Returns (success, message)."""
        try:
            response = httpx.get(
                f"{self.url}/rest/api/3/myself",
                auth=self.auth,
                headers=self.headers,
                timeout=10.0,
            )
            if response.status_code == 200:
                user = response.json()
                return True, f"Connected as {user.get('displayName', 'Unknown')}"
            return False, f"Authentication failed: {response.status_code}"
        except Exception as e:
            log.error(f"Jira connection test failed: {e}")
            sanitized = _sanitize_error_message(str(e))
            return False, f"Connection failed: {sanitized}"
    
    def list_projects(self, query: str = "") -> List[Dict]:
        """
        List Jira projects accessible to the user.
        
        Returns:
            List of dicts with keys: id, key, name
        """
        try:
            response = httpx.get(
                f"{self.url}/rest/api/3/project/search",
                auth=self.auth,
                headers=self.headers,
                params={'maxResults': 100},
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()
            projects = []
            for p in data.get('values', []):
                project = {
                    'id': p.get('id'),
                    'key': p.get('key'),
                    'name': p.get('name'),
                }
                
                # Skip projects with missing key or name (defensive: Jira API should always provide these)
                if not project['key'] or not project['name']:
                    log.warning(f"Skipping Jira project with missing key or name: {project}")
                    continue
                
                # Filter by query if provided
                if query:
                    q_lower = query.lower()
                    if (q_lower in project['key'].lower() or 
                        q_lower in project['name'].lower()):
                        projects.append(project)
                else:
                    projects.append(project)
            return projects
        except Exception as e:
            log.error(f"Failed to list Jira projects: {e}")
            return []
    
    def get_issue_types(self, project_key: str) -> List[Dict]:
        """Get available issue types for a project."""
        try:
            response = httpx.get(
                f"{self.url}/rest/api/3/project/{project_key}",
                auth=self.auth,
                headers=self.headers,
                timeout=10.0,
            )
            response.raise_for_status()
            data = response.json()
            return data.get('issueTypes', [])
        except Exception as e:
            log.error(f"Failed to get issue types: {e}")
            return []
    
    def create_issue(
        self,
        project_key: str,
        summary: str,
        description: str,
        issue_type: str = "Bug",
        priority: Optional[str] = None,
        labels: Optional[List[str]] = None,
    ) -> tuple[bool, str, Optional[str]]:
        """
        Create a Jira issue.
        
        Returns:
            (success: bool, message: str, issue_key: Optional[str])
        """
        try:
            # Build issue payload
            fields = {
                'project': {'key': project_key},
                'summary': summary,
                'description': {
                    'type': 'doc',
                    'version': 1,
                    'content': [
                        {
                            'type': 'paragraph',
                            'content': [
                                {
                                    'type': 'text',
                                    'text': description,
                                }
                            ]
                        }
                    ]
                },
                'issuetype': {'name': issue_type},
            }
            
            if priority:
                fields['priority'] = {'name': priority}
            
            if labels:
                fields['labels'] = labels
            
            response = httpx.post(
                f"{self.url}/rest/api/3/issue",
                auth=self.auth,
                headers=self.headers,
                json={'fields': fields},
                timeout=15.0,
            )
            
            if response.status_code == 201:
                data = response.json()
                issue_key = data.get('key')
                issue_url = f"{self.url}/browse/{issue_key}"
                return True, f"Created {issue_key}: {issue_url}", issue_key
            else:
                error_data = response.json() if response.text else {}
                error_msg = error_data.get('errorMessages', [response.text])[0] if error_data.get('errorMessages') else str(error_data)
                sanitized_msg = _sanitize_error_message(str(error_msg))
                return False, f"Failed to create issue: {sanitized_msg}", None
                
        except Exception as e:
            log.error(f"Failed to create Jira issue: {e}")
            sanitized = _sanitize_error_message(str(e))
            return False, f"Error: {sanitized}", None


def get_jira_client(config_json: str) -> Optional[JiraClient]:
    """Create JiraClient from stored config JSON."""
    try:
        config = json.loads(config_json)
        url = config.get('url')
        email = config.get('email')
        api_token = config.get('api_token')
        
        if not all([url, email, api_token]):
            return None
        
        return JiraClient(url=url, email=email, api_token=api_token)
    except Exception as e:
        log.error(f"Failed to create Jira client: {e}")
        return None
