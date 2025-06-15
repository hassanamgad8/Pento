import vulners
import os
from typing import List, Dict, Any

def enrich_finding_with_vulners(service: str, version: str) -> List[Dict[str, Any]]:
    """
    Enriches vulnerability findings with data from Vulners API.
    
    Args:
        service (str): The service name (e.g., 'apache', 'nginx')
        version (str): The service version
        
    Returns:
        list: List of enriched vulnerability findings
    """
    try:
        # Get API key from environment variable
        api_key = os.getenv('VULNERS_API_KEY')
        if not api_key:
            print("Warning: VULNERS_API_KEY environment variable not set")
            return []

        # Initialize Vulners API client
        vulners_api = vulners.Vulners(api_key=api_key)
        
        # Construct search query
        query = f'type:cve AND affectedSoftware.name:{service} AND affectedSoftware.version:{version}'
        
        # Search for vulnerabilities
        search_result = vulners_api.search(query)
        
        # Process and return findings
        findings = []
        if search_result and 'data' in search_result:
            for vuln in search_result['data']:
                findings.append({
                    'id': vuln.get('id'),
                    'title': vuln.get('title'),
                    'description': vuln.get('description'),
                    'cvss': vuln.get('cvss', {}).get('score'),
                    'published': vuln.get('published'),
                    'modified': vuln.get('modified'),
                    'type': vuln.get('type'),
                    'references': vuln.get('references', [])
                })
        
        return findings
        
    except Exception as e:
        print(f"Error querying Vulners API: {str(e)}")
        return [] 