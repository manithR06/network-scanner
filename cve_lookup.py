import requests
import time
import json
import os
from datetime import datetime, timedelta

# Simple file-based cache so we don't hammer the API
CACHE_FILE = '/tmp/cve_cache.json'


def load_cache():
    """Load cached CVE results from disk."""
    if os.path.exists(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            pass
    return {}


def save_cache(cache):
    """Save CVE results to disk cache."""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f)
    except:
        pass


def lookup_cves(service_name, version=None, max_results=5):
    """
    Look up CVEs for a service name and optional version.
    Returns a list of CVE dicts with id, description, severity, score.

    Example:
        lookup_cves('openssh', '8.2')
        lookup_cves('apache')
    """
    if not service_name:
        return []

    # Build cache key
    cache_key = f"{service_name}:{version or 'any'}"
    cache = load_cache()

    # Return cached result if fresh
    if cache_key in cache:
        entry = cache[cache_key]
        cached_at = datetime.fromisoformat(entry['cached_at'])
        if datetime.utcnow() - cached_at < timedelta(hours=24):
            return entry['cves']

    # Build search query
    query = service_name
    if version:
        query = f"{service_name} {version}"

    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    params = {
        'keywordSearch': query,
        'resultsPerPage': max_results,
    }

    try:
        # Respect NVD rate limit — 5 requests per 30 seconds without API key
        time.sleep(1)

        response = requests.get(url, params=params, timeout=10)

        if response.status_code != 200:
            print(
                f"[!] CVE API returned {response.status_code} for {service_name}")
            return []

        data = response.json()
        cve_list = []

        for item in data.get('vulnerabilities', []):
            cve = item.get('cve', {})
            cve_id = cve.get('id', 'Unknown')

            # Get description (English)
            descriptions = cve.get('descriptions', [])
            description = next(
                (d['value'] for d in descriptions if d.get('lang') == 'en'),
                'No description available'
            )

            # Get CVSS score and severity
            score = None
            severity = 'UNKNOWN'
            metrics = cve.get('metrics', {})

            # Try CVSSv3 first, then v2
            if 'cvssMetricV31' in metrics:
                cvss = metrics['cvssMetricV31'][0]['cvssData']
                score = cvss.get('baseScore')
                severity = cvss.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV30' in metrics:
                cvss = metrics['cvssMetricV30'][0]['cvssData']
                score = cvss.get('baseScore')
                severity = cvss.get('baseSeverity', 'UNKNOWN')
            elif 'cvssMetricV2' in metrics:
                cvss = metrics['cvssMetricV2'][0]['cvssData']
                score = cvss.get('baseScore')
                severity = 'HIGH' if score and score >= 7 else 'MEDIUM' if score and score >= 4 else 'LOW'

            cve_list.append({
                'id':          cve_id,
                'description': description[:300] + '...' if len(description) > 300 else description,
                'severity':    severity,
                'score':       score,
                'url':         f"https://nvd.nist.gov/vuln/detail/{cve_id}"
            })

        # Cache the result
        cache[cache_key] = {
            'cached_at': datetime.utcnow().isoformat(),
            'cves':      cve_list
        }
        save_cache(cache)

        print(f"[+] Found {len(cve_list)} CVEs for {service_name}")
        return cve_list

    except requests.exceptions.Timeout:
        print(f"[!] CVE lookup timed out for {service_name}")
        return []
    except Exception as e:
        print(f"[!] CVE lookup error for {service_name}: {e}")
        return []


def get_cves_for_scan(scan):
    """
    Look up CVEs for all services found in a scan.
    Returns a dict: { 'service_name': [cve, cve, ...] }
    """
    results = {}
    seen = set()  # avoid duplicate lookups

    for host in scan.hosts:
        for port in host.ports:
            service = port.service_name
            if not service or service in seen:
                continue
            seen.add(service)

            # Only look up risky services to save API calls
            if port.risk_level in ('critical', 'high', 'medium'):
                cves = lookup_cves(service, port.service_version)
                if cves:
                    results[service] = cves

    return results
