"""
nvd_client.py — National Vulnerability Database API Client

This module talks to the NVD (National Vulnerability Database),
run by the US Government's NIST (National Institute of Standards & Technology).

Think of NVD like a massive, constantly updated encyclopedia of
every known security flaw ever discovered — over 200,000 entries.

Each entry is called a CVE (Common Vulnerabilities and Exposures).
Each CVE has:
 - A unique ID: CVE-2023-44487
 - A description: What the vulnerability is
 - A CVSS score: How dangerous it is (0.0 to 10.0)
 - Affected CPE: Which software versions are affected

The free API lets us ask:
 "Does Apache 2.4.51 have any known vulnerabilities?"
 "What CVEs affect OpenSSH 8.4?"
 "Give me all critical CVEs from the last 30 days"

NVD API documentation: https://nvd.nist.gov/developers/vulnerabilities
No API key required for basic use (rate limited to 5 requests/30 seconds)
With a free API key: 50 requests/30 seconds
"""

import requests
import time
import json
import os
from datetime import datetime, timedelta


# ── NVD API Configuration ────────────────────────────────────────
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_TIMEOUT = 15 # Seconds to wait for NVD to respond
RATE_LIMIT_WAIT = 6 # Seconds between requests (free tier: 5 req/30s)
CACHE_DIR = "config/nvd_cache"
CACHE_HOURS = 24 # Cache results for 24 hours to avoid hammering the API


class NVDClient:
 """
 A client for the NVD (National Vulnerability Database) REST API.
 
 Features:
 - Queries NVD for CVEs matching a product/version
 - Caches results to disk so we don't re-query the same thing
 - Respects rate limits so we don't get blocked
 - Gracefully handles when NVD is unavailable (offline mode)
 """

 def __init__(self, logger, api_key: str = None):
 """
 Set up the NVD client.
 
 Args:
 logger: The toolkit logger
 api_key: Optional free NVD API key (nvd.nist.gov/developers/request-an-api-key)
 Without a key: 5 requests per 30 seconds
 With a key: 50 requests per 30 seconds
 """
 self.logger = logger
 self.api_key = api_key
 self.last_call = 0 # Timestamp of last API call (for rate limiting)

 # Create cache directory
 os.makedirs(CACHE_DIR, exist_ok=True)

 self.logger.info("NVD Client initialized")
 if api_key:
 self.logger.info(" ✅ API key provided — higher rate limits active")
 else:
 self.logger.info(" ℹ️ No API key — using free tier (5 req/30s)")
 self.logger.info(" Get a free key at: nvd.nist.gov/developers/request-an-api-key")

 # ══════════════════════════════════════════════════════════════
 # PRIMARY METHODS — what the Inspector calls
 # ══════════════════════════════════════════════════════════════

 def search_by_keyword(self, keyword: str, max_results: int = 10) -> list:
 """
 Search for CVEs matching a keyword (like "Apache 2.4.51").
 
 This is the main method the Inspector uses.
 
 Args:
 keyword: Product name and/or version (e.g. "OpenSSH 8.4")
 max_results: How many CVEs to return
 
 Returns:
 List of CVE dictionaries, each containing:
 - id: "CVE-2023-12345"
 - description: Plain English description of the flaw
 - severity: "CRITICAL" / "HIGH" / "MEDIUM" / "LOW"
 - cvss_score: 0.0 to 10.0 (10 = most dangerous)
 - published: Date the CVE was published
 - url: Link to full NVD entry
 """
 self.logger.info(f" Querying NVD for: '{keyword}'")

 # Check cache first — no need to call the API if we already have results
 cached = self._load_cache(keyword)
 if cached is not None:
 self.logger.info(f" Using cached results ({len(cached)} CVEs)")
 return cached[:max_results]

 # Make the API call
 try:
 results = self._query_nvd(keyword, max_results)
 self._save_cache(keyword, results)
 self.logger.info(f" ✅ Found {len(results)} CVE(s) from NVD")
 return results

 except requests.exceptions.ConnectionError:
 self.logger.warning(f" Cannot reach NVD API — no internet connection")
 return []
 except requests.exceptions.Timeout:
 self.logger.warning(f" NVD API timed out — will retry later")
 return []
 except Exception as e:
 self.logger.error(f" NVD query failed: {str(e)}")
 return []

 def get_cve_by_id(self, cve_id: str) -> dict | None:
 """
 Fetch full details for a specific CVE by its ID.
 
 Args:
 cve_id: Like "CVE-2023-44487"
 
 Returns:
 CVE dictionary or None if not found
 """
 cache_key = f"cve_{cve_id}"
 cached = self._load_cache(cache_key)
 if cached:
 return cached[0] if cached else None

 try:
 self._rate_limit()
 params = {"cveId": cve_id}
 if self.api_key:
 params["apiKey"] = self.api_key

 response = requests.get(NVD_BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
 response.raise_for_status()

 data = response.json()
 vulns = data.get("vulnerabilities", [])
 if not vulns:
 return None

 result = [self._parse_cve(vulns[0])]
 self._save_cache(cache_key, result)
 return result[0]

 except Exception as e:
 self.logger.error(f"Could not fetch {cve_id}: {e}")
 return None

 def get_recent_critical_cves(self, days: int = 30, max_results: int = 20) -> list:
 """
 Get the most recent CRITICAL severity CVEs.
 
 Useful for staying current — "what new critical vulnerabilities
 have been disclosed in the last 30 days?"
 
 Args:
 days: How many days back to look
 max_results: Maximum CVEs to return
 """
 cache_key = f"recent_critical_{days}d"
 cached = self._load_cache(cache_key, max_age_hours=6) # Cache 6hrs for recency
 if cached:
 return cached[:max_results]

 try:
 end_date = datetime.utcnow()
 start_date = end_date - timedelta(days=days)

 self._rate_limit()
 params = {
 "cvssV3Severity": "CRITICAL",
 "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
 "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
 "resultsPerPage": max_results
 }
 if self.api_key:
 params["apiKey"] = self.api_key

 response = requests.get(NVD_BASE_URL, params=params, timeout=REQUEST_TIMEOUT)
 response.raise_for_status()

 data = response.json()
 cves = [self._parse_cve(v) for v in data.get("vulnerabilities", [])]
 cves.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)

 self._save_cache(cache_key, cves, max_age_hours=6)
 self.logger.info(f"Retrieved {len(cves)} recent CRITICAL CVEs (last {days} days)")
 return cves

 except Exception as e:
 self.logger.error(f"Could not fetch recent CVEs: {e}")
 return []

 # ══════════════════════════════════════════════════════════════
 # PRIVATE METHODS — internal mechanics
 # ══════════════════════════════════════════════════════════════

 def _query_nvd(self, keyword: str, max_results: int) -> list:
 """
 Makes the actual HTTP request to the NVD API.
 
 HTTP request = like your browser loading a webpage, but
 we're asking for data (JSON) instead of a web page.
 """
 self._rate_limit()

 params = {
 "keywordSearch": keyword,
 "resultsPerPage": min(max_results, 20), # NVD max is 2000 but we keep it small
 }
 if self.api_key:
 params["apiKey"] = self.api_key

 self.logger.debug(f"NVD API request: {NVD_BASE_URL}?keywordSearch={keyword}")

 response = requests.get(
 NVD_BASE_URL,
 params=params,
 timeout=REQUEST_TIMEOUT,
 headers={"User-Agent": "Dayea/1.0 Security Research"}
 )

 # raise_for_status() throws an error if we get a 4xx or 5xx response
 # 200 = OK, 404 = Not Found, 429 = Rate Limited, 500 = Server Error
 response.raise_for_status()

 data = response.json()
 vulnerabilities = data.get("vulnerabilities", [])

 # Parse each raw CVE into our clean, simple format
 parsed = [self._parse_cve(v) for v in vulnerabilities]

 # Sort by CVSS score — highest severity first
 parsed.sort(key=lambda x: x.get('cvss_score', 0), reverse=True)

 return parsed

 def _parse_cve(self, raw_vuln: dict) -> dict:
 """
 Converts the raw NVD API response into a clean, simple dictionary.
 
 The NVD API response is deeply nested and complex.
 This function extracts just what we need.
 
 Raw NVD format (messy, deeply nested):
 {"cve": {"id": "CVE-...", "descriptions": [...], "metrics": {...}}}
 
 Our clean format:
 {"id": "CVE-...", "description": "...", "severity": "HIGH", "cvss_score": 8.1}
 """
 try:
 cve = raw_vuln.get("cve", {})

 # Get the CVE ID
 cve_id = cve.get("id", "Unknown")

 # Get English description
 # NVD provides descriptions in multiple languages — we want English
 descriptions = cve.get("descriptions", [])
 description = next(
 (d["value"] for d in descriptions if d.get("lang") == "en"),
 "No description available"
 )

 # Get CVSS score and severity
 # CVSS = Common Vulnerability Scoring System
 # It's a number from 0.0 to 10.0 measuring danger level
 cvss_score = 0.0
 severity = "UNKNOWN"

 metrics = cve.get("metrics", {})

 # Try CVSS v3.1 first (most modern), fall back to v3.0, then v2
 for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
 if metric_key in metrics and metrics[metric_key]:
 metric = metrics[metric_key][0]
 cvss_data = metric.get("cvssData", {})
 cvss_score = cvss_data.get("baseScore", 0.0)
 severity = metric.get("baseSeverity",
 cvss_data.get("baseSeverity", "UNKNOWN"))
 break

 # Map CVSS score to severity if not set
 if severity == "UNKNOWN" and cvss_score > 0:
 if cvss_score >= 9.0: severity = "CRITICAL"
 elif cvss_score >= 7.0: severity = "HIGH"
 elif cvss_score >= 4.0: severity = "MEDIUM"
 else: severity = "LOW"

 # Get published date
 published = cve.get("published", "")[:10] # Just the date part

 return {
 "id": cve_id,
 "description": description[:500], # Truncate very long descriptions
 "severity": severity.upper(),
 "cvss_score": cvss_score,
 "published": published,
 "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
 "source": "NVD"
 }

 except Exception as e:
 # If parsing fails for any reason, return a minimal entry
 return {
 "id": raw_vuln.get("cve", {}).get("id", "PARSE_ERROR"),
 "description": f"Could not parse CVE details: {e}",
 "severity": "UNKNOWN",
 "cvss_score": 0.0,
 "published": "",
 "url": "",
 "source": "NVD"
 }

 def _rate_limit(self):
 """
 Pauses between API calls to respect NVD's rate limits.
 
 Without an API key: 5 requests per 30 seconds = 6 second gap
 With an API key: 50 requests per 30 seconds = 0.6 second gap
 
 If we go too fast, NVD will temporarily block us (HTTP 429).
 """
 wait_time = 0.6 if self.api_key else RATE_LIMIT_WAIT
 elapsed = time.time() - self.last_call

 if elapsed < wait_time:
 sleep_for = wait_time - elapsed
 self.logger.debug(f"Rate limiting — waiting {sleep_for:.1f}s")
 time.sleep(sleep_for)

 self.last_call = time.time()

 def _cache_path(self, key: str) -> str:
 """Returns the file path for a cached result"""
 # Clean the key to make it a safe filename
 safe_key = "".join(c if c.isalnum() or c in '-_' else '_' for c in key)
 return os.path.join(CACHE_DIR, f"{safe_key}.json")

 def _load_cache(self, key: str, max_age_hours: int = CACHE_HOURS) -> list | None:
 """
 Loads cached results from disk if they're still fresh.
 
 "Fresh" means the cache file is less than max_age_hours old.
 Old cache = we re-query the API for updated info.
 """
 path = self._cache_path(key)
 if not os.path.exists(path):
 return None

 try:
 with open(path, 'r') as f:
 cache_data = json.load(f)

 # Check if cache has expired
 cached_time = datetime.fromisoformat(cache_data.get("timestamp", "2000-01-01"))
 age_hours = (datetime.utcnow() - cached_time).total_seconds() / 3600

 if age_hours > max_age_hours:
 self.logger.debug(f"Cache expired for '{key}' ({age_hours:.1f}h old)")
 return None

 return cache_data.get("results", [])

 except Exception:
 return None

 def _save_cache(self, key: str, results: list, max_age_hours: int = CACHE_HOURS):
 """Saves results to disk cache for future use"""
 path = self._cache_path(key)
 try:
 with open(path, 'w') as f:
 json.dump({
 "timestamp": datetime.utcnow().isoformat(),
 "key": key,
 "results": results
 }, f, indent=2)
 except Exception as e:
 self.logger.debug(f"Could not save cache for '{key}': {e}")
