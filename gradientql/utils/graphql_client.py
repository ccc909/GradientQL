"""GraphQL HTTP transport client."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger("gradientql.graphql_client")

_client_cache: dict[str, "GraphQLClient"] = {}


def get_client(
    url: str,
    headers: dict[str, str] | None = None,
    csrf_config: dict[str, Any] | None = None,
    http: dict[str, Any] | None = None,
) -> "GraphQLClient":
    """Return a process-wide cached client for the URL.

    The cache is keyed on url alone: headers, csrf_config, and http are honored
    only when the client is first created and ignored on later cache hits.
    """
    if url not in _client_cache:
        _client_cache[url] = GraphQLClient(url, headers, csrf_config, http)
    return _client_cache[url]


def clear_client_cache() -> None:
    _client_cache.clear()


INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          name
          description
          type {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                        ofType {
                          kind
                          name
                        }
                      }
                    }
                  }
                }
              }
            }
          }
          defaultValue
        }
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        defaultValue
      }
      interfaces {
        kind
        name
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        kind
        name
      }
    }
    directives {
      name
      description
      locations
      args {
        name
        description
        type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                    ofType {
                      kind
                      name
                      ofType {
                        kind
                        name
                      }
                    }
                  }
                }
              }
            }
          }
        }
        defaultValue
      }
    }
  }
}
"""


_INTERESTING_HEADERS = frozenset({
    "server", "x-powered-by", "x-runtime", "x-request-id",
    "x-debug", "via", "x-magento-tags", "x-frame-options",
})


class GraphQLClient:
    """Stateful HTTP transport for one GraphQL endpoint over a reused session."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        csrf_config: dict[str, Any] | None = None,
        http: dict[str, Any] | None = None,
    ) -> None:
        self.url = url
        self.last_request: dict[str, Any] | None = None  # the most recent request, for copy-curl
        self.session = requests.Session()
        if headers:
            self.session.headers.update(headers)
        self.session.headers.setdefault("Content-Type", "application/json")
        self._session_initialized = False
        self._csrf_config = csrf_config or {}

        http = http or {}
        proxy = http.get("proxy")
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self.session.verify = http.get("verify_tls", True)
        self._timeout = http.get("timeout", 30)
        self._delay = float(http.get("delay", 0.0))
        adapter = HTTPAdapter(max_retries=http.get("retries", 2))
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _throttle(self) -> None:
        if self._delay > 0:
            time.sleep(self._delay)

    @property
    def session_headers(self) -> dict[str, str]:
        return dict(self.session.headers)

    @property
    def session_cookies(self) -> dict[str, str]:
        return {k: v for k, v in self.session.cookies.items()}

    def _get_base_url(self) -> str:
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def _fetch_csrf_token(self) -> str | None:
        """Fetch a CSRF token per csrf_config, or None if disabled or unavailable.

        Returns None when CSRF is not enabled, when the token cannot be located
        in the configured source (meta/cookie/header), or on any request error.
        """
        if not self._csrf_config.get("enabled", False):
            return None

        source = self._csrf_config.get("source", "meta")
        token_url = self._csrf_config.get("token_url") or self._get_base_url()
        
        logger.info("Fetching CSRF token from %s (source: %s)", token_url, source)
        
        try:
            self._throttle()
            resp = self.session.get(token_url, timeout=self._timeout)
            resp.raise_for_status()
            
            token = None
            
            if source == "meta":
                meta_name = self._csrf_config.get("meta_name", "csrf-token")
                patterns = [
                    rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']+)["\']',
                    rf'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']?{re.escape(meta_name)}["\']?',
                ]
                for pattern in patterns:
                    match = re.search(pattern, resp.text, re.IGNORECASE)
                    if match:
                        token = match.group(1)
                        break
                        
            elif source == "cookie":
                cookie_name = self._csrf_config.get("cookie_name", "csrf_token")
                token = self.session.cookies.get(cookie_name)
                
            elif source == "header":
                header_name = self._csrf_config.get("header_name", "X-CSRF-Token")
                token = resp.headers.get(header_name)
            
            if token:
                logger.info("CSRF token obtained successfully")
            else:
                logger.warning("Could not extract CSRF token from %s", source)
                
            return token
            
        except requests.exceptions.RequestException as exc:
            logger.warning("Failed to fetch CSRF token: %s", exc)
            return None

    def _init_session(self) -> None:
        """Prime the session once: set the CSRF header and capture auth state.

        Runs at most once per client; sends a warmup request and folds any
        returned cookies and auth headers back into the session for reuse.
        """
        if self._session_initialized:
            return

        csrf_token = self._fetch_csrf_token()
        if csrf_token:
            header_name = self._csrf_config.get("header_name", "X-CSRF-Token")
            self.session.headers[header_name] = csrf_token
            logger.info("Set CSRF header: %s", header_name)

        self._session_initialized = True
        init_success = False

        try:
            logger.info("Initializing session with %s", self.url)
            self._throttle()
            resp = self.session.post(
                self.url,
                json={"query": "{ __typename }"},
                timeout=self._timeout,
            )
            init_success = True

            if self.session.cookies:
                cookie_names = list(self.session.cookies.keys())
                logger.info("Session cookies captured: %s", cookie_names)

            auth_headers_to_capture = [
                "Authorization",
                "X-Auth-Token",
                "X-Session-Token",
                "X-CSRF-Token",
                "X-Access-Token",
            ]
            for header in auth_headers_to_capture:
                if header in resp.headers:
                    self.session.headers[header] = resp.headers[header]
                    logger.info("Captured auth header: %s", header)

        except requests.exceptions.RequestException as exc:
            logger.warning("Session initialization request failed: %s", exc)
            if not init_success:
                self._session_initialized = False

    def execute(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        extra_headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Send a query and return the response body enriched with probe metadata.

        A query whose text is a JSON array is sent verbatim as a batch. The
        returned dict always carries `_status_code`, `_response_time_ms`, and a
        filtered `_headers`; transport failures return that shape with a status
        of 0 rather than raising, and an empty reply to a batch adds
        `_batch_not_supported`.
        """
        self._init_session()

        payload: dict[str, Any] | list[dict[str, Any]]
        stripped = query.strip()
        is_batch = False
        if stripped.startswith("["):
            try:
                parsed_batch = json.loads(stripped)
                if isinstance(parsed_batch, list) and len(parsed_batch) > 0:
                    payload = parsed_batch
                    is_batch = True
            except (json.JSONDecodeError, ValueError):
                pass
        if not is_batch:
            payload = {"query": query}
            if variables:
                payload["variables"] = variables

        self._log_curl(payload)
        self.last_request = {"url": self.url, "payload": payload,
                             "headers": {**dict(self.session.headers), **(extra_headers or {})}}

        start_time = time.time()
        try:
            self._throttle()
            resp = self.session.post(
                self.url, json=payload, timeout=self._timeout,
                headers=extra_headers if extra_headers else None,
            )
        except requests.exceptions.RequestException as exc:
            elapsed = time.time() - start_time
            logger.error("HTTP request failed after %.2fs: %s", elapsed, exc)
            return {
                "data": None,
                "errors": [{"message": str(exc)}],
                "_status_code": 0,
                "_response_time_ms": int(elapsed * 1000),
            }

        elapsed = time.time() - start_time
        raw_text = resp.text
        
        if not raw_text or raw_text.strip() in ("", "{}", "[]"):
            logger.warning(f"Empty or minimal response: status={resp.status_code}, body='{raw_text[:200]}', content-type={resp.headers.get('content-type', 'unknown')}")
            if isinstance(payload, list) and len(payload) > 1:
                logger.warning(f"BATCH NOT SUPPORTED: Empty response to batch query with {len(payload)} operations")
                body = {
                    "_batch_not_supported": True,
                    "_batch_size": len(payload),
                    "data": None,
                    "errors": [{"message": "Batch queries not supported by this endpoint"}],
                }
                body["_status_code"] = resp.status_code
                body["_headers"] = {k: v for k, v in resp.headers.items() if k.lower() in _INTERESTING_HEADERS}
                body["_response_time_ms"] = int(elapsed * 1000)
                return body
        
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            body = {"data": None, "errors": [{"message": raw_text[:500]}]}

        if isinstance(body, list):
            body = {
                "_batch_responses": body,
                "data": None,
                "errors": None,
            }

        body["_status_code"] = resp.status_code
        body["_headers"] = {
            k: v for k, v in resp.headers.items()
            if k.lower() in _INTERESTING_HEADERS
        }
        body["_response_time_ms"] = int(elapsed * 1000)

        self._log_response(resp.status_code, elapsed, body)

        return body

    def execute_apq_probe(self, sha256_hash: str) -> dict[str, Any]:
        """Probe for Automatic Persisted Queries support with a bare hash.

        Sends only the persistedQuery hash (no query text) and sets
        `_apq_detected` True when the server replies PersistedQueryNotFound,
        which signals the APQ protocol is active.
        """
        self._init_session()
        payload = {
            "extensions": {
                "persistedQuery": {
                    "version": 1,
                    "sha256Hash": sha256_hash,
                }
            }
        }
        logger.info(">>> APQ PROBE: POST %s (hash=%s...)", self.url, sha256_hash[:16])
        start_time = time.time()
        try:
            self._throttle()
            resp = self.session.post(self.url, json=payload, timeout=self._timeout)
        except requests.exceptions.RequestException as exc:
            elapsed = time.time() - start_time
            return {
                "data": None,
                "errors": [{"message": str(exc)}],
                "_status_code": 0,
                "_response_time_ms": int(elapsed * 1000),
            }
        elapsed = time.time() - start_time
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            body = {"data": None, "errors": [{"message": resp.text[:500]}]}
        if isinstance(body, list):
            body = {"_batch_responses": body, "data": None, "errors": None}
        body["_status_code"] = resp.status_code
        body["_response_time_ms"] = int(elapsed * 1000)

        raw_text = json.dumps(body).lower()
        apq_detected = "persistedquerynotfound" in raw_text
        body["_apq_detected"] = apq_detected
        if apq_detected:
            logger.info("APQ DETECTED: Server supports Automatic Persisted Queries!")
        else:
            logger.info("APQ not detected (response: %s)", resp.text[:200])
        return body

    def _log_curl(self, payload: dict[str, Any] | list[dict[str, Any]]) -> None:
        if isinstance(payload, list):
            logger.info(">>> POST %s (BATCH: %d queries)", self.url, len(payload))
            for i, item in enumerate(payload[:3]):
                query = item.get("query", "") if isinstance(item, dict) else str(item)
                query_preview = query.replace("\n", " ").replace("  ", " ")[:160]
                if len(query) > 160:
                    query_preview += "..."
                logger.info("    Query[%d]: %s", i, query_preview)
            if len(payload) > 3:
                logger.info("    ... and %d more", len(payload) - 3)
            return

        query = payload.get("query", "") if isinstance(payload, dict) else str(payload)
        query_preview = query.replace("\n", " ").replace("  ", " ")[:200]
        if len(query) > 200:
            query_preview += "..."

        logger.info(">>> POST %s", self.url)
        logger.info("    Query: %s", query_preview)

        if len(query) < 1000:
            logger.debug("    Full query: %s", query)
        if payload.get("variables"):
            vars_str = json.dumps(payload["variables"], default=str)
            if len(vars_str) > 200:
                vars_str = vars_str[:200] + "..."
            logger.info("    Variables: %s", vars_str)

    def _log_response(self, status: int, elapsed: float, body: dict[str, Any]) -> None:
        has_data = body.get("data") is not None and body.get("data") != {}
        has_errors = bool(body.get("errors"))

        data_preview = ""
        if has_data:
            data_str = json.dumps(body["data"], default=str)
            data_preview = data_str[:300] + "..." if len(data_str) > 300 else data_str

        error_preview = ""
        if has_errors:
            first_error = body["errors"][0] if body["errors"] else {}
            if isinstance(first_error, dict):
                error_preview = first_error.get("message", str(first_error))[:200]
            else:
                error_preview = str(first_error)[:200]

        if status == 200 and has_data and not has_errors:
            indicator = "OK"
        elif status == 200 and has_errors:
            indicator = "ERR"
        elif status >= 400:
            indicator = f"HTTP {status}"
        else:
            indicator = str(status)

        logger.info("<<< %s (%.0fms)", indicator, elapsed * 1000)
        if data_preview:
            logger.info("    Data: %s", data_preview)
        if error_preview:
            logger.info("    Error: %s", error_preview)

    def introspect(self) -> dict[str, Any]:
        logger.info("Running introspection on %s", self.url)
        result = self.execute(INTROSPECTION_QUERY)
        if result.get("errors"):
            logger.warning("Introspection returned errors: %s", result["errors"])
        return result
