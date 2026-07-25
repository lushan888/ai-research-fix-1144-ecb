# Fix: CL.TE HTTP Request Smuggling → Cache Poisoning

## Vulnerability
Front-end nginx uses Content-Length while back-end uses Transfer-Encoding: chunked. Attackers craft ambiguous requests that cause front-end and back-end to disagree on request boundaries, poisoning the cache for subsequent users.

## Attack Vector
```
POST / HTTP/1.1
Content-Length: 44
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
```

## Fix Implementation
1. Reject requests with both Content-Length and Transfer-Encoding headers
2. Validate Transfer-Encoding header format (only "chunked" is accepted)
3. Normalize Content-Length header parsing
4. WSGI middleware to inspect all incoming requests
5. Nginx configuration to reject ambiguous requests at the proxy level

## Files Changed
- `FIXES/cl_te_http_smuggling_1472.py` — Python fix + middleware + nginx config

## References
- CWE-444: Inconsistent Interpretation of HTTP Requests
- CWE-525: Web Cache Poisoning