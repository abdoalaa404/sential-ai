/**
 * SENTIAL AI - BENCHMARK VULNERABLE TARGET APPLICATION
 * ----------------------------------------------------
 * Port: 5000 (http://localhost:5000)
 * Purpose: Safe, isolated, local benchmark web server for testing and evaluating Sential AI scanner.
 * Total Documented Vulnerabilities: 28
 *
 * OWASP Top 10 Coverage:
 * A01: Broken Access Control (IDOR, Admin Exposure, Open Redirect, CSRF)
 * A02: Cryptographic Failures (Sensitive Data Exposure, Missing Cookies Flags)
 * A03: Injection (SQL Injection, Command Injection, Reflected XSS)
 * A04: Insecure Design (Lack of Rate Limiting)
 * A05: Security Misconfiguration (Missing Headers, CORS, Debug Endpoints, Source Maps)
 * A06: Vulnerable & Outdated Components (Server Banner Leaks)
 * A07: Identification & Auth Failures (SQL Auth Bypass, Unauthenticated Admin)
 * A08: Software & Data Integrity Failures
 * A09: Security Logging & Monitoring Failures
 * A10: Server-Side Request Forgery (SSRF)
 */

const http = require('http');
const url = require('url');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 5000;

// Catalog of the 28 intentional vulnerabilities
const VULNERABILITY_CATALOG = [
  { id: 'VULN-01', title: 'Missing Content-Security-Policy (CSP) Header', severity: 'MEDIUM', cwe: 'CWE-693', category: 'Security Misconfiguration', endpoint: '/' },
  { id: 'VULN-02', title: 'Missing Anti-Clickjacking Header (X-Frame-Options)', severity: 'MEDIUM', cwe: 'CWE-1021', category: 'Security Misconfiguration', endpoint: '/' },
  { id: 'VULN-03', title: 'Missing X-Content-Type-Options (MIME-Sniffing)', severity: 'LOW', cwe: 'CWE-16', category: 'Security Misconfiguration', endpoint: '/' },
  { id: 'VULN-04', title: 'Missing Referrer-Policy Header', severity: 'LOW', cwe: 'CWE-200', category: 'Information Disclosure', endpoint: '/' },
  { id: 'VULN-05', title: 'Missing Permissions-Policy / Feature-Policy', severity: 'LOW', cwe: 'CWE-16', category: 'Security Misconfiguration', endpoint: '/' },
  { id: 'VULN-06', title: 'Server & Tech Banner Disclosure (Server, X-Powered-By)', severity: 'LOW', cwe: 'CWE-200', category: 'Information Disclosure', endpoint: 'All Responses' },
  { id: 'VULN-07', title: 'Session Cookie Missing HttpOnly Flag', severity: 'LOW', cwe: 'CWE-1004', category: 'Session Management', endpoint: '/' },
  { id: 'VULN-08', title: 'Session Cookie Missing SameSite Attribute', severity: 'LOW', cwe: 'CWE-1275', category: 'Session Management', endpoint: '/' },
  { id: 'VULN-09', title: 'Permissive CORS: Arbitrary Origin Reflected with Credentials', severity: 'HIGH', cwe: 'CWE-942', category: 'Cross-Origin Security', endpoint: '/' },
  { id: 'VULN-10', title: 'Publicly Accessible Environment File (.env)', severity: 'CRITICAL', cwe: 'CWE-200 / CWE-552', category: 'Sensitive Data Exposure', endpoint: '/.env' },
  { id: 'VULN-11', title: 'Exposed Git Repository Metadata (.git/HEAD & .git/config)', severity: 'HIGH', cwe: 'CWE-538', category: 'Source Code Disclosure', endpoint: '/.git/HEAD' },
  { id: 'VULN-12', title: 'Publicly Accessible SQL Database Backup (backup.sql)', severity: 'CRITICAL', cwe: 'CWE-200', category: 'Sensitive Data Exposure', endpoint: '/backup.sql' },
  { id: 'VULN-13', title: 'Diagnostic PHP Info Script Exposed (phpinfo.php)', severity: 'HIGH', cwe: 'CWE-200', category: 'Information Disclosure', endpoint: '/phpinfo.php' },
  { id: 'VULN-14', title: 'Unauthenticated Administrative Console (/admin)', severity: 'HIGH', cwe: 'CWE-285', category: 'Broken Access Control', endpoint: '/admin' },
  { id: 'VULN-15', title: 'Reflected Cross-Site Scripting (Reflected XSS)', severity: 'HIGH', cwe: 'CWE-79', category: 'Cross-Site Scripting', endpoint: '/search?q=... and /?q=...' },
  { id: 'VULN-16', title: 'Insecure Direct Object Reference (IDOR - User Profile)', severity: 'HIGH', cwe: 'CWE-639', category: 'Broken Access Control', endpoint: '/api/users/:id/profile' },
  { id: 'VULN-17', title: 'Insecure Direct Object Reference (IDOR - Orders & Invoices)', severity: 'HIGH', cwe: 'CWE-639', category: 'Broken Access Control', endpoint: '/api/orders/:id' },
  { id: 'VULN-18', title: 'Path / Directory Traversal (Arbitrary File Read)', severity: 'HIGH', cwe: 'CWE-22', category: 'Path Traversal', endpoint: '/api/download?file=...' },
  { id: 'VULN-19', title: 'Remote OS Command Injection in System Shell Execution', severity: 'CRITICAL', cwe: 'CWE-78', category: 'Command Injection', endpoint: '/api/tools/ping?host=...' },
  { id: 'VULN-20', title: 'SQL Injection: Data Extraction in Search Query', severity: 'CRITICAL', cwe: 'CWE-89', category: 'SQL Injection', endpoint: '/api/products/search?q=...' },
  { id: 'VULN-21', title: 'SQL Injection: Authentication Bypass via Login', severity: 'CRITICAL', cwe: 'CWE-89', category: 'SQL Injection', endpoint: '/api/auth/login' },
  { id: 'VULN-22', title: 'Open URL Redirection via Unvalidated Parameter', severity: 'MEDIUM', cwe: 'CWE-601', category: 'Broken Access Control', endpoint: '/redirect?url=...' },
  { id: 'VULN-23', title: 'Sensitive System Diagnostic Information Disclosure', severity: 'MEDIUM', cwe: 'CWE-200', category: 'Information Disclosure', endpoint: '/api/debug/system-info' },
  { id: 'VULN-24', title: 'Server-Side Request Forgery (SSRF - Webhook Tester)', severity: 'HIGH', cwe: 'CWE-918', category: 'SSRF', endpoint: '/api/webhook/test' },
  { id: 'VULN-25', title: 'Broken Authentication: Missing Rate Limiting on Login', severity: 'MEDIUM', cwe: 'CWE-307', category: 'Authentication Failure', endpoint: '/api/auth/login' },
  { id: 'VULN-26', title: 'Cross-Site Request Forgery (CSRF - Missing Anti-CSRF Token)', severity: 'MEDIUM', cwe: 'CWE-352', category: 'Broken Access Control', endpoint: '/api/user/change-email' },
  { id: 'VULN-27', title: 'Publicly Accessible Video Stream Manifest (.m3u8)', severity: 'MEDIUM', cwe: 'CWE-200', category: 'Information Disclosure', endpoint: '/stream.m3u8' },
  { id: 'VULN-28', title: 'Exposed Production JavaScript Source Map (/main.js.map)', severity: 'HIGH', cwe: 'CWE-540', category: 'Source Code Disclosure', endpoint: '/main.js.map' },
];

// In-memory mock database
const MOCK_USERS = [
  { id: 1, username: 'admin', email: 'admin@target.local', fullName: 'System Administrator', role: 'administrator', balance: 50000 },
  { id: 2, username: 'alice', email: 'alice.johnson@target.local', fullName: 'Alice Johnson', role: 'user', balance: 1420 },
  { id: 3, username: 'bob', email: 'bob.smith@target.local', fullName: 'Bob Smith', role: 'user', balance: 890 },
];

const MOCK_ORDERS = [
  { id: 1, userId: 1, total: 1540.00, items: ['Server Hardware', 'Enterprise License'], status: 'CONFIRMED' },
  { id: 2, userId: 2, total: 249.99, items: ['Security Key YubiKey', 'USB Hub'], status: 'SHIPPED' },
  { id: 3, userId: 3, total: 79.50, items: ['Technical Cybersecurity Book'], status: 'DELIVERED' },
];

const MOCK_PRODUCTS = [
  { id: 101, name: 'Sential Quantum Shield Appliance', category: 'Hardware', price: 2999 },
  { id: 102, name: 'Cyber Warfare Defense Toolkit', category: 'Software', price: 899 },
  { id: 103, name: 'Enterprise Vulnerability Scanner License', category: 'Cloud', price: 4500 },
  { id: 104, name: 'Zero-Day Intrusion Prevention Module', category: 'Security', price: 1200 },
];

// Helper to parse JSON body
function parseJsonBody(req) {
  return new Promise((resolve) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      try {
        resolve(JSON.parse(data || '{}'));
      } catch {
        resolve({});
      }
    });
  });
}

const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const query = parsed.query;
  const origin = req.headers['origin'];

  // 1. INTENTIONAL VULNERABILITY: Technology Banner Disclosure (VULN-06)
  res.setHeader('Server', 'Apache/2.4.41 (Ubuntu)');
  res.setHeader('X-Powered-By', 'Express/4.18.2');

  // 2. INTENTIONAL VULNERABILITY: Insecure Session Cookie (VULN-07, VULN-08)
  // Missing HttpOnly and SameSite flags deliberately!
  res.setHeader('Set-Cookie', 'session_id=sential_target_sess_894172bc; Path=/');

  // 3. INTENTIONAL VULNERABILITY: Permissive CORS Reflection (VULN-09)
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  }

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // 4. ROUTE: GET /.env & /.env.local (VULN-10)
  if (pathname === '/.env' || pathname === '/.env.local') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`# Production Environment Configuration File
NODE_ENV=production
PORT=5000
DATABASE_URL="postgresql://db_master_user:Sup3rS3cretP@ssw0rd!@10.0.4.15:5432/production_db"
DB_HOST=10.0.4.15
DB_USER=db_master_user
DB_PASSWORD=Sup3rS3cretP@ssw0rd!
JWT_SECRET=c2VudGlhbC1haS1zdXBlci1zZWNyZXQtand0LWtleS0yMDI2
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_SECRET_KEY=sk_test_51MzBenchmarkStripeKeyDummySample992831
`);
    return;
  }

  // 5. ROUTE: GET /.env.backup (VULN-10 / Backup Disclosure)
  if (pathname === '/.env.backup') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`JWT_SECRET=supersecret123\nDB_FILE=dev.db\nINTERNAL_API_KEY=key_test_9988\nDATABASE_URL=postgres://admin:pass@localhost:5432/db`);
    return;
  }

  // 6. ROUTE: GET /.git/HEAD & /.git/config (VULN-11)
  if (pathname === '/.git/HEAD') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ref: refs/heads/main\n');
    return;
  }
  if (pathname === '/.git/config') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
\tlogallrefupdates = true
[remote "origin"]
\turl = https://github.com/benchmark-internal/target-webapp.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
\tremote = origin
\tmerge = refs/heads/main
`);
    return;
  }

  // 7. ROUTE: GET /backup.sql (VULN-12)
  if (pathname === '/backup.sql') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(`-- Production Database Dump
-- Host: localhost    Database: benchmark_db
-- Server version: PostgreSQL 14.8

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) NOT NULL,
    ssn VARCHAR(20) NOT NULL,
    credit_card VARCHAR(30)
);

INSERT INTO users (id, username, password_hash, email, ssn, credit_card) VALUES
(1, 'superadmin', '$2a$12$K8j7y6t5r4e3w2q1p0o9u8y7t6r5e4w3q2', 'admin@benchmark.org', '123-45-6789', '4532-7589-3214-9988'),
(2, 'finance_lead', '$2a$12$L9k8j7h6g5f4d3s2a1z0m9n8b7v6c5x4z', 'finance@benchmark.org', '987-65-4321', '4111-1111-1111-1111');
`);
    return;
  }

  // 8. ROUTE: GET /phpinfo.php (VULN-13)
  if (pathname === '/phpinfo.php') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><title>PHP 7.4.3 - phpinfo()</title></head>
<body>
<h1>PHP Version 7.4.3</h1>
<p>System: Linux ubuntu-server-benchmark 5.4.0-42-generic #46-Ubuntu SMP</p>
<p>Loaded Configuration File: /etc/php/7.4/apache2/php.ini</p>
<table border="1">
<tr><td>SERVER["SERVER_SOFTWARE"]</td><td>Apache/2.4.41 (Ubuntu)</td></tr>
<tr><td>SERVER["DOCUMENT_ROOT"]</td><td>/var/www/html</td></tr>
</table>
</body></html>`);
    return;
  }

  // 9. ROUTE: GET /admin (VULN-14)
  if (pathname === '/admin') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><head><title>Admin Dashboard Management</title></head>
<body style="font-family:sans-serif;background:#0f172a;color:#f8fafc;padding:2rem;">
  <h2>Administrative Management Panel</h2>
  <div style="background:#1e293b;padding:1.5rem;border-radius:8px;border:1px solid #334155;">
    <h3>Admin Control Center - Active Session</h3>
    <p>Status: Authenticated as System Superadmin (Unprotected Direct Portal)</p>
    <ul>
      <li>User Management &amp; DB Records</li>
      <li>System Logs and Audit Trails</li>
      <li>Security Configuration Keys</li>
    </ul>
  </div>
</body></html>`);
    return;
  }

  // 10. ROUTE: GET /main.js.map (VULN-28)
  if (pathname === '/main.js.map') {
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(JSON.stringify({
      version: 3,
      file: "main.js",
      sources: ["src/app.ts", "src/auth.ts"],
      sourcesContent: [
        "export const API_KEY = 'sk_live_internal_secret_99482';\nfunction connect() { console.log('Connected'); }",
        "export function login(user, pass) { return checkCredentials(user, pass); }"
      ],
      mappings: "AAAA;ACAA"
    }));
    return;
  }

  // 11. ROUTE: GET /stream.m3u8 (VULN-27)
  if (pathname === '/stream.m3u8') {
    res.writeHead(200, { 'Content-Type': 'application/vnd.apple.mpegurl; charset=utf-8' });
    res.end(`#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:10
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
segment0.ts
#EXTINF:10.0,
segment1.ts
#EXT-X-ENDLIST
`);
    return;
  }

  // 12. ROUTE: GET /server-status (Server Status Disclosure)
  if (pathname === '/server-status') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html><html><body><h1>Apache Server Status for localhost</h1><p>Server Version: Apache/2.4.41 (Ubuntu)</p><p>Total requests: 1420 - Active workers: 3</p></body></html>`);
    return;
  }

  // 13. ROUTE: GET /redirect (VULN-22: Open URL Redirection)
  if (pathname === '/redirect') {
    const targetUrl = query.url || 'https://sentinel-security-audit.com';
    res.writeHead(302, {
      'Location': targetUrl,
      'Content-Type': 'text/html'
    });
    res.end(`<p>Redirecting to <a href="${targetUrl}">${targetUrl}</a>...</p>`);
    return;
  }

  // 14. ROUTE: GET /api/users/:id/profile (VULN-16: IDOR User Profile)
  const userMatch = pathname.match(/^\/api\/users\/([0-9]+)\/profile$/);
  if (userMatch) {
    const uid = parseInt(userMatch[1], 10);
    const user = MOCK_USERS.find(u => u.id === uid) || {
      id: uid,
      username: `user_${uid}`,
      email: `user_${uid}@benchmark.local`,
      fullName: `Benchmark Subject #${uid}`,
      role: uid === 1 ? 'administrator' : 'user',
      balance: uid * 500
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(user));
    return;
  }

  // 15. ROUTE: GET /api/orders/:id (VULN-17: IDOR Orders)
  const orderMatch = pathname.match(/^\/api\/orders\/([0-9]+)$/);
  if (orderMatch) {
    const oid = parseInt(orderMatch[1], 10);
    const order = MOCK_ORDERS.find(o => o.id === oid) || {
      id: oid,
      userId: oid,
      total: oid * 125.50,
      items: [`Order Item A #${oid}`, `Order Item B #${oid}`],
      status: 'CONFIRMED'
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(order));
    return;
  }

  // 16. ROUTE: GET /api/download (VULN-18: Path / Directory Traversal)
  if (pathname === '/api/download') {
    const fileParam = query.file || '';
    if (fileParam.includes('package.json')) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        name: "sential-benchmark-vulnerable-app",
        version: "1.0.0",
        description: "Intentional Vulnerability Benchmark Target for Sential AI Scanner",
        main: "server.js",
        dependencies: {
          "express": "^4.18.2",
          "sqlite3": "^5.1.6"
        }
      }, null, 2));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`File contents for ${fileParam}`);
    return;
  }

  // 17. ROUTE: GET /api/tools/ping (VULN-19: Command Injection)
  if (pathname === '/api/tools/ping') {
    const host = query.host || '127.0.0.1';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: "success",
      command: `ping -c 1 ${host}`,
      host: host,
      output: `PING ${host} (${host}) 56(84) bytes of data.\n64 bytes from ${host}: icmp_seq=1 ttl=64 time=0.042 ms\n--- ${host} ping statistics ---\n1 packets transmitted, 1 received, 0% packet loss`
    }));
    return;
  }

  // 18. ROUTE: GET /api/products/search (VULN-20: SQL Injection in Search)
  if (pathname === '/api/products/search') {
    const q = (query.q || '').toString();
    // Vulnerable SQL interpolation simulation
    if (q.includes("'") || q.includes("OR") || q.includes("1=1") || q.includes("--")) {
      // Returns all records when boolean injection happens
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(MOCK_PRODUCTS));
      return;
    }
    const filtered = MOCK_PRODUCTS.filter(p => p.name.toLowerCase().includes(q.toLowerCase()));
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(filtered));
    return;
  }

  // 19. ROUTE: POST /api/auth/login (VULN-21: SQL Auth Bypass & VULN-25: No Rate Limit)
  if (pathname === '/api/auth/login' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    const username = body.username || '';
    const password = body.password || '';

    // Check boolean injection bypass
    if (username.includes("'") && (username.includes("OR") || username.includes("1=1") || username.includes("--"))) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        message: "Authentication successful via raw SQL query execution.",
        user: {
          id: 1,
          username: "admin",
          role: "administrator",
          token: "benchmark_bearer_token_xyz9982"
        }
      }));
      return;
    }

    // Normal invalid auth - NOTICE: Never returns 429 (No Rate Limiting)
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: false,
      error: "Invalid credentials.",
      attemptUser: username
    }));
    return;
  }

  // 20. ROUTE: GET /api/debug/system-info (VULN-23: Sensitive Debug Info)
  if (pathname === '/api/debug/system-info') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      node_version: process.version,
      platform: process.platform,
      arch: process.arch,
      cwd: process.cwd(),
      pid: process.pid,
      uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      environment: "STAGING_BENCHMARK_DEMO",
      database_driver: "sqlite3/internal",
      build_timestamp: "2026-10-25T18:00:00Z"
    }));
    return;
  }

  // 21. ROUTE: POST /api/webhook/test (VULN-24: Server-Side Request Forgery)
  if (pathname === '/api/webhook/test' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    const targetUrl = body.url || 'http://127.0.0.1:5000/api/debug/system-info';
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: "success",
      message: "Webhook probe executed successfully against internal endpoint.",
      targetUrl: targetUrl,
      preview: {
        http_code: 200,
        content_type: "application/json",
        body_snippet: '{"node_version":"v24.21.0","cwd":"c:\\Users\\VR STORE\\Graduation-Project"}'
      }
    }));
    return;
  }

  // 22. ROUTE: POST /api/user/change-email (VULN-26: CSRF Missing Token)
  if (pathname === '/api/user/change-email' && req.method === 'POST') {
    const body = await parseJsonBody(req);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      status: "success",
      message: "Email successfully updated without CSRF token validation.",
      email: body.email || 'probe@security-audit.local'
    }));
    return;
  }

  // 23. ROUTE: GET /search or GET / with query parameter `q` (VULN-15: Reflected XSS)
  const searchQuery = query.q || query.search || query.query || '';
  if (searchQuery) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Search Results - Sential Benchmark Target</title>
  <style>
    body { font-family: system-ui, sans-serif; background: #0b0f19; color: #f8fafc; padding: 2rem; }
    .card { background: #111827; border: 1px solid #1f2937; border-radius: 8px; padding: 1.5rem; margin-top: 1rem; }
  </style>
</head>
<body>
  <h2>Search Inquiry Results</h2>
  <div class="card">
    <!-- INTENTIONAL REFLECTED XSS VULNERABILITY -->
    <h3>Search results for: <em>${searchQuery}</em></h3>
    <p>Found 0 matched items for query string: ${searchQuery}</p>
  </div>
  <p><a href="/" style="color:#38bdf8;">&larr; Back to Benchmark Dashboard</a></p>
</body>
</html>`);
    return;
  }

  // 24. ROUTE: GET / - Beautiful Interactive Benchmark Dashboard
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sential AI - Benchmark Vulnerable Target Server</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #090d16;
      color: #e2e8f0;
      font-family: 'Cairo', system-ui, sans-serif;
      padding: 2rem 1rem;
      min-height: 100vh;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    header {
      background: linear-gradient(135deg, rgba(30, 41, 59, 0.7), rgba(15, 23, 42, 0.9));
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 16px;
      padding: 2rem;
      margin-bottom: 2rem;
      backdrop-filter: blur(12px);
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    .badge {
      display: inline-block;
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-running { background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }
    .badge-high { background: rgba(249, 115, 22, 0.2); color: #fb923c; border: 1px solid #f97316; }
    .badge-medium { background: rgba(234, 179, 8, 0.2); color: #facc15; border: 1px solid #eab308; }
    .badge-low { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }

    h1 { font-size: 2rem; margin-top: 0.5rem; color: #fff; font-weight: 700; }
    p.subtitle { color: #94a3b8; margin-top: 0.25rem; font-size: 0.95rem; }

    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 1rem;
      margin-top: 1.5rem;
    }
    .stat-card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid rgba(255, 255, 255, 0.05);
      border-radius: 12px;
      padding: 1.25rem;
    }
    .stat-number { font-size: 2rem; font-weight: 700; color: #38bdf8; font-family: 'JetBrains Mono', monospace; }
    .stat-label { color: #64748b; font-size: 0.8rem; text-transform: uppercase; font-weight: 600; margin-top: 0.25rem; }

    .card {
      background: #0f172a;
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 14px;
      padding: 1.5rem;
      margin-bottom: 2rem;
    }
    .card h2 { font-size: 1.3rem; margin-bottom: 1rem; color: #f1f5f9; display: flex; align-items: center; justify-content: space-between; }

    table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: 0.9rem; }
    th { text-align: left; padding: 0.85rem; background: rgba(30, 41, 59, 0.5); color: #94a3b8; font-weight: 600; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 1px solid rgba(255,255,255,0.08); }
    td { padding: 0.85rem; border-bottom: 1px solid rgba(255, 255, 255, 0.04); vertical-align: middle; }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    code { font-family: 'JetBrains Mono', monospace; background: rgba(0,0,0,0.4); padding: 0.2rem 0.5rem; border-radius: 6px; font-size: 0.82rem; color: #38bdf8; }
    a { color: #38bdf8; text-decoration: none; }
    a:hover { text-decoration: underline; }

    .test-box {
      display: flex;
      gap: 0.75rem;
      margin-top: 1rem;
    }
    .test-box input {
      flex: 1;
      background: #1e293b;
      border: 1px solid #334155;
      padding: 0.75rem 1rem;
      border-radius: 8px;
      color: #fff;
      font-size: 0.9rem;
    }
    .test-box button {
      background: #0284c7;
      color: #fff;
      border: none;
      padding: 0.75rem 1.5rem;
      border-radius: 8px;
      font-weight: 600;
      cursor: pointer;
    }
    .test-box button:hover { background: #0369a1; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <span class="badge badge-running">&#9679; LIVE TARGET RUNNING</span>
        <span style="color:#94a3b8; font-family:'JetBrains Mono'; font-size:0.85rem;">http://localhost:${PORT}</span>
      </div>
      <h1>Sential AI &mdash; Vulnerable Benchmark Target Server</h1>
      <p class="subtitle">Mock QA test benchmark environment purposefully embedded with 28 OWASP Top 10 web vulnerabilities to measure scanner detection coverage.</p>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-number">28</div>
          <div class="stat-label">Total Documented Vulnerabilities</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:#ef4444;">6</div>
          <div class="stat-label">Critical Severity Flaws</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:#f97316;">10</div>
          <div class="stat-label">High Severity Flaws</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:#eab308;">6</div>
          <div class="stat-label">Medium Severity Flaws</div>
        </div>
        <div class="stat-card">
          <div class="stat-number" style="color:#3b82f6;">6</div>
          <div class="stat-label">Low Severity Flaws</div>
        </div>
      </div>
    </header>

    <div class="card">
      <h2>Interactive Reflected XSS Test Box</h2>
      <p style="color:#94a3b8; font-size:0.9rem;">Test the unescaped query parameter directly in the web browser:</p>
      <form action="/search" method="GET" class="test-box">
        <input type="text" name="q" value="&lt;script&gt;alert('Sential-AI-XSS-Verified')&lt;/script&gt;" />
        <button type="submit">Test XSS Probe</button>
      </form>
    </div>

    <div class="card">
      <h2>
        <span>Benchmark Vulnerabilities Catalog (28 Flaws)</span>
        <span style="font-size:0.85rem; color:#94a3b8; font-weight:normal;">Target Port: ${PORT}</span>
      </h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Vulnerability Title</th>
            <th>Severity</th>
            <th>CWE</th>
            <th>Category</th>
            <th>Vulnerable Endpoint</th>
          </tr>
        </thead>
        <tbody>
          ${VULNERABILITY_CATALOG.map(v => {
            const sevClass = v.severity.toLowerCase();
            const linkHref = v.endpoint.startsWith('/') ? v.endpoint : null;
            return `
            <tr>
              <td><code>${v.id}</code></td>
              <td><strong>${v.title}</strong></td>
              <td><span class="badge badge-${sevClass}">${v.severity}</span></td>
              <td><code>${v.cwe}</code></td>
              <td>${v.category}</td>
              <td>
                ${linkHref ? `<a href="${linkHref}" target="_blank"><code>${v.endpoint}</code></a>` : `<code>${v.endpoint}</code>`}
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>
    </div>
  </div>
</body>
</html>`);
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[BENCHMARK SERVER] Sential AI Vulnerability Target is live on http://localhost:${PORT}`);
  console.log(`[BENCHMARK SERVER] Total documented vulnerabilities: ${VULNERABILITY_CATALOG.length}`);
});
