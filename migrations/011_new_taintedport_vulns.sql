-- Add 3 new TaintedPort vulnerabilities (TP-027, TP-028, TP-029)
-- Uses INSERT OR IGNORE so it's safe to re-run

INSERT OR IGNORE INTO vulnerabilities
    (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter, description, code_location, poc, remediation, created_by)
SELECT
    apps.id,
    'TP-027',
    'SSRF via Wine Import URL',
    'high',
    'SSRF',
    'POST',
    '/wines/import-url',
    'url',
    'The wine import endpoint fetches content from a user-supplied URL using file_get_contents(), which supports file://, http://, and other PHP stream wrappers. An attacker can read arbitrary local files. This enables a chain: (1) read file:///var/www/backend/api/config/jwt.php, (2) extract the JWT secret, (3) forge a properly HS256-signed admin token.',
    'backend/api/controllers/WineController.php',
    '{"url": "file:///var/www/backend/api/config/jwt.php"}',
    'Validate the URL scheme (allow only https://), block private/internal IPs, and use curl with CURLOPT_PROTOCOLS instead of file_get_contents().',
    apps.created_by
FROM apps WHERE apps.name = 'TaintedPort' AND apps.version = '1.0';

INSERT OR IGNORE INTO vulnerabilities
    (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter, description, code_location, poc, remediation, created_by)
SELECT
    apps.id,
    'TP-028',
    'SQLi -> TOTP Secret Extraction -> 2FA Bypass -> Account Takeover',
    'critical',
    'SQLi',
    'GET',
    '/wines',
    'search',
    'Vulnerability chain combining SQL injection with TOTP secret theft to fully bypass 2FA and take over any account. Steps: (1) Use SQLi to extract email, password_hash, and totp_secret for all users, (2) crack password offline, (3) compute valid TOTP codes from stolen secret, (4) login as victim with valid 2FA.',
    'backend/api/models/Wine.php -> getAll(); backend/api/controllers/AuthController.php -> login()',
    'search='' UNION SELECT 1,email,password_hash,name,5,6,totp_secret,totp_enabled FROM users--',
    'Fix the underlying SQL injection vulnerabilities. Store TOTP secrets encrypted at rest.',
    apps.created_by
FROM apps WHERE apps.name = 'TaintedPort' AND apps.version = '1.0';

INSERT OR IGNORE INTO vulnerabilities
    (app_id, vuln_id, title, severity, vuln_type, http_method, url, parameter, description, code_location, poc, remediation, created_by)
SELECT
    apps.id,
    'TP-029',
    'Reflected XSS - Contact Form Preview (Server-Side)',
    'medium',
    'XSS',
    'POST',
    '/contact/preview',
    'name',
    'The contact form preview endpoint receives form data and renders an HTML page with form values embedded directly without escaping. Unlike other XSS vulns in this app (DOM-based via dangerouslySetInnerHTML), this is a traditional server-side reflected XSS. All four form fields (name, email, subject, message) are vulnerable.',
    'backend/api/controllers/ContactController.php',
    'name=<script>alert(document.cookie)</script>',
    'HTML-encode all user input with htmlspecialchars() before embedding in the page.',
    apps.created_by
FROM apps WHERE apps.name = 'TaintedPort' AND apps.version = '1.0';
