-- Finding types that are bare CWE numbers ("CWE-915") become readable vuln
-- classes ("Mass Assignment"). vuln_type is the finding's heading on the scan
-- page and nobody knows CWE numbers by heart. The 2026-11-12 COS importer
-- (extractor_version 'cos') copied each vulnerability's `cwe` field into
-- vuln_type; it now translates via tools/import_scan.py CWE_NAMES, which this
-- table is generated from. An unlisted CWE falls back to the finding's title.
-- Changes no stored match or score (the heuristic rematch reads vuln_type, and
-- a readable class suits it better than a CWE number).
UPDATE scan_findings
SET vuln_type = COALESCE(
    CASE UPPER(TRIM(vuln_type))
        WHEN 'CWE-20' THEN 'Input Validation'
        WHEN 'CWE-22' THEN 'Path Traversal'
        WHEN 'CWE-78' THEN 'Command Injection'
        WHEN 'CWE-79' THEN 'XSS'
        WHEN 'CWE-89' THEN 'SQLi'
        WHEN 'CWE-94' THEN 'Code Injection'
        WHEN 'CWE-117' THEN 'Log Injection'
        WHEN 'CWE-200' THEN 'Information Disclosure'
        WHEN 'CWE-204' THEN 'Account Enumeration'
        WHEN 'CWE-209' THEN 'Verbose Errors'
        WHEN 'CWE-215' THEN 'Debug Information Exposure'
        WHEN 'CWE-269' THEN 'Privilege Escalation'
        WHEN 'CWE-284' THEN 'Broken Access Control'
        WHEN 'CWE-285' THEN 'Broken Authorization'
        WHEN 'CWE-287' THEN 'Broken Authentication'
        WHEN 'CWE-306' THEN 'Missing Authentication'
        WHEN 'CWE-307' THEN 'Brute Force'
        WHEN 'CWE-312' THEN 'Sensitive Data Exposure'
        WHEN 'CWE-319' THEN 'Cleartext Transmission'
        WHEN 'CWE-326' THEN 'Weak TLS'
        WHEN 'CWE-327' THEN 'Weak Cryptography'
        WHEN 'CWE-330' THEN 'Weak Randomness'
        WHEN 'CWE-345' THEN 'Signature Bypass'
        WHEN 'CWE-347' THEN 'JWT Signature Bypass'
        WHEN 'CWE-352' THEN 'CSRF'
        WHEN 'CWE-362' THEN 'Race Condition'
        WHEN 'CWE-384' THEN 'Session Fixation'
        WHEN 'CWE-400' THEN 'Resource Exhaustion'
        WHEN 'CWE-434' THEN 'Unrestricted File Upload'
        WHEN 'CWE-472' THEN 'Parameter Tampering'
        WHEN 'CWE-489' THEN 'Debug Endpoint Exposure'
        WHEN 'CWE-497' THEN 'Version Disclosure'
        WHEN 'CWE-502' THEN 'Insecure Deserialization'
        WHEN 'CWE-522' THEN 'Credential Exposure'
        WHEN 'CWE-601' THEN 'Open Redirect'
        WHEN 'CWE-611' THEN 'XXE'
        WHEN 'CWE-613' THEN 'Session Not Invalidated'
        WHEN 'CWE-639' THEN 'IDOR'
        WHEN 'CWE-640' THEN 'Weak Password Recovery'
        WHEN 'CWE-693' THEN 'Missing Security Headers'
        WHEN 'CWE-770' THEN 'Missing Rate Limiting'
        WHEN 'CWE-798' THEN 'Hardcoded Credentials'
        WHEN 'CWE-799' THEN 'Missing Usage Limit'
        WHEN 'CWE-840' THEN 'Business Logic'
        WHEN 'CWE-862' THEN 'Missing Authorization'
        WHEN 'CWE-863' THEN 'Broken Authorization'
        WHEN 'CWE-915' THEN 'Mass Assignment'
        WHEN 'CWE-918' THEN 'SSRF'
        WHEN 'CWE-942' THEN 'CORS'
        WHEN 'CWE-943' THEN 'NoSQL Injection'
        WHEN 'CWE-1021' THEN 'Clickjacking'
        WHEN 'CWE-1336' THEN 'SSTI'
        WHEN 'CWE-1392' THEN 'Default Credentials'
    END,
    title)
WHERE vuln_type LIKE 'CWE-%'
  AND scan_id IN (SELECT id FROM scans WHERE extractor_version = 'cos');
