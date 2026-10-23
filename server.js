const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Heuristic & Static Security Engine (Web, Cloud, C/C++ Memory Safety & Input Validation)
function fallbackRegexReview(diffText) {
  const findings = [];
  const lines = diffText.split('\n');
  let currentFile = 'snippet.txt';
  let lineNo = 0;

  // 1. Check if input is in Git Unified Diff format or raw code
  const isDiff = lines.some(l => l.startsWith('diff --git') || l.startsWith('+++ ') || l.startsWith('@@ '));

  // 2. Reject random gibberish / invalid non-code text
  const trimmed = diffText.trim();
  if (trimmed.length > 0 && !isDiff && !/[;{}()=<>\[\]\/#]/.test(trimmed)) {
    findings.push({
      file: 'input',
      line: 1,
      severity: 'WARNING',
      owasp: 'A04:2021 - Insecure Design',
      category: 'Input Validation',
      issue: 'Unrecognized input format (neither a valid git diff nor structured source code).',
      fix: 'Paste a unified git diff (e.g. from `git diff`) or a valid C/C++/JS source snippet.',
      suggestedCode: '// Paste valid unified diff starting with "diff --git" or code containing valid statements'
    });
    return findings;
  }

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];

    if (rawLine.startsWith('+++ b/')) {
      currentFile = rawLine.replace('+++ b/', '').trim();

      // Check for sensitive files committed to repository
      if (/(\.env|id_rsa|\.pem|\.pfx|wp-config\.php|credentials\.json)$/i.test(currentFile)) {
        findings.push({
          file: currentFile,
          line: 1,
          severity: 'CRITICAL',
          owasp: 'A05:2021 - Security Misconfiguration',
          category: 'Sensitive File',
          issue: `High-risk sensitive file (${path.basename(currentFile)}) tracked in repository.`,
          fix: 'Remove file from repository history and add pattern to .gitignore.',
          suggestedCode: '# Added to .gitignore\n' + path.basename(currentFile)
        });
      }
      continue;
    } else if (rawLine.startsWith('@@')) {
      const match = rawLine.match(/\+(\d+)/);
      if (match) lineNo = parseInt(match[1], 10) - 1;
      continue;
    }

    // Determine target code line:
    // If it is a git diff, inspect only added lines (+)
    // If it is raw pasted code, inspect every line
    let code = null;
    if (isDiff) {
      if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
        lineNo++;
        code = rawLine.slice(1);
      } else if (!rawLine.startsWith('-')) {
        lineNo++;
      }
    } else {
      lineNo++;
      code = rawLine;
    }

    if (!code || !code.trim()) continue;

    // 1. Secrets & Credentials
    if (/(api_?key|secret|password|bearer|auth_token)\s*=\s*['"][A-Za-z0-9_\-\.]{8,}['"]/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'CRITICAL',
        owasp: 'A07:2021 - Identification & Auth Failures',
        category: 'Secrets & Auth',
        issue: 'Hardcoded secret or credential token exposed in code.',
        fix: 'Migrate secret to environment variables or a secret vault.',
        suggestedCode: code.replace(/=\s*['"][A-Za-z0-9_\-\.]+['"]/, '= process.env.API_SECRET || ""')
      });
    }

    // 2. Private Cryptographic Keys
    if (/-----BEGIN[ A-Z_-]*KEY/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'CRITICAL',
        owasp: 'A02:2021 - Cryptographic Failures',
        category: 'Secrets & Auth',
        issue: 'Private cryptographic key header committed directly into code.',
        fix: 'Revoke and rotate this key immediately; store in cloud secret vault.',
        suggestedCode: '// Secret key loaded from secure secret manager at runtime\nconst privateKey = await secretManager.getSecret("APP_PRIVATE_KEY");'
      });
    }

    // 3. AWS Access Key IDs
    if (/(AKIA[0-9A-Z]{16})/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'CRITICAL',
        owasp: 'A07:2021 - Identification & Auth Failures',
        category: 'Secrets & Auth',
        issue: 'Exposed AWS Access Key ID detected.',
        fix: 'Use AWS IAM Roles or AWS Secrets Manager instead of inline keys.',
        suggestedCode: code.replace(/AKIA[0-9A-Z]{16}/, 'process.env.AWS_ACCESS_KEY_ID')
      });
    }

    // 4. SQL Injection
    if (/(SELECT|INSERT|UPDATE|DELETE).*\$\{.*\}|(SELECT|INSERT|UPDATE|DELETE).*f['"]|(SELECT|INSERT|UPDATE|DELETE).*(\+\s*['"]|\+\s*[a-zA-Z0-9_]+)/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'CRITICAL',
        owasp: 'A03:2021 - Injection',
        category: 'Injections',
        issue: 'Direct string concatenation in SQL statement invites SQL injection.',
        fix: 'Use parameterized queries ($1, ? placeholders) or ORM abstraction.',
        suggestedCode: 'return db.query("SELECT * FROM users WHERE email = $1", [userEmail]);'
      });
    }

    // 5. Dynamic Code Execution / Eval
    if (/\beval\(|\bnew Function\(|setTimeout\([^,]+['"][^'"]+['"]/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'CRITICAL',
        owasp: 'A03:2021 - Injection',
        category: 'Injections',
        issue: 'Dynamic code execution via eval/Function allows Remote Code Execution (RCE).',
        fix: 'Refactor using static parsing or safe functional strategies.',
        suggestedCode: '// Replaced dangerous eval with structured static mapper\nconst safeResult = JSON.parse(inputData);'
      });
    }

    // 6. Dangerous / Unbounded C String Functions (Buffer Overflow)
    if (/\b(gets|strcpy|strcat|sprintf)\s*\(/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'CRITICAL',
        owasp: 'A03:2021 - Injection',
        category: 'Memory Safety',
        issue: 'Dangerous unbounded C string function detected (buffer overflow risk).',
        fix: 'Replace with bounded variants (fgets, strncpy, strncat, snprintf).',
        suggestedCode: code.replace(/sprintf\s*\(([^,]+),/g, 'snprintf($1, sizeof($1),')
      });
    }

    // 7. Dangerous Zero-Byte Allocation
    if (/\bmalloc\s*\(\s*0\s*\)/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'WARNING',
        owasp: 'A05:2021 - Security Misconfiguration',
        category: 'Memory Safety',
        issue: 'Zero-byte allocation detected via malloc(0).',
        fix: 'Ensure allocation size is strictly greater than 0 before allocating.',
        suggestedCode: 'if (size > 0) ptr = malloc(size);'
      });
    }

    // 8. C/C++ Free without Null Reset (Dangling Pointer / Double Free Hazard)
    if (/\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\)/i.test(code)) {
      const ptrMatch = code.match(/\bfree\s*\(\s*([a-zA-Z0-9_]+)\s*\)/);
      if (ptrMatch) {
        findings.push({
          file: currentFile,
          line: lineNo,
          severity: 'SUGGESTION',
          owasp: 'A04:2021 - Insecure Design',
          category: 'Memory Safety',
          issue: `Pointer "${ptrMatch[1]}" freed without setting to NULL (dangling pointer hazard).`,
          fix: `Assign "${ptrMatch[1]} = NULL;" immediately after free().`,
          suggestedCode: `free(${ptrMatch[1]});\n${ptrMatch[1]} = NULL;`
        });
      }
    }

    // 9. Syntax Check: Unclosed string literal
    const quoteMatches = code.match(/(?<!\\)"/g) || [];
    if (quoteMatches.length % 2 !== 0 && !code.trim().startsWith('//') && !code.trim().startsWith('/*')) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'WARNING',
        owasp: 'A04:2021 - Insecure Design',
        category: 'Syntax & Build',
        issue: 'Unclosed string literal detected.',
        fix: 'Close string quotes with matching `"` and terminate statement.',
        suggestedCode: code + '";'
      });
    }

    // 10. Cross-Site Scripting (XSS)
    if (/\.innerHTML\s*=|\bdangerouslySetInnerHTML/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'WARNING',
        owasp: 'A03:2021 - Injection',
        category: 'XSS & Client',
        issue: 'Unescaped innerHTML assignment introduces Cross-Site Scripting (XSS).',
        fix: 'Use textContent, innerText, or sanitize inputs with DOMPurify.',
        suggestedCode: code.replace(/\.innerHTML\s*=/, '.textContent =')
      });
    }

    // 11. CORS Wildcard
    if (/Access-Control-Allow-Origin['"]?\s*,\s*['"]\*/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'WARNING',
        owasp: 'A05:2021 - Security Misconfiguration',
        category: 'Configuration',
        issue: 'Wildcard CORS origin (*) detected. Permits arbitrary origin access.',
        fix: 'Restrict origin to trusted production domains.',
        suggestedCode: "res.setHeader('Access-Control-Allow-Origin', process.env.TRUSTED_ORIGIN || 'https://example.com');"
      });
    }

    // 12. Debug Logging Artifacts
    if (/console\.(log|debug|trace)\(|DEBUG\s*=\s*true/i.test(code)) {
      findings.push({
        file: currentFile,
        line: lineNo,
        severity: 'SUGGESTION',
        owasp: 'A09:2021 - Logging & Monitoring Failures',
        category: 'Code Smells',
        issue: 'Production debug logging statement left active in PR diff.',
        fix: 'Remove logging output or guard with environment checks.',
        suggestedCode: '// Removed debugging artifact before merge'
      });
    }
  }

  return findings;
}

// Security Metric Calculator
function calculateSecurityScore(findings) {
  let score = 100;
  for (const f of findings) {
    if (f.severity === 'CRITICAL') score -= 30;
    else if (f.severity === 'WARNING') score -= 15;
    else if (f.severity === 'SUGGESTION') score -= 5;
  }
  score = Math.max(0, score);
  let grade = 'A+';
  if (score < 40) grade = 'F (Dangerous)';
  else if (score < 70) grade = 'C (High Risk)';
  else if (score < 90) grade = 'B (Fair)';

  const categories = {};
  findings.forEach(f => {
    categories[f.category || 'General'] = (categories[f.category || 'General'] || 0) + 1;
  });

  return { score, grade, categories };
}

// Fetch GitHub PR Diff API
app.post('/api/fetch-pr', async (req, res) => {
  const { prUrl } = req.body;
  if (!prUrl) return res.status(400).json({ error: 'GitHub PR URL is required.' });

  const match = prUrl.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
  if (!match) {
    return res.status(400).json({ error: 'Invalid PR URL format. Use: https://github.com/:owner/:repo/pull/:id' });
  }

  const [, owner, repo, pullNumber] = match;
  try {
    const ghRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/pulls/${pullNumber}`, {
      headers: {
        'Accept': 'application/vnd.github.v3.diff',
        'User-Agent': 'Open-PR-Reviewer'
      }
    });

    if (!ghRes.ok) {
      return res.status(ghRes.status).json({ error: `GitHub API error: ${ghRes.statusText}` });
    }

    const diff = await ghRes.text();
    return res.json({ diff });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to fetch diff from GitHub API.' });
  }
});

// Review Diff API
app.post('/api/review', async (req, res) => {
  const { diff, model = 'codellama:7b' } = req.body;

  if (!diff || !diff.trim()) {
    return res.status(400).json({ error: 'Diff content cannot be empty.' });
  }

  const prompt = `You are a strict security and code quality auditor for pull requests.
Analyze the following git diff carefully line by line.
Check for hardcoded secrets, SQL injection, logic flaws, and memory safety issues.
Return a valid JSON array of objects matching this schema:
[
  {
    "file": "string",
    "line": 0,
    "severity": "CRITICAL" | "WARNING" | "SUGGESTION",
    "owasp": "OWASP Top 10 Category",
    "category": "Category name",
    "issue": "concise description",
    "fix": "recommended replacement or change",
    "suggestedCode": "safe replacement code"
  }
]
Output valid JSON only.

Diff to review:
${diff}`;

  // 1. Check local Ollama instance if available
  try {
    const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
    const response = await fetch(`${ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: model,
        prompt: prompt,
        stream: false,
        format: 'json'
      }),
      signal: AbortSignal.timeout(8000)
    });

    if (response.ok) {
      const data = await response.json();
      let parsed = JSON.parse(data.response);
      let reviews = Array.isArray(parsed) ? parsed : (Object.values(parsed).find(v => Array.isArray(v)) || [parsed]);
      const metrics = calculateSecurityScore(reviews);
      return res.json({ source: `ollama (${model})`, reviews, metrics });
    }
  } catch (err) {
    // Fall back to heuristic engine
  }

  // 2. Automated Static Heuristic Engine
  const fallbackReviews = fallbackRegexReview(diff);
  const metrics = calculateSecurityScore(fallbackReviews);
  return res.json({ source: 'open-source heuristic engine', reviews: fallbackReviews, metrics });
});

// Safe fallback for Express v5
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});