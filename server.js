const express = require('express');
const path = require('path');
const { spawn } = require('child_process');
const fs = require('fs/promises');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20mb' }));
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

// General-purpose source-code error check. Prefer local syntax tools and use
// the local model for languages without an installed checker.
function runLocalCommand(command, args, source = '', options = {}) {
  const timeoutMs = options.timeoutMs || 15000;
  const maxOutputBytes = options.maxOutputBytes || 1024 * 1024;
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';
    let outputBytes = 0;
    let outputLimitExceeded = false;
    let timedOut = false;
    const child = spawn(command, args, {
      windowsHide: true,
      cwd: options.cwd,
      shell: options.shell || false,
      env: { ...process.env, ...(options.env || {}) },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    const receive = (chunk, stream) => {
      outputBytes += Buffer.byteLength(chunk);
      if (outputBytes > maxOutputBytes) {
        outputLimitExceeded = true;
        child.kill();
        return;
      }
      if (stream === 'stdout') stdout += chunk;
      else stderr += chunk;
    };
    child.stdout.on('data', chunk => receive(chunk, 'stdout'));
    child.stderr.on('data', chunk => receive(chunk, 'stderr'));
    child.on('error', error => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal, stdout, stderr, timedOut, outputLimitExceeded });
    });
    child.stdin.end(source);
  });
}

function parseCommandResult(language, result) {
  const output = `${result.stdout || ''}\n${result.stderr || ''}`.trim();
  const diagnosticLines = [...new Set(output.split(/\r?\n/).map(line => line.trim()).filter(line =>
    /\b(error|warning|syntaxerror|exception|fatal|cannot find|undefined reference)\b/i.test(line)
  ))].slice(0, 100);
  const lines = diagnosticLines.length ? diagnosticLines : [output || `${language} check failed (exit code ${result.code}).`];
  return {
    source: `${language} syntax checker`,
    issues: result.code === 0 ? [] : lines.map(message => {
      const lineMatch = message.match(/(?:line\s+|\()(\d+)(?::\d+|,\d+)?/i) || message.match(/:(\d+)(?::\d+)?/);
      return { line: lineMatch ? Number(lineMatch[1]) : null, message, fix: '' };
    })
  };
}

function commandUnavailable(result) {
  return process.platform === 'win32' && result.code !== 0 &&
    /is not recognized as an internal or external command/i.test(`${result.stdout || ''}\n${result.stderr || ''}`);
}

async function withTemporaryFiles(files, callback) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), 'code-check-'));
  try {
    for (const file of files) {
      const target = path.join(root, ...file.path.split('/'));
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, file.content, 'utf8');
    }
    return await callback(root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const PROJECT_FILE_EXTENSIONS = new Set([
  '.py', '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.c', '.h', '.cc', '.cpp',
  '.cxx', '.hpp', '.hxx', '.java', '.go', '.rs', '.json', '.yaml', '.yml', '.toml',
  '.txt', '.xml', '.css', '.html', '.properties', '.gradle', '.lock'
]);

async function runLocalSyntaxCheck(language, source, fileNameHint = '', level = 'compile') {
  const normalized = language.trim().toLowerCase();
  let command;
  let args;
  if (normalized === 'python' || normalized === 'python 3') {
    command = process.env.PYTHON_PATH || 'python';
    const parserExpression = level === 'syntax' ? 'ast.parse(source)' : 'compile(source, "<code-check>", "exec")';
    const pythonScript = [
      'import ast, sys',
      'source = sys.stdin.buffer.read().decode("utf-8", errors="replace")',
      'try:',
      `    ${parserExpression}`,
      'except SyntaxError as error:',
      '    print(f"SyntaxError at line {error.lineno}: {error.msg}")',
      '    sys.exit(1)',
      'except Exception as error:',
      '    print(f"{type(error).__name__}: {error}")',
      '    sys.exit(1)'
    ].join('\n');
    args = ['-c', pythonScript];
  } else if (['javascript', 'js', 'node.js'].includes(normalized)) {
    command = process.execPath;
    args = ['--check', '-'];
  } else if (normalized === 'c') {
    command = process.env.C_COMPILER || 'gcc';
    if (level === 'syntax') args = ['-Wall', '-Wextra', '-Werror', '-x', 'c', '-fsyntax-only', '-'];
    else return withTemporaryFiles([{ path: 'CodeCheck.c', content: source }], async root => {
      try {
        const result = await runLocalCommand(command, ['-Wall', '-Wextra', '-Werror', '-c', path.join(root, 'CodeCheck.c'), '-o', path.join(root, 'CodeCheck.o')]);
        return parseCommandResult(language, result);
      } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    });
  } else if (['c++', 'cpp', 'cxx'].includes(normalized)) {
    command = process.env.CXX_COMPILER || 'g++';
    if (level === 'syntax') args = ['-Wall', '-Wextra', '-Werror', '-x', 'c++', '-std=c++17', '-fsyntax-only', '-'];
    else return withTemporaryFiles([{ path: 'CodeCheck.cpp', content: source }], async root => {
      try {
        const result = await runLocalCommand(command, ['-Wall', '-Wextra', '-Werror', '-std=c++17', '-c', path.join(root, 'CodeCheck.cpp'), '-o', path.join(root, 'CodeCheck.o')]);
        return parseCommandResult(language, result);
      } catch (error) { if (error.code === 'ENOENT') return null; throw error; }
    });
  } else if (normalized === 'java') {
    const className = source.match(/\bpublic\s+(?:final\s+)?class\s+([A-Za-z_$][\w$]*)/)?.[1] || 'CodeCheck';
    return withTemporaryFiles([{ path: `${className}.java`, content: source }], async root => {
      try {
        const outputDir = path.join(root, 'out');
        await fs.mkdir(outputDir, { recursive: true });
        const result = await runLocalCommand(process.env.JAVAC_PATH || 'javac', [
          '-proc:none', '-d', outputDir, path.join(root, `${className}.java`)
        ]);
        return parseCommandResult(language, result);
      } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
      }
    });
  } else if (['typescript', 'tsx'].includes(normalized)) {
    const fileName = normalized === 'tsx' || path.extname(fileNameHint).toLowerCase() === '.tsx' ? 'CodeCheck.tsx' : 'CodeCheck.ts';
    return withTemporaryFiles([{ path: fileName, content: source }], async root => {
      const tscScript = process.env.TSC_PATH;
      const command = tscScript ? process.execPath : (process.env.TSC_COMPILER || 'tsc');
      const args = [
      ...(tscScript ? [tscScript] : []), '--noEmit', '--pretty', 'false', '--skipLibCheck',
        '--target', 'ES2022', '--module', 'ESNext', ...(fileName.endsWith('.tsx') ? ['--jsx', 'react-jsx'] : []),
        path.join(root, fileName)
      ];
      try {
        const result = await runLocalCommand(command, args, '', {
          shell: process.platform === 'win32' && !tscScript
        });
        return commandUnavailable(result) ? null : parseCommandResult(language, result);
      } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
      }
    });
  } else if (normalized === 'go') {
    return withTemporaryFiles([
      { path: 'go.mod', content: 'module codecheck\n\ngo 1.20\n' },
      { path: 'main.go', content: source }
    ], async root => {
      try {
        const result = await runLocalCommand(process.env.GO_COMPILER || 'go', [
          'build', '-o', path.join(root, 'codecheck.exe'), '.'
        ], '', { cwd: root, env: { GOPROXY: 'off', GOTOOLCHAIN: 'local' } });
        return parseCommandResult(language, result);
      } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
      }
    });
  } else if (normalized === 'rust') {
    return withTemporaryFiles([{ path: 'codecheck.rs', content: source }], async root => {
      try {
        const result = await runLocalCommand(process.env.RUSTC_COMPILER || 'rustc', [
          '--crate-type', 'lib', '--emit', 'metadata', '-o', path.join(root, 'codecheck.rmeta'),
          path.join(root, 'codecheck.rs')
        ]);
        return parseCommandResult(language, result);
      } catch (error) {
        if (error.code === 'ENOENT') return null;
        throw error;
      }
    });
  } else {
    return null;
  }

  try {
    const result = await runLocalCommand(command, args, source);
    return parseCommandResult(language, result);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw error;
  }
}

const CHECKABLE_EXTENSIONS = {
  Python: ['.py'], JavaScript: ['.js', '.mjs', '.cjs'], TypeScript: ['.ts', '.tsx'],
  C: ['.c'], 'C++': ['.cc', '.cpp', '.cxx', '.h', '.hpp', '.hxx'], Java: ['.java'],
  Go: ['.go'], Rust: ['.rs']
};

async function runLintCheck(language, files) {
  const extensions = CHECKABLE_EXTENSIONS[language];
  if (!extensions) return null;
  const sources = files.filter(file => extensions.includes(path.posix.extname(file.path).toLowerCase()));
  if (!sources.length) return { source: `${language} linter`, issues: [] };

  return withTemporaryFiles(files, async root => {
    const sourcePaths = sources.map(file => path.join(root, ...file.path.split('/')));
    let command;
    let args;
    let options = { cwd: root };
    if (language === 'Python') {
      command = process.env.RUFF_COMPILER || 'ruff';
      args = ['check', '--output-format', 'concise', ...sourcePaths];
    } else if (language === 'JavaScript') {
      command = process.env.ESLINT_COMPILER || 'eslint';
      args = ['--no-config-lookup', '--no-ignore', '--rule', 'no-undef:error', '--rule', 'no-unreachable:error', ...sourcePaths];
      options = { ...options, shell: process.platform === 'win32' };
    } else if (language === 'C' || language === 'C++') {
      command = process.env.CPPCHECK_COMPILER || 'cppcheck';
      args = ['--error-exitcode=1', '--enable=warning,style,performance,portability', ...sourcePaths];
    } else if (language === 'Go') {
      command = process.env.GO_COMPILER || 'go';
      if (!files.some(file => path.posix.basename(file.path) === 'go.mod')) {
        await fs.writeFile(path.join(root, 'go.mod'), 'module codecheck\n\ngo 1.20\n', 'utf8');
      }
      args = ['vet', './...'];
      options = { ...options, env: { GOPROXY: 'off', GOTOOLCHAIN: 'local' }, timeoutMs: 30000 };
    } else if (language === 'Rust') {
      command = process.env.RUSTFMT_COMPILER || 'rustfmt';
      args = ['--check', ...sourcePaths];
    } else {
      return null;
    }

    try {
      const result = await runLocalCommand(command, args, '', options);
      if (commandUnavailable(result)) return null;
      const parsed = parseCommandResult(language, result);
      const output = `${result.stdout || ''}\n${result.stderr || ''}`.replace(/\\/g, '/').toLowerCase();
      for (const issue of parsed.issues) {
        const diagnostic = issue.message.replace(/\\/g, '/').toLowerCase();
        issue.path = sources.find(file => diagnostic.includes(file.path.toLowerCase()))?.path ||
          sources.find(file => output.includes(path.posix.basename(file.path).toLowerCase()))?.path;
      }
      parsed.source = `${language} ${language === 'Python' ? 'Ruff' : language === 'JavaScript' ? 'ESLint' : language === 'Go' ? 'go vet' : language === 'Rust' ? 'rustfmt' : 'cppcheck'} check`;
      return parsed;
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
  });
}

const PROJECT_LANGUAGE_EXTENSIONS = {
  Python: new Set(['.py']),
  JavaScript: new Set(['.js', '.mjs', '.cjs']),
  TypeScript: new Set(['.ts', '.tsx']),
  C: new Set(['.c']),
  'C++': new Set(['.cc', '.cpp', '.cxx', '.h', '.hpp', '.hxx']),
  Java: new Set(['.java']),
  Go: new Set(['.go']),
  Rust: new Set(['.rs'])
};

function safeProjectFiles(input) {
  if (!Array.isArray(input) || input.length === 0 || input.length > 100) {
    throw new Error('Choose between 1 and 100 project files.');
  }
  let totalBytes = 0;
  const files = input.map(file => {
    if (!file || typeof file.path !== 'string' || typeof file.content !== 'string') {
      throw new Error('Each project file must include a path and text content.');
    }
    const normalized = file.path.replace(/\\/g, '/');
    if (!normalized || normalized.startsWith('/') || /^[a-z]:/i.test(normalized) || normalized.includes('\0')) {
      throw new Error('A project file has an invalid path.');
    }
    const segments = normalized.split('/');
    if (segments.some(segment => !segment || segment === '.' || segment === '..')) {
      throw new Error('A project file has an invalid path.');
    }
    const extension = path.posix.extname(normalized).toLowerCase();
    if (!PROJECT_FILE_EXTENSIONS.has(extension) && !['package.json', 'go.mod', 'Cargo.toml', 'CMakeLists.txt'].includes(path.posix.basename(normalized))) {
      throw new Error(`Unsupported project file type: ${extension || '(no extension)'}`);
    }
    totalBytes += Buffer.byteLength(file.content, 'utf8');
    return { path: segments.join('/'), content: file.content };
  });
  if (totalBytes > 8 * 1024 * 1024) throw new Error('Project files exceed the 8 MB size limit.');
  return files;
}

async function runProjectSyntaxCheck(language, files, level = 'compile') {
  if (level === 'lint') return runLintCheck(language, files);
  const extensions = PROJECT_LANGUAGE_EXTENSIONS[language];
  if (!extensions) return null;
  const sources = files.filter(file => extensions.has(path.posix.extname(file.path).toLowerCase()));
  if (!sources.length) return { source: `${language} syntax checker`, issues: [{ line: null, path: null, message: `No ${language} source files were found in the selected project.`, fix: '' }] };

  return withTemporaryFiles(files, async root => {
    const sourcePaths = sources.map(file => path.join(root, ...file.path.split('/')));
    let result;
    try {
      if (language === 'Python') {
        const parserExpression = level === 'syntax'
          ? 'ast.parse(pathlib.Path(name).read_text(encoding="utf-8", errors="replace"), filename=name)'
          : 'compile(pathlib.Path(name).read_text(encoding="utf-8", errors="replace"), name, "exec")';
        const pythonScript = [
          'import ast, pathlib, sys',
          'failed = False',
          'for name in sys.argv[1:]:',
          `    try: ${parserExpression}`,
          '    except SyntaxError as e:',
          '        print(f"{name}:{e.lineno}: SyntaxError: {e.msg}")',
          '        failed = True',
          'sys.exit(1 if failed else 0)'
        ].join('\n');
        result = await runLocalCommand(process.env.PYTHON_PATH || 'python', ['-c', pythonScript, ...sourcePaths]);
      } else if (language === 'JavaScript') {
        const diagnostics = [];
        for (const filePath of sourcePaths) {
          const item = await runLocalCommand(process.execPath, ['--check', filePath]);
          if (item.code !== 0) diagnostics.push(item.stderr || item.stdout);
        }
        result = { code: diagnostics.length ? 1 : 0, stdout: '', stderr: diagnostics.join('\n') };
      } else if (language === 'C' || language === 'C++') {
        const command = language === 'C' ? (process.env.C_COMPILER || 'gcc') : (process.env.CXX_COMPILER || 'g++');
        if (level === 'syntax') {
          const args = language === 'C'
            ? ['-Wall', '-Wextra', '-Werror', '-x', 'c', '-fsyntax-only', ...sourcePaths]
            : ['-Wall', '-Wextra', '-Werror', '-x', 'c++', '-std=c++17', '-fsyntax-only', ...sourcePaths];
          result = await runLocalCommand(command, args, '', { cwd: root });
        } else {
          const compiled = [];
          for (let index = 0; index < sourcePaths.length; index++) {
            const args = language === 'C'
              ? ['-Wall', '-Wextra', '-Werror', '-x', 'c', '-c', sourcePaths[index], '-o', path.join(root, `codecheck-${index}.o`)]
              : ['-Wall', '-Wextra', '-Werror', '-x', 'c++', '-std=c++17', '-c', sourcePaths[index], '-o', path.join(root, `codecheck-${index}.o`)];
            compiled.push(await runLocalCommand(command, args, '', { cwd: root }));
          }
          result = { code: compiled.some(item => item.code !== 0) ? 1 : 0,
            stdout: compiled.map(item => item.stdout).filter(Boolean).join('\n'),
            stderr: compiled.map(item => item.stderr).filter(Boolean).join('\n') };
        }
      } else if (language === 'Java') {
        const outputDir = path.join(root, 'out');
        await fs.mkdir(outputDir, { recursive: true });
        result = await runLocalCommand(process.env.JAVAC_PATH || 'javac', ['-proc:none', '-d', outputDir, ...sourcePaths], '', { cwd: root });
      } else if (language === 'TypeScript') {
        const tscScript = process.env.TSC_PATH;
        const command = tscScript ? process.execPath : (process.env.TSC_COMPILER || 'tsc');
        const configPath = files.some(file => path.posix.basename(file.path) === 'tsconfig.json');
        const args = [...(tscScript ? [tscScript] : []), '--noEmit', '--pretty', 'false', '--skipLibCheck'];
        if (configPath) args.push('--project', root);
        else args.push('--target', 'ES2022', '--module', 'ESNext', ...(sources.some(file => file.path.toLowerCase().endsWith('.tsx')) ? ['--jsx', 'react-jsx'] : []), ...sourcePaths);
        result = await runLocalCommand(command, args, '', {
          cwd: root, shell: process.platform === 'win32' && !tscScript
        });
        if (commandUnavailable(result)) return null;
      } else if (language === 'Go') {
        if (!files.some(file => path.posix.basename(file.path) === 'go.mod')) {
          await fs.writeFile(path.join(root, 'go.mod'), 'module codecheck\n\ngo 1.20\n', 'utf8');
        }
        result = await runLocalCommand(process.env.GO_COMPILER || 'go', ['build', './...'], '', {
          cwd: root, env: { GOPROXY: 'off', GOTOOLCHAIN: 'local' }, timeoutMs: 30000
        });
      } else {
        const rustRoot = sources.find(file => ['main.rs', 'lib.rs'].includes(path.posix.basename(file.path))) || sources[0];
        result = await runLocalCommand(process.env.RUSTC_COMPILER || 'rustc', [
          '--crate-type', 'lib', '--emit', 'metadata', path.join(root, ...rustRoot.path.split('/'))
        ], '', { cwd: root });
      }
    } catch (error) {
      if (error.code === 'ENOENT') return null;
      throw error;
    }
    const parsed = parseCommandResult(language, result);
    parsed.source = `${language} ${level === 'syntax' ? 'syntax' : 'compile/type'} checker`;
    if (parsed.issues.length) {
      for (const issue of parsed.issues) {
        const diagnostic = issue.message.replace(/\\/g, '/');
        for (const file of sources) {
          if (diagnostic.toLowerCase().includes(file.path.toLowerCase())) {
            issue.path = file.path;
            break;
          }
        }
      }
    }
    return parsed;
  });
}

// Test execution is available only through this local development server. Each
// run uses a temporary working directory and strict time/output limits.
app.post('/api/run-tests', async (req, res) => {
  const { code, language, cases } = req.body;
  if (typeof code !== 'string' || !code.trim()) return res.status(400).json({ error: 'Code cannot be empty.' });
  if (Buffer.byteLength(code, 'utf8') > 100 * 1024) return res.status(413).json({ error: 'Test runner accepts code up to 100 KB.' });
  if (!Array.isArray(cases) || cases.length < 1 || cases.length > 10) return res.status(400).json({ error: 'Add between 1 and 10 test cases.' });
  if (cases.some(test => !test || typeof test.input !== 'string' || typeof test.expected !== 'string' || Buffer.byteLength(test.input) > 16 * 1024 || Buffer.byteLength(test.expected) > 16 * 1024 || (test.name != null && String(test.name).length > 80))) {
    return res.status(400).json({ error: 'Each test input and expected output must be text under 16 KB.' });
  }

  const normalized = String(language).trim().toLowerCase();
  const supported = ['python', 'python 3', 'javascript', 'js', 'node.js', 'typescript', 'c', 'c++', 'cpp', 'cxx', 'java', 'go', 'rust'];
  if (!supported.includes(normalized)) return res.status(400).json({ error: `Test execution is not configured for ${language}.` });

  try {
    const results = await withTemporaryFiles([], async root => {
      const sourcePath = ext => path.join(root, `Main${ext}`);
      const isCpp = ['c++', 'cpp', 'cxx'].includes(normalized);
      const isC = normalized === 'c';
      const isPython = normalized === 'python' || normalized === 'python 3';
      const isJs = ['javascript', 'js', 'node.js'].includes(normalized);
      let command;
      let args;
      let cwd = root;

      if (isPython) {
        const file = sourcePath('.py');
        await fs.writeFile(file, code, 'utf8');
        command = process.env.PYTHON_PATH || 'python';
        args = [file];
      } else if (isJs) {
        const file = sourcePath('.js');
        await fs.writeFile(file, code, 'utf8');
        command = process.execPath;
        args = [file];
      } else if (normalized === 'typescript') {
        const file = sourcePath('.ts');
        const outputDir = path.join(root, 'compiled');
        await fs.writeFile(file, code, 'utf8');
        await fs.mkdir(outputDir);
        const tscScript = process.env.TSC_PATH;
        const compiler = tscScript ? process.execPath : (process.env.TSC_COMPILER || 'tsc');
        const compilerArgs = [...(tscScript ? [tscScript] : []), '--target', 'ES2022', '--module', 'commonjs', '--skipLibCheck', '--outDir', outputDir, file];
        const compiled = await runLocalCommand(compiler, compilerArgs, '', { cwd: root, timeoutMs: 20000, shell: process.platform === 'win32' && !tscScript });
        if (commandUnavailable(compiled)) throw new Error('Install TypeScript (tsc) to run TypeScript test cases.');
        if (compiled.code !== 0) return { compileIssues: parseCommandResult(language, compiled).issues, cases: cases.map(test => ({ name: test.name, input: test.input, expected: test.expected, actual: '', status: 'fail', error: 'Compilation failed; see TypeScript diagnostics.' })) };
        command = process.execPath;
        args = [path.join(outputDir, 'Main.js')];
      } else if (isC || isCpp) {
        const file = sourcePath(isC ? '.c' : '.cpp');
        const binary = path.join(root, process.platform === 'win32' ? 'Main.exe' : 'Main');
        await fs.writeFile(file, code, 'utf8');
        const compiler = isC ? (process.env.C_COMPILER || 'gcc') : (process.env.CXX_COMPILER || 'g++');
        const compileArgs = isC
          ? ['-Wall', '-Wextra', '-Werror', file, '-o', binary]
          : ['-Wall', '-Wextra', '-Werror', '-std=c++17', file, '-o', binary];
        const compiled = await runLocalCommand(compiler, compileArgs, '', { cwd: root, timeoutMs: 15000 });
        if (commandUnavailable(compiled)) throw new Error(`Install ${isC ? 'GCC' : 'G++'} to run ${language} test cases.`);
        if (compiled.code !== 0) return { compileIssues: parseCommandResult(language, compiled).issues, cases: cases.map(test => ({ name: test.name, input: test.input, expected: test.expected, actual: '', status: 'fail', error: 'Compilation failed; see compiler diagnostics.' })) };
        command = binary;
        args = [];
      } else if (normalized === 'java') {
        const className = code.match(/\bclass\s+([A-Za-z_$][\w$]*)/)?.[1] || 'Main';
        const file = path.join(root, `${className}.java`);
        await fs.writeFile(file, code, 'utf8');
        const outputDir = path.join(root, 'classes');
        await fs.mkdir(outputDir);
        const compiled = await runLocalCommand(process.env.JAVAC_PATH || 'javac', ['-proc:none', '-d', outputDir, file], '', { cwd: root, timeoutMs: 15000 });
        if (commandUnavailable(compiled)) throw new Error('Install the JDK to run Java test cases.');
        if (compiled.code !== 0) return { compileIssues: parseCommandResult(language, compiled).issues, cases: cases.map(test => ({ name: test.name, input: test.input, expected: test.expected, actual: '', status: 'fail', error: 'Compilation failed; see compiler diagnostics.' })) };
        command = process.env.JAVA_PATH || 'java';
        args = ['-cp', outputDir, className];
      } else if (normalized === 'go') {
        const file = sourcePath('.go');
        await fs.writeFile(file, code, 'utf8');
        await fs.writeFile(path.join(root, 'go.mod'), 'module localcheck\n\ngo 1.20\n', 'utf8');
        const binary = path.join(root, process.platform === 'win32' ? 'Main.exe' : 'Main');
        const compiled = await runLocalCommand(process.env.GO_COMPILER || 'go', ['build', '-o', binary, file], '', { cwd: root, env: { GOPROXY: 'off', GOTOOLCHAIN: 'local' }, timeoutMs: 30000 });
        if (commandUnavailable(compiled)) throw new Error('Install Go to run Go test cases.');
        if (compiled.code !== 0) return { compileIssues: parseCommandResult(language, compiled).issues, cases: cases.map(test => ({ name: test.name, input: test.input, expected: test.expected, actual: '', status: 'fail', error: 'Compilation failed; see compiler diagnostics.' })) };
        command = binary;
        args = [];
      } else {
        const file = sourcePath('.rs');
        const binary = path.join(root, process.platform === 'win32' ? 'Main.exe' : 'Main');
        await fs.writeFile(file, code, 'utf8');
        const compiled = await runLocalCommand(process.env.RUSTC_COMPILER || 'rustc', [file, '-o', binary], '', { cwd: root, timeoutMs: 30000 });
        if (commandUnavailable(compiled)) throw new Error('Install Rust (rustc) to run Rust test cases.');
        if (compiled.code !== 0) return { compileIssues: parseCommandResult(language, compiled).issues, cases: cases.map(test => ({ name: test.name, input: test.input, expected: test.expected, actual: '', status: 'fail', error: 'Compilation failed; see compiler diagnostics.' })) };
        command = binary;
        args = [];
      }

      const output = [];
      for (const test of cases) {
        const run = await runLocalCommand(command, args, test.input, { cwd, timeoutMs: 5000, maxOutputBytes: 64 * 1024 });
        const actual = run.stdout || '';
        const expected = test.expected.replace(/\r\n/g, '\n').trimEnd();
        const received = actual.replace(/\r\n/g, '\n').trimEnd();
        const error = run.timedOut ? 'Execution exceeded the 5-second time limit.'
          : run.outputLimitExceeded ? 'Output exceeded the 64 KB limit.'
            : run.code !== 0 ? (run.stderr || `Program exited with code ${run.code}.`).trim() : '';
        output.push({ name: test.name, input: test.input, expected: test.expected, actual, status: !error && received === expected ? 'pass' : 'fail', error });
      }
      return { compileIssues: [], cases: output };
    });
    return res.json(results);
  } catch (error) {
    if (error.code === 'ENOENT') return res.status(503).json({ error: `Required compiler/runtime for ${language} is not installed.` });
    return res.status(500).json({ error: error.message });
  }
});

app.post('/api/check-project', async (req, res) => {
  const { language = 'All', level = 'compile' } = req.body;
  if (!['syntax', 'compile', 'lint'].includes(level)) return res.status(400).json({ error: 'Choose syntax, compile/type, or lint check level.' });
  let files;
  try { files = safeProjectFiles(req.body.files); }
  catch (error) { return res.status(400).json({ error: error.message }); }

  try {
    const detected = Object.entries(PROJECT_LANGUAGE_EXTENSIONS)
      .filter(([, extensions]) => files.some(file => extensions.has(path.posix.extname(file.path).toLowerCase())))
      .map(([name]) => name);
    const languages = language === 'All' || language === 'Auto-detect' ? detected : [language];
    if (!languages.length) return res.status(400).json({ error: 'No supported source files were found in the selected project.' });

    const checks = [];
    for (const currentLanguage of languages) {
      const result = await runProjectSyntaxCheck(currentLanguage, files, level);
      if (!result) {
        const message = level === 'lint' && ['Java', 'TypeScript'].includes(currentLanguage)
          ? `No built-in ${currentLanguage} linter is configured.`
          : `No ${level} checker is installed for ${currentLanguage}.`;
        checks.push({ language: currentLanguage, status: 'unavailable', source: null, issues: [], message });
        continue;
      }
      const issues = result.issues.map(issue => ({ ...issue, language: currentLanguage }));
      checks.push({ language: currentLanguage, status: issues.length ? 'errors' : 'pass', source: result.source, issues });
    }
    const allIssues = checks.flatMap(check => check.issues);
    const hasErrors = checks.some(check => check.status === 'errors');
    const hasUnavailable = checks.some(check => check.status === 'unavailable');
    const status = hasErrors ? 'errors' : hasUnavailable ? 'partial' : 'pass';
    return res.json({ status, score: status === 'pass' ? 100 : 0, language: languages.join(', '), level,
      source: checks.map(check => `${check.language}: ${check.source || 'checker unavailable'}`).join(' · '),
      message: status === 'pass' ? `All ${checks.length} language checks passed.` : undefined,
      checks, issues: allIssues });
  } catch (error) {
    return res.status(500).json({ error: `Project check failed: ${error.message}` });
  }
});

app.post('/api/check-code', async (req, res) => {
  const { code, language, filename = '', level = 'compile', model = 'codellama:7b' } = req.body;
  if (typeof code !== 'string' || !code.trim()) {
    return res.status(400).json({ error: 'Code cannot be empty.' });
  }
  if (typeof language !== 'string' || !language.trim()) {
    return res.status(400).json({ error: 'Programming language is required.' });
  }
  if (!['syntax', 'compile', 'lint'].includes(level)) return res.status(400).json({ error: 'Choose syntax, compile/type, or lint check level.' });

  try {
    const localResult = level === 'lint'
      ? await runLintCheck(language, [{ path: filename || `CodeCheck${language === 'Python' ? '.py' : language === 'JavaScript' ? '.js' : language === 'TypeScript' ? '.ts' : language === 'C++' ? '.cpp' : language === 'C' ? '.c' : language === 'Go' ? '.go' : language === 'Rust' ? '.rs' : '.txt'}`, content: code }])
      : await runLocalSyntaxCheck(language, code, filename, level);
    if (localResult) {
      const passed = localResult.issues.length === 0;
      if (level !== 'lint') localResult.source = `${language} ${level === 'syntax' ? 'syntax' : 'compile/type'} checker`;
      return res.json({
        status: passed ? 'pass' : 'errors',
        score: passed ? 100 : 0,
        level,
        language: language.trim(),
        source: localResult.source,
        message: passed
          ? level === 'syntax' ? 'Syntax check passed. No syntax errors found.'
            : level === 'lint' ? 'Lint check passed. No lint or formatting issues were reported.'
              : 'Compile/type check passed. No compile-time errors were reported.'
          : undefined,
        issues: localResult.issues
      });
    }
  } catch (err) {
    return res.status(500).json({ error: `Local ${language} syntax check failed: ${err.message}` });
  }

  const prompt = `You are a careful code checker. Perform a ${level} check of the supplied ${language} code. For lint checks, report actionable lint or formatting problems. For syntax/compile checks, report definite syntax, type, name-resolution, or compile-time errors. Do not report speculative runtime concerns. If the code passes, return no issues. Return valid JSON only, using this schema:
{"issues":[{"line":1,"message":"specific error","fix":"suggested correction"}]}
The line number must refer to the supplied code. Do not claim you compiled or executed the code.

Code:\n${code}`;

  try {
    const ollamaUrl = process.env.OLLAMA_URL || 'http://localhost:11434';
    const response = await fetch(`${ollamaUrl}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model, prompt, stream: false, format: 'json' }),
      signal: AbortSignal.timeout(30000)
    });
    if (!response.ok) throw new Error(`Ollama returned ${response.status}`);

    const data = await response.json();
    const parsed = JSON.parse(data.response);
    const issues = Array.isArray(parsed) ? parsed : parsed.issues;
    if (!Array.isArray(issues)) throw new Error('Model response did not contain an issues array');

    const normalized = issues.map(issue => ({
      line: Number.isInteger(Number(issue.line)) && Number(issue.line) > 0 ? Number(issue.line) : null,
      message: String(issue.message || issue.issue || 'Unspecified error'),
      fix: String(issue.fix || '')
    }));
    const passed = normalized.length === 0;
    return res.json({
      status: passed ? 'pass' : 'errors',
      score: passed ? 100 : 0,
      level,
      language: language.trim(),
      source: `Ollama (${model}) · ${level} review`,
      model,
      issues: normalized
    });
  } catch (err) {
    return res.status(503).json({
      error: `No local syntax checker is available for ${language}, and Ollama could not check the code. Install a language compiler/runtime or start Ollama with the selected model.`,
      detail: err.message
    });
  }
});

app.use('/api', (req, res) => {
  res.status(404).json({ error: `API endpoint not found: ${req.method} ${req.path}` });
});

// Safe fallback for Express v5
app.use((req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, 'localhost', () => {
  console.log(`Server running on port ${PORT}`);
});
