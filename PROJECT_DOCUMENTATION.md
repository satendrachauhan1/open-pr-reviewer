# Code Checker: Project Documentation

## Overview

Code Checker is a local-first web application for checking source code. Users can paste code, upload one source file, or select a project folder. The application reports compiler or parser diagnostics, source locations where available, and a score of 100/100 when the chosen check reports no issues. This score applies only to that check and does not prove expected output or logical correctness.

The app is designed for syntax and compile-time feedback. A passing result is not a proof of correctness, security, or runtime behavior.

## Features

- Source-file upload with language selection based on its extension.
- Automatic language detection for pasted code, with a manual language selector.
- Local single-file checks for Python, JavaScript, C, C++, Java, TypeScript, Go, and Rust when the corresponding tool is installed.
- Local project-folder checks for Python, JavaScript, C, C++, Java, TypeScript, Go, and Rust.
- Mixed-language folders run checks for every detected supported language instead of selecting only the dominant language.
- Syntax, compile/type, and lint/formatting check levels. Lint tools include Ruff, ESLint, cppcheck, `go vet`, and rustfmt where applicable and installed.
- Project files are written to a temporary directory so compilers can resolve local files and imports when the language tool supports it.
- Compiler diagnostics are shown separately, with clickable file/line locations and nearby source when a diagnostic location is available.
- JSON and plain-text report downloads.
- Refresh / Re-run repeats the last check. Up to 20 recent result summaries can be reopened from browser storage; the history stores diagnostics, not source code.
- Line-numbered editor with tab indentation, wrap/font-size controls, and navigation to issue locations.
- User-defined input/expected-output tests for Python, JavaScript, C, C++, Java, Go, and Rust.
- Separate result views for summaries, errors, warnings, and runtime test output.
- Saved project folders and their test cases in browser IndexedDB, plus a built-in runnable sample.
- Download a generated GitHub Actions workflow for the detected project languages. This repository includes a workflow for its own source checks.
- Optional local Ollama fallback for single-file languages without an available local syntax checker.
- GitHub pull request review endpoints and the security heuristic engine remain available in the backend.

## Technology

| Area | Technology |
| --- | --- |
| Web server and API | Node.js, Express |
| Browser UI | HTML, CSS, vanilla JavaScript |
| Python syntax | Python standard library `ast` |
| JavaScript syntax | Node.js `--check` |
| C/C++ checks | GCC/G++ (`-fsyntax-only` for Syntax; temporary object files for Compile; `-Wall -Wextra -Werror` treats compiler warnings as errors) |
| Java compile check | JDK `javac` with annotation processing disabled |
| TypeScript check | TypeScript compiler `tsc --noEmit` |
| Go project check | Go toolchain `go build` with network module lookup disabled |
| Rust project check | `rustc` (local modules; Cargo dependencies are not resolved) |
| Optional AI fallback | Local Ollama HTTP API |

Tools are discovered from the system PATH unless an environment variable overrides their executable. Optional overrides include `PYTHON_PATH`, `C_COMPILER`, `CXX_COMPILER`, `JAVAC_PATH`, `TSC_COMPILER` or `TSC_PATH`, `GO_COMPILER`, `RUSTC_COMPILER`, `RUFF_COMPILER`, `ESLINT_COMPILER`, `CPPCHECK_COMPILER`, and `RUSTFMT_COMPILER`.

## Requirements and setup

Install Node.js 18 or later and npm. From the project directory:

```powershell
npm install
npm start
```

Open `http://localhost:3000`. Stop an existing server with Ctrl+C before restarting if the port is already in use.

Install the language compiler/runtime you need. The app does not install compiler toolchains. Ollama is optional for single-file fallback checks; start Ollama and pull the selected model before using that fallback.

## Using the checker

### Single source file

Choose a file in the left panel. The app reads its text, infers the language from its extension, places the content in the editor, and starts a check. You can also paste code and choose a language manually. The check button sends the code and language to `/api/check-code`.

### Project folder

Choose a folder, and the browser reads up to 100 supported source/config files with a combined limit of 8 MB. It detects all source languages among Python, JavaScript, TypeScript, C, C++, Java, Go, and Rust and submits them together to `/api/check-project`. Every detected language is checked independently. If a checker is missing, that language is marked unavailable and the aggregate result is partial rather than a 100/100 pass.

Supported configuration files are included in the temporary project where the checker uses them (for example, `tsconfig.json` or `go.mod`). Go dependency resolution is configured offline. Dependencies that are not already available may therefore be reported as errors. Rust is checked directly with rustc; external Cargo dependencies are not resolved.

### Check levels, history, and workflow

- **Syntax** asks the language parser/compiler to report syntax issues.
- **Compile / type check** uses the available compiler or type checker without running the resulting program. For interpreted languages, it can overlap with syntax validation.
- **Lint / formatting** uses optional local tools: Ruff for Python, ESLint for JavaScript, cppcheck for C/C++, `go vet` for Go, and rustfmt for Rust. Java and TypeScript linting are not built in. If a linter is missing, a single-file check may use Ollama; project results mark that language unavailable.
- **Refresh / Re-run** repeats the most recently selected single-file or project check.
- **Recent checks** stores up to 20 results in the current browser. It keeps report metadata and diagnostics, not source code.
- **GitHub Actions** downloads a workflow configured for languages detected in the selected folder (or the selected language for a single-file check). Add it to the target repo at `.github/workflows/code-check.yml`.

### Editor, test cases, and saved projects

The editor displays language-aware syntax colors and line numbers, supports Tab indentation and Ctrl+Enter to check, and provides wrap and font-size controls. Clicking a diagnostic location selects that line in the editor. The Try a sample button loads a C++ sum program with a ready-to-run test case.

Add up to 10 test cases. Each case sends standard input to the current editor source and compares standard output with the expected output. The runner supports Python, JavaScript, TypeScript, C, C++, Java, Go, and Rust when their runtimes/toolchains are installed. It compiles once where needed, then allows up to five seconds and 64 KB of output per case. Trailing whitespace is ignored when comparing output. Test execution occurs on the local machine as the same OS user as the app; run only code you trust. The server listens on the loopback hostname (`localhost`). Project test execution currently uses the source currently open in the editor, not a multi-file build.

Use Save project to store the current code or selected project folder together with its test cases in browser IndexedDB. Choose a saved item and press Open to restore it. Saved projects remain in that browser profile and are not uploaded to a server. Recent checks continue to store result metadata and diagnostics in local storage.

### Error context and reports

When a compiler returns a usable file and line location, the UI displays nearby source and highlights the reported line. Select **Download JSON** or **Download report** after a result to save a report. Reports contain metadata and diagnostics, not the source code.

## API

### `POST /api/check-code`

Request:

```json
{
  "code": "console.log('hello');",
  "language": "JavaScript",
  "level": "compile",
  "filename": "example.js",
  "model": "codellama:7b"
}
```

`level` accepts `syntax`, `compile`, or `lint` (default `compile`). `filename` is optional and helps choose the TypeScript/TSX parser mode. A successful response includes `status`, `score`, `language`, `level`, `source`, `message` (on pass), and all collected `issues`. Each issue can include `line`, `message`, and `fix`.

### `POST /api/check-project`

Request:

```json
{
  "language": "JavaScript",
  "level": "compile",
  "files": [
    { "path": "src/main.js", "content": "import './helper.js';" },
    { "path": "src/helper.js", "content": "export const ready = true;" }
  ]
}
```

The route accepts 1–100 allowlisted source/config files totaling no more than 8 MB. Paths must be relative and may not traverse outside the temporary project. `language: "All"` checks each supported language found, and `level` accepts `syntax`, `compile`, or `lint`. The response includes per-language `checks` with `pass`, `errors`, or `unavailable` status and a flattened `issues` list. Issues can include a relative `path` and `language`.

### `POST /api/run-tests`

Accepts `{ "code": "...", "language": "C++", "cases": [{ "name": "sum", "input": "1 2 3", "expected": "6" }] }`. It accepts 1–10 test cases, source up to 100 KB, and input/output expectations up to 16 KB each. Each run has a five-second timeout and 64 KB output limit. It returns each case's status, expected output, actual output, and runtime or compile error details. This endpoint executes code locally and is available only through the loopback server.

### Legacy review routes

- `POST /api/review` reviews a diff with Ollama when available and otherwise uses the local heuristic security scanner.
- `POST /api/fetch-pr` fetches a public GitHub pull request diff.

## Privacy and safety

- The default workflow runs on the user's machine through the local Express server.
- Uploaded/project source is held in memory for the request and written to a temporary directory only while a local compiler needs it; the directory is removed afterward.
- Local compilers are invoked with argument arrays rather than shell command strings.
- The syntax/compile checker does not execute submitted programs. The explicit test runner does execute the current source locally with the app user's permissions; it uses temporary working folders, time limits, and output limits, but it is not an OS-level sandbox. Run only code you trust.
- The Express server binds to `localhost`; the test runner is not intended to be exposed to a network.
- Single-file fallback code is sent to the local Ollama server configured by `OLLAMA_URL` (defaults to `http://localhost:11434`). It is not sent to a hosted model by this application.
- The GitHub PR route makes an outbound request to GitHub for the public diff URL supplied by the user.

## Limits

- A syntax/compile pass does not establish semantic correctness, security, expected output, performance, or runtime behavior.
- Available checks depend on installed compilers and versions. Missing toolchains cause an unavailable response (or a single-file Ollama fallback where supported).
- `node --check` checks JavaScript syntax but does not resolve module imports. TypeScript, Java, and Go checks have greater project awareness when their configuration and dependencies are present. Rust checks do not resolve Cargo dependencies.
- TypeScript checks without a project config use a basic no-emit compiler invocation. Framework-generated types and custom build pipelines may need additional setup.
- Lint tools are optional and language-specific. Java and TypeScript lint checks are not built in; unavailable tools must not be read as a pass.
- The generated GitHub Actions workflow runs checks on pushes and pull requests. Review it before enabling it on repositories accepting untrusted contributions; build tools such as Cargo can run build scripts.
- Files with unsupported extensions, binaries, and files beyond the size/count limits are not included.
- AI fallback is an estimate, not a compiler result. It can miss errors or produce incorrect diagnostics.

## Judge demonstration outline

1. Load the built-in sample and demonstrate its input/expected-output test case.
2. Introduce a syntax error and show the file/line diagnostic and source context.
3. Save the project, reload it, and demonstrate the test case is restored.
4. Select a mixed-language folder and show the per-language pass/error/unavailable summaries.
5. Switch between check levels, use the result tabs, and reopen a prior result.
6. Download the JSON/text report and GitHub Actions workflow.
7. Explain the local execution safety limits and that test running is separate from compile checking.

## License

MIT. See [LICENSE](LICENSE).
