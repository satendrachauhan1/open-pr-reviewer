# Code Checker

A local-first code review workspace. Edit snippets, check source files and projects, run input/output cases, and review diagnostics in the browser.

## Features

- Upload a source file or paste code directly.
- Detect common languages from file extensions and code patterns.
- Run local syntax checks for Python, JavaScript, C, C++, and Java when their tools are installed; TypeScript, Go, and Rust checks are enabled when their toolchains are installed.
- Check all detected supported languages in a project folder. Compilers can resolve project files and imports where their normal build/check commands support it.
- Show diagnostics with line context when the checker supplies a location, and download a JSON or text report.
- Check syntax, compile/type rules, or lint/formatting rules; mixed-language folders run checks for each detected supported language.
- Re-run the active check with Refresh, revisit recent results stored in the browser, and download a GitHub Actions workflow for detected project languages.
- Edit in a syntax-colored, line-numbered editor with indentation, wrapping, font-size controls, and source-line navigation.
- Save and reopen projects locally in browser storage, including their test cases.
- Run up to 10 input/expected-output cases for Python, JavaScript, TypeScript, C, C++, Java, Go, and Rust.
- Review summary, errors, warnings, and test output in separate result views; try the built-in sample.
- Optionally use a local Ollama model for single-file languages without an installed checker.

## Quick start

Requirements: Node.js 18+ and npm. Install the compiler/runtime for each language you want checked: Python, Node.js, GCC, G++, JDK, TypeScript (`tsc`), Go, and/or Rust (`rustc`). Install optional lint tools separately: Ruff, ESLint 9+, cppcheck, Go, and rustfmt. Ollama is optional for single-file checks where a local checker is unavailable.

```powershell
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000). If port 3000 is already in use, stop the existing server with **Ctrl+C** in its terminal before restarting.

For AI fallback on other languages, install and run [Ollama](https://ollama.com/), then install a model such as:

```powershell
ollama pull codellama:7b
```

## How checking works

Python uses the standard-library `ast` parser; JavaScript uses Node.js syntax-check mode; C/C++ use GCC/G++ syntax-only mode for Syntax and object compilation for Compile; Java uses `javac`; TypeScript uses `tsc --noEmit`; Go uses `go build`; and Rust uses `rustc`. Project checks pass files from every detected supported language to the relevant compiler/checker. Compiled outputs and temporary project copies are kept in a temporary directory and removed after checking. The separate test runner executes the current editor code locally with a 5-second timeout and a 64 KB output cap per case. Run only code you trust: it executes with the same permissions as the app. The compiler checker itself does not run submitted programs or Cargo build scripts. Rust checks do not resolve Cargo dependencies. Other languages use the selected local Ollama model for single-file checks when available. Without a checker or Ollama, the app returns an unavailable error rather than a false pass.

A pass means every requested checker reported no issues within its scope. A partial project result means one or more required language tools were unavailable and does not receive a passing score. Results do not prove that the program is logically correct, secure, or will run successfully. JSX/TSX, framework-specific code, and nonstandard build systems may require project configuration. Linting requires the relevant local tool (Ruff, ESLint, cppcheck, go vet, or rustfmt); Java and TypeScript linting are not built in.

The UI can download a language-specific GitHub Actions workflow for pull requests and pushes. This repository also has its own source-syntax workflow in `.github/workflows/code-check.yml`.

## Documentation

See [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md) for the full architecture, toolchain, setup, API schema, privacy behavior, limitations, and judge demo.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
