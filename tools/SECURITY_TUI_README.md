# Security Findings TUI - Universal SARIF/Security Report Viewer

**Portable**, interactive terminal UI for viewing security scan results from any tool.

## ✨ Features

- 🎯 **Universal SARIF support** - Works with Fluid Attacks, Semgrep, CodeQL, Snyk, Trivy, and more
- 🖱️ **Mouse + keyboard** - Click or use shortcuts
- 📋 **AI-ready** - Copy findings as formatted prompts for AI chat
- 📂 **IDE integration** - Open files in Cursor/VSCode at exact line
- 🎨 **Color-coded** - Severity-based highlighting
- 🔍 **Preview pane** - See code context and remediation
- 📊 **Statistics** - Dashboard with findings breakdown
- 🔄 **Auto-discovery** - Finds all reports in current directory

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
pip install textual rich

# Or use requirements file
pip install -r requirements.txt
```

### Usage

```bash
# Auto-discover all security reports in current directory
python security_tui.py

# View specific SARIF file (any tool!)
python security_tui.py report.sarif
python security_tui.py semgrep-results.json
python security_tui.py snyk-scan.sarif

# View ZAP XML
python security_tui.py zap-results.xml

# Multiple files at once
python security_tui.py scan1.sarif scan2.xml

# Force format detection
python security_tui.py --format sarif custom-report.json
```

## 🎮 Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑`/`↓` or mouse | Navigate findings |
| `Enter` or click | Select finding |
| `c` | Copy to clipboard (formatted for AI) |
| `o` | Open file in Cursor at line |
| `r` | Refresh findings |
| `q` | Quit |
| `?` | Show help |

## 📊 Supported Formats

### SARIF (Static Analysis Results Interchange Format)

Works with **any tool** that outputs SARIF:

- ✅ **Fluid Attacks** - SAST scanner
- ✅ **Semgrep** - Pattern-based code analysis
- ✅ **CodeQL** - GitHub's semantic code analysis
- ✅ **Snyk** - Dependency vulnerabilities
- ✅ **Trivy** - Container/IaC scanning
- ✅ **ESLint** (with SARIF formatter)
- ✅ **Bandit** (with SARIF output)
- ✅ **Many more** - Any SARIF 2.1.0 compliant tool

### ZAP XML

- ✅ **OWASP ZAP** - Dynamic application security testing

## 🔧 Integration Examples

### With Semgrep

```bash
# Run Semgrep and save SARIF
semgrep --config=auto --sarif -o semgrep.sarif .

# View in TUI
python security_tui.py semgrep.sarif
```

### With CodeQL

```bash
# Run CodeQL analysis
codeql database analyze my-db --format=sarif-latest --output=codeql.sarif

# View in TUI
python security_tui.py codeql.sarif
```

### With Snyk

```bash
# Scan dependencies
snyk test --sarif-file-output=snyk.sarif

# View in TUI
python security_tui.py snyk.sarif
```

### With Trivy

```bash
# Scan container or filesystem
trivy fs --format sarif --output trivy.sarif .

# View in TUI
python security_tui.py trivy.sarif
```

### With ESLint

```bash
# Install SARIF formatter
npm install -g @microsoft/eslint-formatter-sarif

# Run ESLint with SARIF output
eslint . --format @microsoft/eslint-formatter-sarif --output-file eslint.sarif

# View in TUI
python security_tui.py eslint.sarif
```

## 🎯 Workflow: TUI → AI Chat

Perfect for AI-assisted security fixing:

1. **Run scans** (any tool that outputs SARIF)
2. **Open TUI**: `python security_tui.py`
3. **Select a finding** (click or arrow keys)
4. **Press `c`** to copy formatted prompt
5. **Paste into Cursor/ChatGPT** → AI generates fix
6. Or press `o` to jump directly to the code

### Example Copied Prompt

```
Fix this security issue:

Tool: Semgrep
Severity: 🟠 High
Issue: SQL Injection
Location: app/api.py:142
CWE: CWE-89

Description:
User input is directly concatenated into SQL query without sanitization...

Code:
```python
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
```

Remediation:
Use parameterized queries to prevent SQL injection attacks.

```

## 🌍 Use in Any Project

This tool is **completely portable**! You can:

1. **Copy to any project**:
   ```bash
   cp security_tui.py ~/your-project/
   cd ~/your-project
   python security_tui.py
   ```

1. **Install globally**:

   ```bash
   cp security_tui.py ~/bin/security-viewer
   chmod +x ~/bin/security-viewer
   # Now run from anywhere
   cd any-project
   security-viewer
   ```

2. **Use as a library**:

   ```python
   from security_tui import FindingsParser, FindingsViewer
   
   findings = FindingsParser.parse_sarif("report.sarif")
   app = FindingsViewer(findings)
   app.run()
   ```

## 📦 Requirements

```txt
textual>=0.47.0
rich>=13.0.0
```

## 🎨 Customization

The TUI is highly customizable through CSS. See the `FindingsViewer.CSS` property in the source code.

## 🐛 Troubleshooting

### "No findings found"

- Check that your SARIF file is valid: `python -m json.tool report.sarif`
- Make sure it has a `runs` array with `results`
- Try forcing format: `--format sarif`

### "Unknown file type"

- SARIF files should end in `.sarif` or `.json`
- XML files should end in `.xml`
- Use `--format` to force detection

### Clipboard not working

- **macOS**: Should work out of the box (uses `pbcopy`)
- **Linux**: Install `xclip` (`apt install xclip`)
- **Windows**: May not be supported yet

### Cursor integration not working

- Make sure `cursor` CLI is installed
- Try `cursor --goto file.py:10` manually to test
- Fallback to `code` (VSCode) is automatic

## 📄 License

This tool is part of the Lazeport project but can be used standalone in any project.

## 🤝 Contributing

This is a single-file tool designed to be portable. Feel free to:

- Copy it to your projects
- Modify for your needs
- Share improvements back

## 🔗 Related Tools

- [SARIF Multitool](https://github.com/microsoft/sarif-sdk) - Official SARIF utilities
- [SARIF Viewer VSCode Extension](https://marketplace.visualstudio.com/items?itemName=MS-SarifVSCode.sarif-viewer)
- [Semgrep](https://semgrep.dev/) - Fast pattern-based SAST
- [Trivy](https://trivy.dev/) - Container/IaC security scanner
