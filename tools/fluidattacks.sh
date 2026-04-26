#!/usr/bin/env bash

# Fluid Attacks SAST scanner (CASA compliance)
# Outputs SARIF report to ./Fluid-Attacks-Results.json and stdout

set -e

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

# Generate config (outputs to current directory)
cat > config.yaml << 'EOF'
namespace: casa-scan
tracing_opt_out: True
output:
  file_path: ./Fluid-Attacks-Results.json
  format: SARIF
working_dir: .
sast:
  include:
    - .
  exclude:
    - glob(**.venv/**)
    - glob(**node_modules/**)
    - glob(**dist/**)
    - glob(**build/**)
    - glob(**__pycache__/**)
language: EN
EOF

echo "Running Fluid Attacks SAST scanner..."
docker run --rm -v "$ROOT_DIR:/src" fluidattacks/sast:latest sast scan /src/config.yaml

# Display results summary
if [ -f Fluid-Attacks-Results.json ]; then
  echo ""
  echo "═══ Fluid Attacks Results ═══"
  echo "Full report: Fluid-Attacks-Results.json"
  echo ""
  
  # Show summary using Python (if available)
  if command -v python3 >/dev/null 2>&1; then
    python3 << 'PYEOF'
import json
import sys

try:
    with open('Fluid-Attacks-Results.json', 'r') as f:
        data = json.load(f)
    
    results = data['runs'][0]['results']
    print(f"Total findings: {len(results)}")
    
    if results:
        print("\nFindings by severity:")
        levels = {}
        for r in results:
            level = r.get('level', 'unknown')
            levels[level] = levels.get(level, 0) + 1
        
        for level, count in sorted(levels.items()):
            print(f"  {level.upper()}: {count}")
        
        print("\nTop findings:")
        for i, result in enumerate(results[:5], 1):
            rule_id = result['ruleId']
            location = result['locations'][0]['physicalLocation']['artifactLocation']['uri']
            line = result['locations'][0]['physicalLocation']['region']['startLine']
            message = result['message']['text']
            print(f"{i}. Rule {rule_id}: {location}:{line}")
            print(f"   {message}")
        
        if len(results) > 5:
            print(f"\n... and {len(results) - 5} more findings")
        
        sys.exit(1 if results else 0)
    else:
        print("✓ No vulnerabilities found")
        sys.exit(0)
        
except Exception as e:
    print(f"Error parsing results: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF
  else
    # Fallback: just cat the JSON
    cat Fluid-Attacks-Results.json
  fi
else
  echo "✗ Fluid-Attacks-Results.json not generated"
  exit 1
fi


