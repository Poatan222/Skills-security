#!/usr/bin/env bash
set -e

CLAUDE_DIR="$HOME/.claude"
SKILLS_DIR="$CLAUDE_DIR/skills"

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Claude Code Security Suite — Installer  ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Detect if running via curl | bash (no real script path available)
# $0 will be "bash" or "-bash" when piped, not a file path
SCRIPT_PATH="${BASH_SOURCE[0]:-$0}"

if [[ "$SCRIPT_PATH" == "bash" || "$SCRIPT_PATH" == "-bash" || "$SCRIPT_PATH" == "/dev/stdin" || -z "$SCRIPT_PATH" ]]; then
  INSTALL_TMPDIR="$(mktemp -d /tmp/sec-suite-XXXXXX)"
  echo "[>] Detected pipe mode — cloning repo to $INSTALL_TMPDIR..."
  git clone --depth=1 https://github.com/Poatan222/Skills-security.git "$INSTALL_TMPDIR/repo"
  REPO_DIR="$INSTALL_TMPDIR/repo"
else
  REPO_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
fi

echo "[>] Installing from: $REPO_DIR"
echo ""

mkdir -p "$SKILLS_DIR"
mkdir -p "$CLAUDE_DIR/agents"

# Main orchestrator
echo "[>] Installing /sec orchestrator..."
mkdir -p "$SKILLS_DIR/sec"
cp "$REPO_DIR/sec/SKILL.md" "$SKILLS_DIR/sec/SKILL.md"

# New sub-skills
NEW_SKILLS=("sec-recon" "sec-iac" "sec-container" "sec-ir" "sec-dast" "sec-cicd" "sec-sbom" "sec-report-pdf")
for skill in "${NEW_SKILLS[@]}"; do
  if [ -d "$REPO_DIR/skills/$skill" ]; then
    echo "[>] Installing: $skill"
    mkdir -p "$SKILLS_DIR/$skill"
    cp -r "$REPO_DIR/skills/$skill/." "$SKILLS_DIR/$skill/"
  else
    echo "[!] Skipping $skill (not found in $REPO_DIR/skills/)"
  fi
done

# Existing skills
EXISTING=("api-pentest" "vuln-triage" "threat-modeling" "cspm-prowler" "secure-code-review")
for skill in "${EXISTING[@]}"; do
  if [ -d "$REPO_DIR/$skill" ]; then
    echo "[>] Installing: $skill"
    mkdir -p "$SKILLS_DIR/$skill"
    cp -r "$REPO_DIR/$skill/." "$SKILLS_DIR/$skill/"
  fi
done

echo ""
echo "✓ Installation complete"
echo "  Skills installed to: $SKILLS_DIR"
echo ""
echo "Commands available in Claude Code:"
echo "  /sec audit <target>     Full engagement (4 parallel agents)"
echo "  /sec recon <target>     Attack surface recon"
echo "  /sec dast <url>         Web app security testing"
echo "  /sec iac <path>         IaC security review"
echo "  /sec container <image>  Container security"
echo "  /sec ir <logs>          Incident response triage"
echo "  /sec cicd <repo>        CI/CD pipeline security"
echo "  /sec sbom <manifest>    Dependency risk analysis"
echo "  /sec api <url>          API penetration testing"
echo "  /sec code <file>        Secure code review"
echo "  /sec triage <scan>      Vulnerability triage"
echo "  /sec threat <arch>      Threat modeling"
echo "  /sec report <findings>  PDF report generation"
echo ""
echo "Optional: pip install reportlab  (enables PDF reports)"
echo "Optional: brew install subfinder amass syft trivy"
echo ""
