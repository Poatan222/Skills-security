#!/usr/bin/env bash
set -e

CLAUDE_DIR="$HOME/.claude"
SKILLS_DIR="$CLAUDE_DIR/skills"

# When piped via curl | bash, BASH_SOURCE[0] is empty.
# Detect this and clone the repo to a temp dir instead.
if [[ -z "${BASH_SOURCE[0]}" || "${BASH_SOURCE[0]}" == "bash" || "${BASH_SOURCE[0]}" == "/dev/stdin" ]]; then
  TMPDIR="$(mktemp -d)"
  echo "[>] Cloning Skills-security to $TMPDIR..."
  git clone --depth=1 https://github.com/Poatan222/Skills-security.git "$TMPDIR/repo" 2>/dev/null
  REPO_DIR="$TMPDIR/repo"
else
  REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  Claude Code Security Suite — Installer  ║"
echo "╚══════════════════════════════════════════╝"
echo ""
echo "Repo dir: $REPO_DIR"
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
echo "✓ Installation complete — $SKILLS_DIR"
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
echo "  /sec cspm <output>      Cloud security posture"
echo "  /sec report <findings>  PDF report generation"
echo ""
echo "Optional: pip install reportlab  (PDF reports)"
echo "Optional: brew install subfinder amass syft trivy"
echo ""
