import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
ACTION_LINE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
IMMUTABLE_ACTION_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")
DEPENDENCY_REVIEW_ACTION = (
    "actions/dependency-review-action@"
    "a1d282b36b6f3519aa1f3fc636f609c47dddb294"
)


def test_every_workflow_action_uses_an_immutable_commit_sha():
    workflow_files = sorted(WORKFLOW_ROOT.glob("*.yml")) + sorted(WORKFLOW_ROOT.glob("*.yaml"))
    assert workflow_files, "GitHub Actions workflows must be present."

    unpinned = []
    for workflow in workflow_files:
        content = workflow.read_text(encoding="utf-8")
        for reference in ACTION_LINE.findall(content):
            if reference.startswith("./"):
                continue
            if not IMMUTABLE_ACTION_REF.fullmatch(reference):
                unpinned.append(f"{workflow.relative_to(REPOSITORY_ROOT)}: {reference}")

    message = "Every third-party action must use a full commit SHA:\n" + "\n".join(unpinned)
    assert not unpinned, message


def test_supply_chain_workflow_enforces_security_gates():
    workflow = (WORKFLOW_ROOT / "supply-chain-security.yml").read_text(encoding="utf-8")
    required_controls = (
        "Dependency Graph-independent",
        "pip-audit -r backend/requirements.txt",
        "npm audit --audit-level=high",
        "gitleaks/gitleaks-action@",
        "aquasecurity/trivy-action@",
        "anchore/sbom-action@",
        "scanners: vuln,misconfig,secret,license",
        "severity: HIGH,CRITICAL",
        "exit-code: '1'",
        "security-events: write",
        "GITLEAKS_ENABLE_COMMENTS: 'false'",
        "upload-release-assets: false",
        "trivy-results.sarif",
        "sentinel-trivy-filesystem-sarif",
        "actions/upload-artifact@",
    )
    for control in required_controls:
        assert control in workflow, f"Required supply-chain control missing: {control}"

    # Review only pull-request dependency changes; keep the full-manifest audits too.
    assert "dependency-review-diff:" in workflow
    assert DEPENDENCY_REVIEW_ACTION in workflow
    assert "fail-on-severity: high" in workflow
    assert "license-check: false" in workflow
    assert "comment-summary-in-pr: never" in workflow


def test_container_images_are_scanned_after_build():
    workflow = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    assert workflow.index("Build backend image") < workflow.index("Scan backend image")
    assert workflow.index("Build frontend image") < workflow.index("Scan frontend image")
    assert workflow.count("aquasecurity/trivy-action@") == 2
    assert workflow.count("severity: HIGH,CRITICAL") >= 2


def test_dependabot_updates_all_manifest_ecosystems():
    config = (REPOSITORY_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    for ecosystem, directory in (
        ("pip", "/backend"),
        ("npm", "/frontend"),
        ("github-actions", "/"),
    ):
        assert f"package-ecosystem: {ecosystem}" in config
        assert f"directory: {directory}" in config

    # Preserve Docker image update coverage for both Dockerfiles and root Compose.
    docker_sections = config.split("  - package-ecosystem: docker")[1:]
    docker_directories = {
        section.split("directory:", 1)[1].splitlines()[0].strip()
        for section in docker_sections
        if "directory:" in section
    }
    assert docker_directories == {"/backend", "/frontend", "/"}


def test_backend_image_uses_multistage_patched_python_runtime():
    dockerfile = (REPOSITORY_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.13.18-slim-trixie AS builder" in dockerfile
    assert "FROM debian:trixie-slim AS runtime" in dockerfile
    assert "COPY --from=builder /usr/local /usr/local" in dockerfile
    assert "COPY --from=builder --chown=10001:10001 /srv/backend /srv/backend" in dockerfile
    assert "setuptools>=78.1.1" in dockerfile
    assert "python3.13-venv" not in dockerfile
    assert "groupadd" not in dockerfile
    assert "passwd" not in dockerfile


def test_backend_ci_covers_python_312_and_313():
    workflow = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    assert 'python-version: ["3.12", "3.13"]' in workflow


def test_workflows_avoid_duplicate_feature_branch_push_runs():
    for workflow_name in ("ci.yml", "codeql.yml", "supply-chain-security.yml"):
        workflow = (WORKFLOW_ROOT / workflow_name).read_text(encoding="utf-8")
        push_section = workflow.split("  push:", 1)[1].split("  pull_request:", 1)[0]
        assert "branches: [main]" in push_section
        assert "feat/sentinel-*" not in push_section
        assert (
            "branches: [main, 'feat/sentinel-*', 'fix/sentinel-*']"
            in workflow.split("  pull_request:", 1)[1]
        )


def test_final_backend_runtime_image_excludes_python_build_tools():
    dockerfile = (REPOSITORY_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "python -m pip uninstall --yes pip setuptools wheel" in dockerfile
    assert "rm -rf /usr/local/lib/python3.13/ensurepip" in dockerfile
    assert (
        'find_spec(name) is None for name in ("pip", "setuptools", "wheel", "ensurepip")'
        in dockerfile
    )
