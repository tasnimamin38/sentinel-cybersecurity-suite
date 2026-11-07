import re
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
ACTION_LINE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
IMMUTABLE_ACTION_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")
DEPENDENCY_REVIEW_ACTION = (
    "actions/dependency-review-action@a1d282b36b6f3519aa1f3fc636f609c47dddb294"
)


def test_ci_produces_every_required_main_branch_context():
    workflow = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    required = (
        "Backend security and tests (Python " + "$" + "{{ matrix.python-version }})",
        'python-version: ["3.12", "3.13"]',
        "Frontend security and build",
        "Container image and Compose validation",
    )
    for context in required:
        assert context in workflow, f"Main branch required check is missing: {context}"


def test_codeql_and_trivy_publish_security_check_runs():
    codeql = (WORKFLOW_ROOT / "codeql.yml").read_text(encoding="utf-8")
    supply_chain = (WORKFLOW_ROOT / "supply-chain-security.yml").read_text(encoding="utf-8")
    assert "name: CodeQL" in codeql
    assert "matrix.language" in codeql
    assert "security-events: write" in codeql
    assert "upload-sarif@" in supply_chain
    assert "category: trivy-filesystem" in supply_chain
    assert "severity: HIGH,CRITICAL" in supply_chain


def test_dependency_review_is_a_required_pull_request_gate():
    workflow = (WORKFLOW_ROOT / "supply-chain-security.yml").read_text(encoding="utf-8")
    assert "dependency-review-diff:" in workflow
    assert "name: Review pull-request dependency changes" in workflow
    assert DEPENDENCY_REVIEW_ACTION in workflow
    assert "fail-on-severity: high" in workflow
    assert "license-check: false" in workflow
    assert "pip-audit -r backend/requirements.txt" in workflow
    assert "npm audit --audit-level=high" in workflow


def test_every_third_party_workflow_action_uses_a_full_commit_sha():
    workflow_files = sorted(WORKFLOW_ROOT.glob("*.yml")) + sorted(WORKFLOW_ROOT.glob("*.yaml"))
    assert workflow_files, "GitHub Actions workflows must be present."
    unpinned = []
    for workflow in workflow_files:
        source = workflow.read_text(encoding="utf-8")
        for reference in ACTION_LINE.findall(source):
            if reference.startswith("./"):
                continue
            if not IMMUTABLE_ACTION_REF.fullmatch(reference):
                unpinned.append(f"{workflow.relative_to(REPOSITORY_ROOT)}: {reference}")
    assert not unpinned, "Unpinned GitHub Actions references:\n" + "\n".join(unpinned)


def test_backend_image_uses_patched_python_without_runtime_build_tools():
    dockerfile = (REPOSITORY_ROOT / "backend" / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.13.18-slim-trixie AS builder" in dockerfile
    assert "FROM debian:trixie-slim AS runtime" in dockerfile
    assert "setuptools>=78.1.1" in dockerfile
    assert "python -m pip uninstall --yes pip setuptools wheel" in dockerfile
    assert (
        'find_spec(name) is None for name in ("pip", "setuptools", "wheel", "ensurepip")'
        in dockerfile
    )


def test_tls_probes_require_tls_1_2_or_newer():
    tls_clients = (
        REPOSITORY_ROOT / "backend/app/services/tls.py",
        REPOSITORY_ROOT / "backend/app/services/https_probe.py",
    )
    for client in tls_clients:
        source = client.read_text(encoding="utf-8")
        assert "context.minimum_version = ssl.TLSVersion.TLSv1_2" in source


def test_dependabot_monitors_all_dockerfile_and_compose_locations():
    config = (REPOSITORY_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    docker_sections = config.split("  - package-ecosystem: docker")[1:]
    docker_directories = {
        section.split("directory:", 1)[1].splitlines()[0].strip()
        for section in docker_sections
        if "directory:" in section
    }
    assert docker_directories == {"/backend", "/frontend", "/"}

