from pathlib import Path
import re


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_ROOT = REPOSITORY_ROOT / ".github" / "workflows"
ACTION_LINE = re.compile(r"^\s*uses:\s*([^\s#]+)", re.MULTILINE)
IMMUTABLE_ACTION_REF = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def test_every_workflow_action_uses_an_immutable_commit_sha():
    workflow_files = sorted(WORKFLOW_ROOT.glob("*.yml")) + sorted(
        WORKFLOW_ROOT.glob("*.yaml")
    )
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
        "actions/dependency-review-action@",
        "gitleaks/gitleaks-action@",
        "aquasecurity/trivy-action@",
        "anchore/sbom-action@",
        "scanners: vuln,misconfig,secret,license",
        "severity: HIGH,CRITICAL",
        "exit-code: '1'",
        "security-events: write",
        "GITLEAKS_ENABLE_COMMENTS: 'false'",
        "upload-release-assets: false",
    )
    for control in required_controls:
        assert control in workflow, f"Required supply-chain control missing: {control}"


def test_container_images_are_scanned_after_build():
    workflow = (WORKFLOW_ROOT / "ci.yml").read_text(encoding="utf-8")
    assert workflow.index("Build backend image") < workflow.index("Scan backend image")
    assert workflow.index("Build frontend image") < workflow.index("Scan frontend image")
    assert workflow.count("aquasecurity/trivy-action@") == 2
    assert workflow.count("severity: HIGH,CRITICAL") >= 2


def test_dependabot_updates_all_manifest_ecosystems():
    config = (REPOSITORY_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    for ecosystem, directory in (("pip", "/backend"), ("npm", "/frontend"), ("github-actions", "/")):
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
