"""Pentora tool installer — setup, doctor, update."""
from __future__ import annotations

import shutil
import subprocess

GO_TOOLS: dict[str, str] = {
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "dalfox": "github.com/hahwul/dalfox/v2@latest",
    "waybackurls": "github.com/tomnomnom/waybackurls@latest",
    "hakrawler": "github.com/hakluke/hakrawler@latest",
    "interactsh-client": "github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest",
    "gau": "github.com/lc/gau/v2/cmd/gau@latest",
    "subzy": "github.com/PentestPad/subzy@latest",
    "dnsx": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
    "naabu": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    "mapcidr": "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
    "chaos": "github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
}

PIP_TOOLS: list[str] = [
    "arjun",
    "paramspider",
    "xsstrike",
    "commix",
    "wafw00f",
    "Sublist3r",
    "theHarvester",
    "tplmap",
]

GIT_TOOLS: dict[str, str] = {
    "LinkFinder": "https://github.com/GerbenJavado/LinkFinder",
    "SecretFinder": "https://github.com/m4ll0k/SecretFinder",
    "Ghauri": "https://github.com/r0oth3x49/ghauri",
    "graphw00f": "https://github.com/nicowillis/graphw00f",
    "jwt_tool": "https://github.com/ticarpi/jwt_tool",
    "Smuggler": "https://github.com/defparam/smuggler",
}

DOCKER_IMAGES: list[str] = [
    "opensecurity/mobile-security-framework-mobsf:latest",
]


def _run_cmd(cmd: list[str]) -> bool:
    """Run a shell command, return True on success."""
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=300)  # noqa: S603
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return False


def _info(msg: str) -> None:
    print(msg)  # noqa: T201


def run_installer(skip_go: bool = False, skip_docker: bool = False) -> None:
    """Install all required tools."""
    if not skip_go:
        for tool, pkg in GO_TOOLS.items():
            if shutil.which(tool):
                _info(f"  [skip] {tool} already installed")
                continue
            _info(f"  [go install] {tool}...")
            ok = _run_cmd(["go", "install", pkg])  # noqa: S603
            _info(f"  {'[ok]' if ok else '[fail]'} {tool}")

    for tool in PIP_TOOLS:
        tool_name = tool.lower()
        if shutil.which(tool_name):
            _info(f"  [skip] {tool} already installed")
            continue
        _info(f"  [pip install] {tool}...")
        ok = _run_cmd(["pip", "install", tool])  # noqa: S603
        _info(f"  {'[ok]' if ok else '[fail]'} {tool}")

    if not skip_docker:
        for image in DOCKER_IMAGES:
            _info(f"  [docker pull] {image}...")
            ok = _run_cmd(["docker", "pull", image])  # noqa: S603
            _info(f"  {'[ok]' if ok else '[fail]'} {image}")


def run_doctor() -> int:
    """Check for all required tools. Return count of missing tools."""
    all_tools = list(GO_TOOLS.keys()) + [t.lower() for t in PIP_TOOLS]
    missing = 0
    for tool in all_tools:
        found = shutil.which(tool)
        status = "ok" if found else "MISSING"
        _info(f"  {tool:<30} {status}")
        if not found:
            missing += 1
    _info(f"\n{missing} tool(s) missing.")
    return missing
