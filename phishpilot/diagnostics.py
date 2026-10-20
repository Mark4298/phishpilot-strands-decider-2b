"""Read-only, standard-library diagnostics for PhishPilot's local prerequisites.

The default report is offline. The optional health check can contact only an
IP-literal loopback endpoint and never submits an inference request.
"""

from __future__ import annotations

import argparse
import ctypes
import importlib.metadata
import ipaddress
import math
import os
import stat
import sys
import tomllib
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from phishpilot.errors import ValidationError
from phishpilot.integrations.decider_http import (
    DEFAULT_DECIDER_URL,
    DEFAULT_TIMEOUT_SECONDS,
    DeciderHttpClient,
)

GIB = 1024**3
MIN_STARTUP_HEADROOM_BYTES = 10 * GIB
MAX_MEMORY_LOAD_PERCENT = 90.0
HEALTH_TIMEOUT_SECONDS = 2.0
RUNTIME_PACKAGES = (
    "strands-agents",
    "strands-decider",
    "streamlit",
    "boto3",
    "requests",
    "pydantic",
    "python-dotenv",
)
MODEL_RUNTIME_PACKAGES = ("torch", "transformers", "peft", "accelerate")
DEVELOPMENT_PACKAGES = ("pytest", "pytest-cov", "ruff")
EXPECTED_MODEL_REPOSITORIES = (
    "StrandsAgents/strands-decider-2B-hobson-v19",
    "Qwen/Qwen3.5-2B-Base",
)

Status = Literal["READY", "BLOCKED", "UNKNOWN"]


@dataclass(frozen=True, slots=True)
class MemoryInfo:
    total_bytes: int
    available_bytes: int
    load_percent: float

    def __post_init__(self) -> None:
        if (
            isinstance(self.total_bytes, bool)
            or isinstance(self.available_bytes, bool)
            or not isinstance(self.total_bytes, int)
            or not isinstance(self.available_bytes, int)
            or self.total_bytes <= 0
            or not 0 <= self.available_bytes <= self.total_bytes
        ):
            raise ValueError("memory byte counts are invalid")
        if (
            isinstance(self.load_percent, bool)
            or not isinstance(self.load_percent, (int, float))
            or not math.isfinite(float(self.load_percent))
            or not 0.0 <= float(self.load_percent) <= 100.0
        ):
            raise ValueError("memory load must be between 0 and 100")


@dataclass(frozen=True, slots=True)
class ReadinessCheck:
    name: str
    status: Status
    detail: str


@dataclass(frozen=True, slots=True)
class DiagnosticsReport:
    python_version: str
    python_requirement: str | None
    python_compatible: bool | None
    package_versions: Mapping[str, str | None]
    environment_present: Mapping[str, bool]
    decider_endpoint: str | None
    decider_timeout_seconds: float | None
    decider_configuration_valid: bool
    model_caches: Mapping[str, bool | None]
    memory: MemoryInfo | None
    memory_error: str | None
    health_checked: bool
    health_available: bool | None
    health_detail: str | None
    checks: tuple[ReadinessCheck, ...]
    local_preflight_status: Status


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def read_memory_info() -> MemoryInfo:
    """Read physical memory totals without elevation or changing system state."""
    if os.name == "nt":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if not kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            error_code = ctypes.get_last_error()
            if error_code == 5:
                raise PermissionError("GlobalMemoryStatusEx access denied")
            raise OSError(error_code, "GlobalMemoryStatusEx failed")
        return MemoryInfo(
            total_bytes=int(status.ullTotalPhys),
            available_bytes=int(status.ullAvailPhys),
            load_percent=float(status.dwMemoryLoad),
        )

    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        values: dict[str, int] = {}
        with meminfo.open(encoding="ascii") as source:
            for line in source:
                key, separator, remainder = line.partition(":")
                if separator and key in {"MemTotal", "MemAvailable"}:
                    values[key] = int(remainder.strip().split()[0]) * 1024
        try:
            total = values["MemTotal"]
            available = values["MemAvailable"]
        except KeyError as exc:
            raise OSError("physical memory counters are incomplete") from exc
        return MemoryInfo(total, available, (1 - available / total) * 100)

    try:
        total = int(os.sysconf("SC_PHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
        available = int(os.sysconf("SC_AVPHYS_PAGES") * os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, OSError, ValueError) as exc:
        raise OSError("physical memory counters are unavailable") from exc
    return MemoryInfo(total, available, (1 - available / total) * 100)


def _version_tuple(value: str) -> tuple[int, ...] | None:
    try:
        parts = tuple(int(part) for part in value.split("."))
    except (TypeError, ValueError):
        return None
    return parts if parts and all(part >= 0 for part in parts) else None


def _python_satisfies(version: tuple[int, ...], requirement: str) -> bool | None:
    """Evaluate simple comma-separated Python version clauses from pyproject.toml."""
    operators = (">=", "<=", "==", "!=", ">", "<")
    for clause in requirement.split(","):
        clause = clause.strip()
        operator = next((item for item in operators if clause.startswith(item)), None)
        if operator is None:
            return None
        bound = _version_tuple(clause[len(operator) :].strip())
        if bound is None:
            return None
        width = max(len(version), len(bound))
        current_padded = version + (0,) * (width - len(version))
        bound_padded = bound + (0,) * (width - len(bound))
        satisfied = {
            ">=": current_padded >= bound_padded,
            "<=": current_padded <= bound_padded,
            "==": current_padded == bound_padded,
            "!=": current_padded != bound_padded,
            ">": current_padded > bound_padded,
            "<": current_padded < bound_padded,
        }[operator]
        if not satisfied:
            return False
    return True


def _read_python_requirement(project_root: Path) -> str | None:
    try:
        with (project_root / "pyproject.toml").open("rb") as source:
            project = tomllib.load(source).get("project", {})
        requirement = project.get("requires-python")
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return requirement if isinstance(requirement, str) else None


def _cache_root(environment: Mapping[str, str]) -> Path:
    configured_hub = environment.get("HF_HUB_CACHE")
    if configured_hub:
        return Path(configured_hub).expanduser()
    configured_home = environment.get("HF_HOME")
    if configured_home:
        return Path(configured_home).expanduser() / "hub"
    return Path.home() / ".cache" / "huggingface" / "hub"


def _directory_status(path: Path) -> bool | None:
    """Return False only for a missing path, and None when inspection is denied."""
    try:
        return stat.S_ISDIR(path.stat().st_mode)
    except FileNotFoundError:
        return False
    except (OSError, ValueError):
        return None


def _environment_presence(environment: Mapping[str, str]) -> dict[str, bool]:
    return {
        "AWS_REGION or AWS_DEFAULT_REGION": bool(
            environment.get("AWS_REGION") or environment.get("AWS_DEFAULT_REGION")
        ),
        "BEDROCK_MODEL_ID": bool(environment.get("BEDROCK_MODEL_ID")),
        "PHISHPILOT_DECIDER_URL": "PHISHPILOT_DECIDER_URL" in environment,
        "PHISHPILOT_DECIDER_TIMEOUT_SECONDS": (
            "PHISHPILOT_DECIDER_TIMEOUT_SECONDS" in environment
        ),
        "AWS credential env vars present": any(
            environment.get(name)
            for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
        ),
    }


def _health_url(decider_endpoint: str) -> str:
    parsed = urlsplit(decider_endpoint)
    hostname = parsed.hostname
    try:
        address = ipaddress.ip_address(hostname or "")
    except ValueError as exc:
        raise ValidationError("health check requires an IP-literal loopback endpoint") from exc
    if not address.is_loopback:
        raise ValidationError("health check requires an IP-literal loopback endpoint")
    return f"{parsed.scheme}://{parsed.netloc}/health"


def check_decider_health(decider_endpoint: str, timeout_seconds: float) -> bool:
    """Check HTTP health on a literal loopback IP only; never follows redirects."""
    health_url = _health_url(decider_endpoint)
    timeout = min(HEALTH_TIMEOUT_SECONDS, timeout_seconds)
    request = Request(health_url, headers={"Accept": "application/json"}, method="GET")
    opener = build_opener(ProxyHandler({}), _NoRedirectHandler())
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status == 200
    except (HTTPError, TimeoutError, URLError, OSError):
        return False


def collect_diagnostics(
    project_root: str | Path = ".",
    *,
    environment: Mapping[str, str] | None = None,
    package_version_reader: Callable[[str], str] | None = None,
    memory_reader: Callable[[], MemoryInfo] | None = None,
    health_checker: Callable[[str, float], bool] | None = None,
    check_health: bool = False,
    python_version: tuple[int, ...] | None = None,
) -> DiagnosticsReport:
    """Collect local readiness data; network and AWS actions are never implicit."""
    root = Path(project_root)
    env = os.environ if environment is None else environment
    version_reader = package_version_reader or importlib.metadata.version
    read_memory = memory_reader or read_memory_info
    check_health_fn = health_checker or check_decider_health

    current_version = python_version or sys.version_info[:3]
    python_display = ".".join(str(part) for part in current_version)
    requirement = _read_python_requirement(root)
    compatibility = (
        _python_satisfies(current_version, requirement) if requirement is not None else None
    )

    packages: dict[str, str | None] = {}
    for package in (*RUNTIME_PACKAGES, *MODEL_RUNTIME_PACKAGES, *DEVELOPMENT_PACKAGES):
        try:
            packages[package] = version_reader(package)
        except importlib.metadata.PackageNotFoundError:
            packages[package] = None
        except (OSError, ValueError):
            packages[package] = None

    endpoint_raw = env.get("PHISHPILOT_DECIDER_URL", DEFAULT_DECIDER_URL)
    timeout_raw: str | float = env.get(
        "PHISHPILOT_DECIDER_TIMEOUT_SECONDS", str(DEFAULT_TIMEOUT_SECONDS)
    )
    model = env.get("PHISHPILOT_DECIDER_MODEL")
    try:
        decider = DeciderHttpClient(
            endpoint=endpoint_raw,
            timeout_seconds=timeout_raw,
            model=model,
        )
    except (ValidationError, TypeError, ValueError):
        decider = None

    cache_status: dict[str, bool | None] = {}
    try:
        cache_root = _cache_root(env)
        for repository in EXPECTED_MODEL_REPOSITORIES:
            cache_name = "models--" + repository.replace("/", "--")
            cache_status[repository] = _directory_status(cache_root / cache_name)
    except (OSError, ValueError):
        cache_status = {repository: None for repository in EXPECTED_MODEL_REPOSITORIES}

    try:
        memory = read_memory()
        memory_error = None
    except PermissionError:
        memory = None
        memory_error = "unavailable: access denied"
    except (OSError, ValueError):
        memory = None
        memory_error = "unavailable: platform memory counters failed"

    health_available: bool | None = None
    health_detail: str | None = None
    if check_health:
        if decider is None:
            health_detail = "not checked because Decider configuration is invalid"
        else:
            try:
                health_available = bool(
                    check_health_fn(decider.endpoint, decider.timeout_seconds)
                )
                health_detail = "available" if health_available else "unavailable"
            except ValidationError:
                health_available = False
                health_detail = "blocked: health checks require an IP-literal loopback endpoint"
            except Exception:
                health_available = False
                health_detail = "unavailable; no response details are retained"

    checks: list[ReadinessCheck] = []
    if compatibility is None:
        checks.append(
            ReadinessCheck(
                "Python compatibility", "UNKNOWN", "constraint unavailable or unsupported"
            )
        )
    elif compatibility:
        checks.append(
            ReadinessCheck(
                "Python compatibility", "READY", "runtime satisfies pyproject.toml"
            )
        )
    else:
        checks.append(
            ReadinessCheck(
                "Python compatibility", "BLOCKED", "runtime is outside pyproject.toml"
            )
        )

    required_runtime = (*RUNTIME_PACKAGES, *MODEL_RUNTIME_PACKAGES)
    missing_runtime = [name for name in required_runtime if packages[name] is None]
    checks.append(
        ReadinessCheck(
            "Runtime packages",
            "BLOCKED" if missing_runtime else "READY",
            "missing: " + ", ".join(missing_runtime)
            if missing_runtime
            else "direct and critical model-runtime packages found",
        )
    )
    checks.append(
        ReadinessCheck(
            "Decider configuration",
            "READY" if decider is not None else "BLOCKED",
            "loopback endpoint and bounded timeout validated"
            if decider is not None
            else "configuration invalid; values omitted",
        )
    )
    missing_caches = [name for name, present in cache_status.items() if present is False]
    unknown_caches = any(present is None for present in cache_status.values())
    cache_check_status: Status = (
        "BLOCKED" if missing_caches else "UNKNOWN" if unknown_caches else "READY"
    )
    checks.append(
        ReadinessCheck(
            "Model cache paths",
            cache_check_status,
            "missing: " + ", ".join(missing_caches)
            if missing_caches
            else "one or more paths could not be inspected"
            if unknown_caches
            else "expected Decider and base-model cache directories exist",
        )
    )
    if memory is None:
        checks.append(
            ReadinessCheck(
                "CPU memory preflight", "UNKNOWN", memory_error or "unavailable"
            )
        )
    elif (
        memory.available_bytes < MIN_STARTUP_HEADROOM_BYTES
        or memory.load_percent >= MAX_MEMORY_LOAD_PERCENT
    ):
        checks.append(
            ReadinessCheck(
                "CPU memory preflight",
                "BLOCKED",
                "below the proposed 10 GiB headroom gate or at/above the 90% stop threshold",
            )
        )
    else:
        checks.append(
            ReadinessCheck(
                "CPU memory preflight",
                "READY",
                "meets the proposed preflight threshold only; not proof of model feasibility",
            )
        )
    if check_health:
        checks.append(
            ReadinessCheck(
                "Local Decider health",
                "READY" if health_available else "BLOCKED",
                health_detail or "unavailable",
            )
        )

    preflight_checks = checks[:5]
    if any(item.status == "BLOCKED" for item in preflight_checks):
        local_preflight_status: Status = "BLOCKED"
    elif any(item.status == "UNKNOWN" for item in preflight_checks):
        local_preflight_status = "UNKNOWN"
    else:
        local_preflight_status = "READY"

    return DiagnosticsReport(
        python_version=python_display,
        python_requirement=requirement,
        python_compatible=compatibility,
        package_versions=packages,
        environment_present=_environment_presence(env),
        decider_endpoint=decider.endpoint if decider is not None else None,
        decider_timeout_seconds=decider.timeout_seconds if decider is not None else None,
        decider_configuration_valid=decider is not None,
        model_caches=cache_status,
        memory=memory,
        memory_error=memory_error,
        health_checked=check_health,
        health_available=health_available,
        health_detail=health_detail,
        checks=tuple(checks),
        local_preflight_status=local_preflight_status,
    )


def _format_gib(value: int) -> str:
    return f"{value / GIB:.2f} GiB"


def render_report(report: DiagnosticsReport) -> str:
    """Render diagnostics without exposing environment values or cache paths."""
    lines = ["PhishPilot read-only diagnostics", ""]
    requirement = report.python_requirement or "unknown"
    if report.python_compatible is True:
        compatible = "yes"
    elif report.python_compatible is False:
        compatible = "no"
    else:
        compatible = "unknown"
    lines.append(
        f"Python: {report.python_version} (compatible: {compatible}; requires {requirement})"
    )
    lines.append("Packages:")
    for package, version in report.package_versions.items():
        lines.append(f"  {package}: {version if version is not None else 'missing/unavailable'}")
    lines.append("Configuration presence (values and secrets are never displayed):")
    for name, present in report.environment_present.items():
        lines.append(f"  {name}: {'present' if present else 'absent'}")
    if report.decider_configuration_valid:
        lines.append(f"Decider endpoint: {report.decider_endpoint}")
        lines.append(f"Decider timeout: {report.decider_timeout_seconds:g} seconds")
    else:
        lines.append("Decider endpoint/timeout: invalid or unavailable; configured values omitted")
    lines.append("Model cache directories (paths not displayed):")
    for repository, present in report.model_caches.items():
        status = "unknown" if present is None else "present" if present else "missing"
        lines.append(f"  {repository}: {status}")
    if report.memory is None:
        lines.append(f"Physical RAM: {report.memory_error or 'unavailable'}")
    else:
        lines.append(
            "Physical RAM: "
            f"{_format_gib(report.memory.available_bytes)} available / "
            f"{_format_gib(report.memory.total_bytes)} total; "
            f"{report.memory.load_percent:.1f}% load"
        )
    if report.health_checked:
        lines.append(f"Decider /health: {report.health_detail or 'unavailable'}")
    else:
        lines.append("Decider /health: not checked (use --check-decider-health to opt in)")
    lines.append("")
    lines.append(f"Local CPU preflight: {report.local_preflight_status}")
    for check in report.checks:
        lines.append(f"  {check.status}: {check.name}: {check.detail}")
    lines.append(
        "Live Decider inference: NOT checked. Bedrock/AWS: NOT checked; "
        "no AWS calls are made."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check-decider-health",
        action="store_true",
        help="explicitly check the configured Decider /health endpoint on loopback only",
    )
    args = parser.parse_args(argv)
    report = collect_diagnostics(check_health=args.check_decider_health)
    print(render_report(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
