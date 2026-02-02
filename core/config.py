"""
Configuration: environment variables and optional config file (JSON).
CLI arguments override config file override env vars.
"""
import json
import logging
import os
from typing import Any

logger = logging.getLogger("mailt.config")


def _env_bool(name: str, default: bool = False) -> bool:
    v = os.environ.get(name, "").strip().lower()
    if v in ("1", "true", "yes", "on"):
        return True
    if v in ("0", "false", "no", "off"):
        return False
    return default


def _env_float(name: str, default: float | None = None) -> float | None:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return float(v)
    except ValueError:
        return default


def load_env_config() -> dict[str, Any]:
    """Load configuration from environment variables (MAILT_*)."""
    return {
        "verbose": _env_bool("MAILT_VERBOSE", False),
        "output_dir": os.environ.get("MAILT_OUTPUT_DIR", "").strip() or None,
        "output_format": os.environ.get("MAILT_FORMAT", "").strip().lower() or "html",
        "quiet": _env_bool("MAILT_QUIET", False),
        "log_file": os.environ.get("MAILT_LOG_FILE", "").strip() or None,
        "scan_timeout_seconds": _env_float("MAILT_TIMEOUT"),
        "dns_timeout": _env_float("MAILT_DNS_TIMEOUT"),
        "smtp_timeout": _env_float("MAILT_SMTP_TIMEOUT"),
    }


def load_file_config(path: str) -> dict[str, Any]:
    """Load configuration from a JSON file. Returns empty dict on error."""
    if not path or not os.path.isfile(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        # Map common keys to our names
        mapping = {
            "verbose": "verbose",
            "output_dir": "output_dir",
            "output_directory": "output_dir",
            "format": "output_format",
            "output_format": "output_format",
            "quiet": "quiet",
            "log_file": "log_file",
            "timeout": "scan_timeout_seconds",
            "scan_timeout": "scan_timeout_seconds",
            "dns_timeout": "dns_timeout",
            "smtp_timeout": "smtp_timeout",
        }
        out = {}
        for k, v in data.items():
            key = mapping.get(k, k)
            if key in (
                "verbose",
                "quiet",
            ):
                out[key] = bool(v)
            elif key in ("output_dir", "output_format", "log_file"):
                out[key] = str(v).strip() if v else None
            elif key in ("scan_timeout_seconds", "dns_timeout", "smtp_timeout"):
                try:
                    out[key] = float(v) if v is not None else None
                except (TypeError, ValueError):
                    logger.warning("Config key %s has invalid value %r; skipping.", key, v)
        return out
    except (OSError, json.JSONDecodeError):
        return {}


def merge_config(env: dict[str, Any], file_cfg: dict[str, Any], cli: dict[str, Any]) -> dict[str, Any]:
    """Merge env (base), then file, then CLI. CLI overrides all."""
    out = dict(env)
    for k, v in file_cfg.items():
        if v is not None:
            out[k] = v
    for k, v in cli.items():
        if v is not None:
            out[k] = v
    return out
