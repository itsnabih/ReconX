"""Profiles and configuration hierarchy for ReconX scans.

Strict priority hierarchy (Section 23 of Implementation.md):
defaults -> profile -> CLI arguments
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
import yaml

from reconx.core.scheduler import SchedulerConfig


VALID_MODES: set[str] = {"safe", "passive", "active"}

DEFAULT_PROFILE_DATA: dict[str, Any] = {
    "name": "default",
    "description": "Standard balanced reconnaissance configuration",
    "mode": "active",
    "modules": {
        "dns": True,
        "network": True,
        "http": True,
        "tls": True,
        "directory": False,
        "nikto": False,
        "sqlmap": False,
    },
    "concurrency": {
        "global": 10,
        "dns": 8,
        "network": 4,
        "http": 8,
        "discovery": 4,
        "vulnerability": 2,
        "default": 8,
    },
    "timeouts": {
        "default": 30.0,
        "dns": 10.0,
        "network": 30.0,
        "http": 15.0,
        "directory": 60.0,
        "nikto": 120.0,
        "sqlmap": 120.0,
    },
    "wordlists": {
        "subdomains": "",
        "directory": "",
    },
}

BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "quick": {
        "name": "quick",
        "description": "Fast reconnaissance with essential DNS and network discovery and low timeouts",
        "mode": "active",
        "modules": {
            "dns": True,
            "network": True,
            "http": True,
            "tls": False,
            "directory": False,
            "nikto": False,
            "sqlmap": False,
        },
        "concurrency": {
            "global": 15,
            "dns": 10,
            "network": 5,
            "http": 10,
            "discovery": 6,
            "vulnerability": 2,
            "default": 10,
        },
        "timeouts": {
            "default": 10.0,
            "dns": 5.0,
            "network": 15.0,
            "http": 10.0,
        },
        "wordlists": {
            "subdomains": "",
            "directory": "",
        },
    },
    "passive": {
        "name": "passive",
        "description": "Passive-only reconnaissance (DNS/OSINT) without active port probing",
        "mode": "passive",
        "modules": {
            "dns": True,
            "network": False,
            "http": False,
            "tls": False,
            "directory": False,
            "nikto": False,
            "sqlmap": False,
        },
        "concurrency": {
            "global": 8,
            "dns": 8,
            "network": 2,
            "http": 4,
            "discovery": 4,
            "vulnerability": 1,
            "default": 8,
        },
        "timeouts": {
            "default": 15.0,
            "dns": 10.0,
        },
        "wordlists": {
            "subdomains": "",
            "directory": "",
        },
    },
    "network": {
        "name": "network",
        "description": "Network infrastructure mapping and port/service discovery",
        "mode": "active",
        "modules": {
            "dns": True,
            "network": True,
            "http": False,
            "tls": False,
            "directory": False,
            "nikto": False,
            "sqlmap": False,
        },
        "concurrency": {
            "global": 10,
            "dns": 8,
            "network": 6,
            "http": 4,
            "discovery": 4,
            "vulnerability": 2,
            "default": 8,
        },
        "timeouts": {
            "default": 30.0,
            "dns": 10.0,
            "network": 60.0,
        },
        "wordlists": {
            "subdomains": "",
            "directory": "",
        },
    },
    "web": {
        "name": "web",
        "description": "Web application footprinting, directory enumeration, and web vulnerability scanning",
        "mode": "active",
        "modules": {
            "dns": True,
            "network": False,
            "http": True,
            "tls": True,
            "directory": True,
            "nikto": True,
            "sqlmap": False,
        },
        "concurrency": {
            "global": 12,
            "dns": 6,
            "network": 2,
            "http": 10,
            "discovery": 6,
            "vulnerability": 2,
            "default": 8,
        },
        "timeouts": {
            "default": 30.0,
            "dns": 10.0,
            "http": 20.0,
            "directory": 60.0,
            "nikto": 120.0,
        },
        "wordlists": {
            "subdomains": "",
            "directory": "",
        },
    },
    "full": {
        "name": "full",
        "description": "Comprehensive reconnaissance covering network, web, directory, and active vulnerability modules",
        "mode": "active",
        "modules": {
            "dns": True,
            "network": True,
            "http": True,
            "tls": True,
            "directory": True,
            "nikto": True,
            "sqlmap": True,
        },
        "concurrency": {
            "global": 20,
            "dns": 8,
            "network": 6,
            "http": 10,
            "discovery": 6,
            "vulnerability": 4,
            "default": 10,
        },
        "timeouts": {
            "default": 60.0,
            "dns": 10.0,
            "network": 120.0,
            "http": 30.0,
            "directory": 120.0,
            "nikto": 300.0,
            "sqlmap": 300.0,
        },
        "wordlists": {
            "subdomains": "",
            "directory": "",
        },
    },
}


def _deep_update(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively update nested dictionaries without mutating the original."""
    result = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and key in result and isinstance(result[key], dict):
            result[key] = _deep_update(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


@dataclass
class ScanProfile:
    """Operational scan configuration profile."""

    name: str
    description: str = ""
    mode: str = "active"
    modules: dict[str, bool] = field(default_factory=dict)
    concurrency: dict[str, int] = field(default_factory=dict)
    timeouts: dict[str, float] = field(default_factory=dict)
    wordlists: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise ValueError("profile name must be a non-empty string")
        if self.mode not in VALID_MODES:
            raise ValueError(
                f"invalid profile mode '{self.mode}'; must be one of {sorted(VALID_MODES)}"
            )

        # Validate concurrency limits
        for k, v in self.concurrency.items():
            if not isinstance(v, int) or v <= 0:
                raise ValueError(f"concurrency '{k}' must be a positive integer, got {v!r}")

        # Validate timeouts
        for k, v in self.timeouts.items():
            if not isinstance(v, (int, float)) or v < 0:
                raise ValueError(f"timeout '{k}' must be non-negative, got {v!r}")

    def is_module_enabled(self, module_name: str) -> bool:
        """Return True if the specified module is enabled."""
        return bool(self.modules.get(module_name, False))

    def get_concurrency(self, resource_class: str = "default") -> int:
        """Get concurrency limit for a resource class, falling back to default or 10."""
        if resource_class in self.concurrency:
            return self.concurrency[resource_class]
        return self.concurrency.get("default", 10)

    def get_timeout(self, module_or_class: str = "default") -> float:
        """Get timeout for a module or resource class, falling back to default or 30.0."""
        if module_or_class in self.timeouts:
            return float(self.timeouts[module_or_class])
        return float(self.timeouts.get("default", 30.0))

    def to_scheduler_config(self) -> SchedulerConfig:
        """Convert profile concurrency and timeout settings into a SchedulerConfig."""
        global_c = self.concurrency.get("global", 10)
        default_c = self.concurrency.get("default", 10)
        default_t = self.timeouts.get("default", 30.0)

        # Build resource concurrency map
        res_concurrency = {
            k: v for k, v in self.concurrency.items() if k not in ("global", "default")
        }
        return SchedulerConfig(
            global_concurrency=global_c,
            resource_concurrency=res_concurrency,
            default_resource_concurrency=default_c,
            default_timeout=default_t,
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert profile to serializable dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "mode": self.mode,
            "modules": dict(self.modules),
            "concurrency": dict(self.concurrency),
            "timeouts": dict(self.timeouts),
            "wordlists": dict(self.wordlists),
        }

    def copy(self) -> ScanProfile:
        """Create a deep copy of the profile."""
        return ScanProfile(
            name=self.name,
            description=self.description,
            mode=self.mode,
            modules=copy.deepcopy(self.modules),
            concurrency=copy.deepcopy(self.concurrency),
            timeouts=copy.deepcopy(self.timeouts),
            wordlists=copy.deepcopy(self.wordlists),
        )

    def apply_overrides(self, overrides: dict[str, Any] | None) -> ScanProfile:
        """Return a new ScanProfile with CLI overrides applied.

        Enforces priority: defaults -> profile -> CLI arguments.
        Supports structured dict overrides as well as flat CLI arguments:
        - mode: str
        - modules: dict[str, bool]
        - enable_modules: Sequence[str]
        - disable_modules: Sequence[str]
        - concurrency: int | dict[str, int]
        - timeouts: float | dict[str, float]
        - timeout: float (alias for default timeout)
        - wordlists: dict[str, str]
        """
        if not overrides:
            return self.copy()

        new_data = self.to_dict()

        if "mode" in overrides and overrides["mode"] is not None:
            new_data["mode"] = str(overrides["mode"])

        if "description" in overrides and overrides["description"] is not None:
            new_data["description"] = str(overrides["description"])

        # Modules overrides
        if "modules" in overrides and isinstance(overrides["modules"], dict):
            new_data["modules"].update(overrides["modules"])
        if "enable_modules" in overrides and overrides["enable_modules"]:
            for mod in overrides["enable_modules"]:
                new_data["modules"][mod] = True
        if "disable_modules" in overrides and overrides["disable_modules"]:
            for mod in overrides["disable_modules"]:
                new_data["modules"][mod] = False

        # Concurrency overrides
        if "concurrency" in overrides and overrides["concurrency"] is not None:
            c = overrides["concurrency"]
            if isinstance(c, int):
                new_data["concurrency"]["global"] = c
            elif isinstance(c, dict):
                new_data["concurrency"].update(c)

        # Timeouts overrides
        if "timeout" in overrides and overrides["timeout"] is not None:
            new_data["timeouts"]["default"] = float(overrides["timeout"])
        if "timeouts" in overrides and overrides["timeouts"] is not None:
            t = overrides["timeouts"]
            if isinstance(t, (int, float)):
                new_data["timeouts"]["default"] = float(t)
            elif isinstance(t, dict):
                new_data["timeouts"].update({k: float(v) for k, v in t.items()})

        # Wordlists overrides
        if "wordlists" in overrides and isinstance(overrides["wordlists"], dict):
            new_data["wordlists"].update(overrides["wordlists"])

        return ScanProfile(**new_data)


class ProfileLoader:
    """Discovers, loads, and merges scan profiles from filesystem or built-in registry."""

    @staticmethod
    def _find_profiles_directory(profiles_dir: str | Path | None = None) -> Path | None:
        """Resolve profiles directory location."""
        if profiles_dir is not None:
            p = Path(profiles_dir)
            if p.is_dir():
                return p.resolve()
            return None

        # Try current working directory / profiles
        cwd_profiles = Path.cwd() / "profiles"
        if cwd_profiles.is_dir():
            return cwd_profiles.resolve()

        # Try relative to repo root (three levels up from reconx/config/)
        repo_profiles = Path(__file__).resolve().parent.parent.parent / "profiles"
        if repo_profiles.is_dir():
            return repo_profiles.resolve()

        return None

    @classmethod
    def list_available_profiles(cls, profiles_dir: str | Path | None = None) -> list[str]:
        """List all available profile names (built-in + YAML files)."""
        names: set[str] = set(BUILTIN_PROFILES.keys())

        pdir = cls._find_profiles_directory(profiles_dir)
        if pdir and pdir.is_dir():
            for file in pdir.iterdir():
                if file.is_file() and file.suffix in (".yaml", ".yml"):
                    names.add(file.stem)

        return sorted(names)

    @classmethod
    def load_from_yaml(cls, path: str | Path) -> dict[str, Any]:
        """Read and parse profile YAML file."""
        filepath = Path(path)
        if not filepath.is_file():
            raise FileNotFoundError(f"Profile YAML file not found: {filepath}")

        with open(filepath, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, dict):
            raise ValueError(f"Profile YAML at {filepath} must contain a mapping/dictionary")

        return data

    @classmethod
    def load(
        cls,
        name_or_path: str = "default",
        cli_overrides: dict[str, Any] | None = None,
        profiles_dir: str | Path | None = None,
    ) -> ScanProfile:
        """Load a profile adhering strictly to priority: defaults -> profile -> CLI arguments."""
        # 1. Base defaults
        data = copy.deepcopy(DEFAULT_PROFILE_DATA)

        # 2. Determine profile source
        profile_data: dict[str, Any] = {}
        path_candidate = Path(name_or_path)

        if path_candidate.is_file():
            # Explicit file path provided
            profile_data = cls.load_from_yaml(path_candidate)
        else:
            # Check profiles directory
            pdir = cls._find_profiles_directory(profiles_dir)
            found_file: Path | None = None
            if pdir:
                for ext in (".yaml", ".yml"):
                    candidate = pdir / f"{name_or_path}{ext}"
                    if candidate.is_file():
                        found_file = candidate
                        break

            if found_file is not None:
                profile_data = cls.load_from_yaml(found_file)
            elif name_or_path in BUILTIN_PROFILES:
                profile_data = copy.deepcopy(BUILTIN_PROFILES[name_or_path])
            elif name_or_path == "default":
                profile_data = {}
            else:
                available = cls.list_available_profiles(profiles_dir)
                raise ValueError(
                    f"Profile '{name_or_path}' not found. Available profiles: {', '.join(available)}"
                )

        # Merge: defaults -> profile
        merged_data = _deep_update(data, profile_data)
        if "name" in profile_data:
            merged_data["name"] = profile_data["name"]
        elif name_or_path != "default":
            merged_data["name"] = name_or_path

        profile = ScanProfile(**merged_data)

        # 3. Merge: CLI arguments
        if cli_overrides:
            profile = profile.apply_overrides(cli_overrides)

        return profile

    @classmethod
    def get_default_profile(cls) -> ScanProfile:
        """Return the baseline default profile."""
        return ScanProfile(**copy.deepcopy(DEFAULT_PROFILE_DATA))


def load_profile(
    name_or_path: str = "default",
    cli_overrides: dict[str, Any] | None = None,
    profiles_dir: str | Path | None = None,
) -> ScanProfile:
    """Convenience helper to load a profile with priority: defaults -> profile -> CLI."""
    return ProfileLoader.load(name_or_path, cli_overrides=cli_overrides, profiles_dir=profiles_dir)
