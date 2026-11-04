"""TOML configuration loading and validation."""
from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


class ConfigError(Exception):
    pass


_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand(value, key: str):
    """Expand VAR references written as dollar-brace in string values; fail loudly when unset."""
    if not isinstance(value, str):
        return value

    def repl(match: "re.Match") -> str:
        name = match.group(1)
        if name not in os.environ:
            raise ConfigError(f"{key}: environment variable {name} is not set")
        return os.environ[name]

    return _ENV_RE.sub(repl, value)


@dataclass
class SourceConfig:
    type: str = "caddy"          # only "caddy" layouts are supported
    access: str = "docker"       # "docker" (docker exec) or "local" (direct fs)
    container: str = "caddy"
    storage: str = "/data/caddy"


@dataclass
class AliyunConfig:
    region: Optional[str] = None
    endpoint: Optional[str] = None
    access_key_id: Optional[str] = None
    access_key_secret: Optional[str] = None


@dataclass
class TargetConfig:
    domain: str
    bucket: str
    endpoint: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None


@dataclass
class Settings:
    config_path: Path
    source: SourceConfig
    aliyun: AliyunConfig
    targets: List[TargetConfig]
    state_file: Path
    log_level: str = "INFO"
    upload_attempts: int = 3

    @property
    def lock_file(self) -> Path:
        return self.state_file.parent / (self.state_file.name + ".lock")


def default_config_path() -> Path:
    env = os.environ.get("CERT_UPLOADER_CONFIG")
    if env:
        return Path(env)
    candidates = [
        Path("config.toml"),
        Path("/etc/cert-uploader/config.toml"),
        Path.home() / ".config" / "cert-uploader" / "config.toml",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise ConfigError(
        "no config file found; pass --config or set CERT_UPLOADER_CONFIG "
        "(looked in: " + ", ".join(str(c) for c in candidates) + ")"
    )


def load_settings(path: Path) -> Settings:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"config file not found: {path}") from None
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from None

    def section(name: str) -> dict:
        value = raw.get(name, {})
        if not isinstance(value, dict):
            raise ConfigError(f"[{name}] must be a table")
        return value

    src_raw = section("source")
    source = SourceConfig(
        type=_expand(src_raw.get("type", "caddy"), "source.type"),
        access=_expand(src_raw.get("access", "docker"), "source.access"),
        container=_expand(src_raw.get("container", "caddy"), "source.container"),
        storage=_expand(src_raw.get("storage", "/data/caddy"), "source.storage"),
    )

    ali_raw = section("aliyun")
    aliyun = AliyunConfig(
        region=_expand(ali_raw.get("region"), "aliyun.region"),
        endpoint=_expand(ali_raw.get("endpoint"), "aliyun.endpoint"),
        access_key_id=_expand(ali_raw.get("access_key_id"), "aliyun.access_key_id"),
        access_key_secret=_expand(ali_raw.get("access_key_secret"), "aliyun.access_key_secret"),
    )

    targets: List[TargetConfig] = []
    target_items = raw.get("target") or raw.get("targets") or []
    for index, item in enumerate(target_items):
        if not isinstance(item, dict):
            raise ConfigError(f"target[{index}] must be a table")
        domain = _expand(item.get("domain"), f"target[{index}].domain")
        bucket = _expand(item.get("bucket"), f"target[{index}].bucket")
        if not domain or not bucket:
            raise ConfigError(f"target[{index}]: domain and bucket are required")
        targets.append(
            TargetConfig(
                domain=domain.strip().lower().rstrip("."),
                bucket=bucket.strip(),
                endpoint=_expand(item.get("endpoint"), f"target[{index}].endpoint"),
                cert_file=_expand(item.get("cert_file"), f"target[{index}].cert_file"),
                key_file=_expand(item.get("key_file"), f"target[{index}].key_file"),
            )
        )
    if not targets:
        raise ConfigError("at least one [[target]] is required")

    state_file = Path(
        _expand(raw.get("state_file") or str(path.parent / "state.json"), "state_file")
    )
    settings = Settings(
        config_path=path,
        source=source,
        aliyun=aliyun,
        targets=targets,
        state_file=state_file,
        log_level=str(raw.get("log_level", "INFO")).upper(),
        upload_attempts=int(raw.get("upload_attempts", 3)),
    )
    validate(settings)
    return settings


def validate(settings: Settings) -> None:
    src = settings.source
    if src.type != "caddy":
        raise ConfigError(
            f"source.type must be 'caddy' (got {src.type!r}); for standalone PEM files "
            "set cert_file/key_file on each [[target]] instead"
        )
    if src.access not in ("docker", "local"):
        raise ConfigError(f"source.access must be 'docker' or 'local' (got {src.access!r})")
    if src.access == "docker" and not src.container:
        raise ConfigError("source.container is required when source.access = 'docker'")
    if not src.storage:
        raise ConfigError("source.storage is required")
    if not settings.aliyun.region:
        raise ConfigError("aliyun.region is required (e.g. 'cn-shanghai')")
    if settings.upload_attempts < 1:
        raise ConfigError("upload_attempts must be >= 1")
    for target in settings.targets:
        if bool(target.cert_file) != bool(target.key_file):
            raise ConfigError(
                f"target {target.domain}: cert_file and key_file must be set together"
            )
