"""Locate and read certificate/key pairs from Caddy storage or explicit PEM files."""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional

from .certs import CertError, cert_time, domain_score, load_cert_chain, sans_of

log = logging.getLogger(__name__)


class SourceError(Exception):
    """Certificate source is misconfigured or unreadable."""


@dataclass
class CertCandidate:
    name: str                            # cert name, e.g. wildcard_.a4ding.com
    origin: str                          # human readable location for logs/state
    read_cert: Callable[[], bytes]
    read_key: Callable[[], bytes]


class DockerSource:
    """Read certificates from a Caddy container's data volume via 'docker exec'.

    Works for unprivileged users in the docker group - no root required.
    """

    def __init__(self, container: str, storage: str):
        self.container = container
        self.storage = storage.rstrip("/")

    def _exec(self, args: List[str]) -> bytes:
        cmd = ["docker", "exec", self.container, *args]
        proc = subprocess.run(cmd, capture_output=True)
        if proc.returncode != 0:
            stderr = proc.stderr.decode("utf-8", "replace").strip()
            raise SourceError(
                f"{' '.join(cmd)} failed: {stderr or f'exit code {proc.returncode}'}"
            )
        return proc.stdout

    def candidates(self) -> List[CertCandidate]:
        root = f"{self.storage}/certificates"
        out = self._exec(
            ["find", root, "-mindepth", "2", "-maxdepth", "2", "-type", "d"]
        ).decode("utf-8", "replace")
        found: List[CertCandidate] = []
        for line in sorted(out.splitlines()):
            line = line.strip()
            if not line:
                continue
            name = line.rsplit("/", 1)[-1]
            crt = f"{line}/{name}.crt"
            key = f"{line}/{name}.key"
            found.append(
                CertCandidate(
                    name=name,
                    origin=f"docker://{self.container}{crt}",
                    read_cert=(lambda p=crt: self._exec(["cat", p])),
                    read_key=(lambda p=key: self._exec(["cat", p])),
                )
            )
        return found


class LocalSource:
    """Read certificates directly from a Caddy storage directory on this host."""

    def __init__(self, storage: str):
        self.storage = Path(storage).expanduser()

    def candidates(self) -> List[CertCandidate]:
        root = self.storage / "certificates"
        if not root.is_dir():
            raise SourceError(f"certificate storage not found: {root}")
        found: List[CertCandidate] = []
        for issuer_dir in sorted(p for p in root.iterdir() if p.is_dir()):
            for cert_dir in sorted(p for p in issuer_dir.iterdir() if p.is_dir()):
                crt = cert_dir / f"{cert_dir.name}.crt"
                key = cert_dir / f"{cert_dir.name}.key"
                if not crt.is_file():
                    continue
                found.append(
                    CertCandidate(
                        name=cert_dir.name,
                        origin=str(crt),
                        read_cert=(lambda p=crt: p.read_bytes()),
                        read_key=(lambda p=key: p.read_bytes()),
                    )
                )
        return found


class FilesSource:
    """A single explicit cert/key pair (manual PEM files, acme.sh output, ...)."""

    def __init__(self, cert_file: str, key_file: str):
        self.cert_path = Path(cert_file).expanduser()
        self.key_path = Path(key_file).expanduser()

    def candidates(self) -> List[CertCandidate]:
        if not self.cert_path.is_file():
            raise SourceError(f"certificate file not found: {self.cert_path}")
        if not self.key_path.is_file():
            raise SourceError(f"private key file not found: {self.key_path}")
        return [
            CertCandidate(
                name=self.cert_path.stem,
                origin=str(self.cert_path),
                read_cert=self.cert_path.read_bytes,
                read_key=self.key_path.read_bytes,
            )
        ]


def make_source(settings, target):
    """Build the certificate source for one target (explicit files win over Caddy)."""
    if target.cert_file and target.key_file:
        return FilesSource(target.cert_file, target.key_file)
    if target.cert_file or target.key_file:
        raise SourceError(
            f"target {target.domain}: cert_file and key_file must be configured together"
        )
    src = settings.source
    if src.access == "docker":
        return DockerSource(src.container, src.storage)
    if src.access == "local":
        return LocalSource(src.storage)
    raise SourceError(f"unknown source.access: {src.access!r}")


def select_for_domain(source, domain: str) -> Optional[CertCandidate]:
    """Pick the candidate whose certificate best covers *domain*.

    Exact SAN match (score 2) beats wildcard match (score 1); ties are broken by
    the longest validity (newest renewal wins).
    """
    best: Optional[CertCandidate] = None
    best_score = 0
    best_not_after = None
    for cand in source.candidates():
        try:
            certs = load_cert_chain(cand.read_cert())
        except (CertError, SourceError) as exc:
            log.debug("skipping %s: %s", cand.origin, exc)
            continue
        leaf = certs[0]
        score = domain_score(sans_of(leaf), domain)
        if score == 0:
            continue
        not_after = cert_time(leaf, "not_valid_after")
        if score > best_score or (
            score == best_score and (best_not_after is None or not_after > best_not_after)
        ):
            best, best_score, best_not_after = cand, score, not_after
    return best
