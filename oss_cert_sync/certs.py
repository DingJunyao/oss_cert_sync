"""Certificate parsing, matching and fingerprint helpers (pure functions, no I/O)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID


class CertError(Exception):
    """Certificate material is missing, malformed or not usable for the target."""


_CERT_BLOCK_RE = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.DOTALL
)


@dataclass
class CertMaterial:
    """A parsed certificate chain plus its matching private key."""

    cert_pem: bytes                    # raw bytes as read from the source
    key_pem: bytes
    certs: List[x509.Certificate]      # every CERTIFICATE block, leaf first
    leaf: x509.Certificate
    key: object

    @property
    def common_name(self) -> str:
        attrs = self.leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return attrs[0].value if attrs else ""

    @property
    def sans(self) -> List[str]:
        return sans_of(self.leaf)

    @property
    def not_before(self) -> datetime:
        return cert_time(self.leaf, "not_valid_before")

    @property
    def not_after(self) -> datetime:
        return cert_time(self.leaf, "not_valid_after")

    @property
    def days_left(self) -> float:
        delta = self.not_after - datetime.now(timezone.utc)
        return delta.total_seconds() / 86400.0

    @property
    def chain_size(self) -> int:
        return len(self.certs)


def cert_time(cert: x509.Certificate, attr: str) -> datetime:
    """Aware UTC datetime for not_valid_before / not_valid_after (old and new cryptography)."""
    value = getattr(cert, attr + "_utc", None)
    if value is None:  # cryptography < 42
        value = getattr(cert, attr).replace(tzinfo=timezone.utc)
    return value


def sans_of(cert: x509.Certificate) -> List[str]:
    """SAN DNS entries; falls back to the common name when no SAN extension exists."""
    names: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [n.value for n in ext.value]
    except x509.ExtensionNotFound:
        pass
    if not names:
        attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            names = [attrs[0].value]
    return names


def load_cert_chain(cert_pem: bytes) -> List[x509.Certificate]:
    """Load every CERTIFICATE block from a PEM blob (leaf first)."""
    blocks = _CERT_BLOCK_RE.findall(cert_pem)
    if not blocks:
        raise CertError("certificate PEM contains no CERTIFICATE blocks")
    return [x509.load_pem_x509_certificate(block) for block in blocks]


def load_private_key(key_pem: bytes):
    try:
        return serialization.load_pem_private_key(key_pem, password=None)
    except (TypeError, ValueError) as exc:
        raise CertError(f"cannot load private key: {exc}") from exc


def load_material(cert_pem: bytes, key_pem: bytes) -> CertMaterial:
    certs = load_cert_chain(cert_pem)
    key = load_private_key(key_pem)
    return CertMaterial(
        cert_pem=cert_pem, key_pem=key_pem, certs=certs, leaf=certs[0], key=key
    )


def public_keys_match(material: CertMaterial) -> bool:
    der_a = material.leaf.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    der_b = material.key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    return der_a == der_b


def san_matches(san: str, domain: str) -> bool:
    """True when a SAN entry covers *domain* (exact match or single-label wildcard)."""
    d = domain.strip().lower().rstrip(".")
    s = san.strip().lower().rstrip(".")
    if not d or not s:
        return False
    if s == d:
        return True
    if s.startswith("*.") and len(s) > 2:
        base = s[2:]
        if d.endswith("." + base):
            label = d[: -len(base) - 1]
            return bool(label) and "." not in label
    return False


def domain_score(sans: List[str], domain: str) -> int:
    """2 = exact SAN match, 1 = wildcard match, 0 = no match."""
    d = domain.strip().lower().rstrip(".")
    best = 0
    for san in sans:
        s = san.strip().lower().rstrip(".")
        if s == d:
            return 2
        if best < 1 and san_matches(s, d):
            best = 1
    return best


def covers_domain(material: CertMaterial, domain: str) -> bool:
    return domain_score(material.sans, domain) > 0


_FINGERPRINT_ALGOS = {"md5": hashes.MD5, "sha1": hashes.SHA1, "sha256": hashes.SHA256}


def fingerprint(cert: x509.Certificate, algorithm: str = "sha256", colons: bool = True) -> str:
    """Uppercase hex fingerprint, optionally colon separated."""
    try:
        algo = _FINGERPRINT_ALGOS[algorithm.lower()]
    except KeyError:
        raise ValueError(f"unsupported fingerprint algorithm: {algorithm}") from None
    digest = cert.fingerprint(algo()).hex().upper()
    if colons:
        return ":".join(digest[i : i + 2] for i in range(0, len(digest), 2))
    return digest


def fingerprint_variants(cert: x509.Certificate) -> set:
    """All normalized (uppercase, colon-less) md5/sha1/sha256 fingerprints of *cert*."""
    return {fingerprint(cert, name, colons=False) for name in _FINGERPRINT_ALGOS}


def fingerprint_matches(cert: x509.Certificate, remote: str) -> bool:
    """Compare a remote fingerprint string (format unknown) against the local cert."""
    if not remote:
        return False
    return remote.strip().upper().replace(":", "") in fingerprint_variants(cert)


def describe(material: CertMaterial) -> str:
    """One-line human summary used by status/doctor/sync logs."""
    return (
        f"CN={material.common_name!r} sans={material.sans} "
        f"valid={material.not_before:%Y-%m-%d}..{material.not_after:%Y-%m-%d} "
        f"days_left={material.days_left:.0f} chain={material.chain_size} "
        f"sha256={fingerprint(material.leaf, 'sha256', colons=False)[:16]}"
    )
