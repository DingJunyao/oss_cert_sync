"""Command line interface: sync / status / doctor."""
from __future__ import annotations

import argparse
import hashlib
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple

from . import __version__, certs, certsource, ossclient, state
from .config import ConfigError, Settings, TargetConfig, default_config_path, load_settings
from .certsource import CertCandidate
from .ossclient import OssClient, has_credentials

log = logging.getLogger("cert_uploader")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_CONFIG = 2
EXIT_CERT = 3


def _digest(cert_pem: bytes, key_pem: bytes) -> str:
    return hashlib.sha256(cert_pem + b"\x00" + key_pem).hexdigest()


def _load_material_for(
    settings: Settings, target: TargetConfig
) -> Tuple[CertCandidate, certs.CertMaterial]:
    source = certsource.make_source(settings, target)
    candidate = certsource.select_for_domain(source, target.domain)
    if candidate is None:
        raise certs.CertError(
            f"no certificate found by source {type(source).__name__} covers {target.domain}"
        )
    material = certs.load_material(candidate.read_cert(), candidate.read_key())
    return candidate, material


def _sync_target(
    settings: Settings, target: TargetConfig, dry_run: bool, force: bool, verify: bool = True
) -> str:
    candidate, material = _load_material_for(settings, target)

    if not certs.public_keys_match(material):
        raise certs.CertError("certificate and private key do not match")
    if material.days_left <= 0:
        raise certs.CertError(f"certificate already expired at {material.not_after.isoformat()}")
    if not certs.covers_domain(material, target.domain):
        raise certs.CertError(
            f"certificate {material.common_name} does not cover {target.domain}"
        )
    if material.chain_size < 2:
        log.warning(
            "%s: certificate file has no issuer chain; some clients may reject it",
            target.domain,
        )
    if material.days_left < 14:
        log.warning("%s: certificate expires in %d day(s)", target.domain, material.days_left)

    digest = _digest(material.cert_pem, material.key_pem)
    records = state.load(settings.state_file)
    previous = records.get(target.domain)
    if previous and previous.get("digest") == digest and not force:
        log.info(
            "%s: certificate unchanged since upload at %s, skipping",
            target.domain,
            previous.get("uploaded_at"),
        )
        return "skipped"

    if dry_run:
        log.info("DRY-RUN %s: would upload %s", target.domain, certs.describe(material))
        return "dry-run"

    client = OssClient(settings.aliyun)
    bucket = client.bucket_for(target)
    client.upload_certificate(
        bucket,
        target.domain,
        material.cert_pem.decode("utf-8"),
        material.key_pem.decode("utf-8"),
        attempts=settings.upload_attempts,
    )
    log.info("%s: uploaded %s", target.domain, certs.describe(material))

    record = {
        "digest": digest,
        "fingerprint_sha256": certs.fingerprint(material.leaf),
        "not_after": material.not_after.isoformat(),
        "uploaded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": candidate.origin,
    }

    if verify:
        try:
            info = client.find_cname(bucket, target.domain)
            cert_info = getattr(info, "certificate", None) if info else None
            if cert_info is None:
                log.warning("%s: could not read back the CNAME certificate info", target.domain)
            else:
                record["remote_cert_id"] = cert_info.cert_id
                record["remote_fingerprint"] = cert_info.fingerprint
                record["remote_valid_end_date"] = str(
                    getattr(cert_info, "valid_end_date", "") or ""
                )
                if cert_info.fingerprint and not certs.fingerprint_matches(
                    material.leaf, cert_info.fingerprint
                ):
                    log.warning(
                        "%s: remote fingerprint mismatch (remote=%s local=%s)",
                        target.domain,
                        cert_info.fingerprint,
                        record["fingerprint_sha256"],
                    )
                else:
                    log.info(
                        "%s: verified on OSS (cert_id=%s)", target.domain, cert_info.cert_id
                    )
        except Exception as exc:  # verification is best-effort
            log.warning("%s: post-upload verification failed: %s", target.domain, exc)

    records[target.domain] = record
    state.save(settings.state_file, records)
    return "uploaded"


def _filter_targets(settings: Settings, wanted: List[str]) -> List[TargetConfig]:
    if not wanted:
        return settings.targets
    names = {w.strip().lower().rstrip(".") for w in wanted}
    known = {t.domain for t in settings.targets}
    missing = names - known
    if missing:
        raise ConfigError(
            "target(s) not in config: " + ", ".join(sorted(missing))
        )
    return [t for t in settings.targets if t.domain in names]


def cmd_sync(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    targets = _filter_targets(settings, args.target)
    exit_code = EXIT_OK
    with state.exclusive_lock(settings.lock_file):
        for target in targets:
            try:
                outcome = _sync_target(
                    settings, target, args.dry_run, args.force, verify=not args.no_verify
                )
                log.info("%s: %s", target.domain, outcome)
            except certs.CertError as exc:
                log.error("%s: %s", target.domain, exc)
                exit_code = max(exit_code, EXIT_CERT)
            except Exception as exc:  # keep syncing the remaining targets
                log.error("%s: %s: %s", target.domain, type(exc).__name__, exc)
                exit_code = max(exit_code, EXIT_ERROR)
    return exit_code


def cmd_status(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    records = state.load(settings.state_file)
    client: Optional[OssClient] = None
    if has_credentials(settings.aliyun):
        try:
            client = OssClient(settings.aliyun)
        except Exception as exc:
            log.warning("could not initialise OSS client: %s", exc)
    for target in settings.targets:
        print(f"== {target.domain} (bucket {target.bucket}) ==")
        try:
            candidate, material = _load_material_for(settings, target)
            print(f"  local  : {certs.describe(material)}")
            print(f"  source : {candidate.origin}")
        except Exception as exc:
            print(f"  local  : ERROR {type(exc).__name__}: {exc}")
        record = records.get(target.domain)
        if record:
            fingerprint = str(record.get("fingerprint_sha256", ""))[:16]
            print(
                f"  state  : uploaded {record.get('uploaded_at')} fp={fingerprint} "
                f"src={record.get('source')}"
            )
        else:
            print("  state  : never uploaded")
        if client is None:
            print(
                "  oss    : no credentials (set OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET); "
                "remote status unknown"
            )
        else:
            try:
                bucket = client.bucket_for(target)
                info = client.find_cname(bucket, target.domain)
                if info is None:
                    print(
                        "  oss    : domain not bound to this bucket; "
                        "PutCname upload will fail until the CNAME exists"
                    )
                else:
                    cert_info = info.certificate
                    if cert_info is None:
                        print("  oss    : bound, but no certificate configured")
                    else:
                        print(
                            f"  oss    : type={cert_info.type} status={cert_info.status} "
                            f"cert_id={cert_info.cert_id} fp={cert_info.fingerprint} "
                            f"valid {cert_info.valid_start_date} .. {cert_info.valid_end_date}"
                        )
            except Exception as exc:
                print(f"  oss    : ERROR {type(exc).__name__}: {exc}")
    return EXIT_OK


def cmd_doctor(args: argparse.Namespace) -> int:
    settings = load_settings(args.config)
    failures = 0

    def check(ok: bool, name: str, detail: str = "") -> None:
        nonlocal failures
        if not ok:
            failures += 1
        mark = "[OK ]" if ok else "[FAIL]"
        line = f"{mark} {name}"
        if detail:
            line += f" -- {detail}"
        print(line)

    try:
        import oss2 as oss2_module

        check(True, f"oss2 {getattr(oss2_module, '__version__', '?')}")
    except ImportError as exc:
        check(False, "oss2 import", str(exc))
    try:
        import cryptography as cryptography_module

        check(True, f"cryptography {getattr(cryptography_module, '__version__', '?')}")
    except ImportError as exc:
        check(False, "cryptography import", str(exc))

    try:
        source = certsource.make_source(settings, settings.targets[0])
        candidates = source.candidates()
        names = ", ".join(c.name for c in candidates) or "(none)"
        check(
            bool(candidates),
            f"certificate source ({type(source).__name__})",
            f"{len(candidates)} candidate(s): {names}",
        )
    except Exception as exc:
        candidates = []
        check(False, "certificate source", str(exc))

    for target in settings.targets:
        try:
            _candidate, material = _load_material_for(settings, target)
            ok = (
                material.days_left > 0
                and certs.covers_domain(material, target.domain)
                and certs.public_keys_match(material)
            )
            check(ok, f"cert for {target.domain}", certs.describe(material))
        except Exception as exc:
            check(False, f"cert for {target.domain}", str(exc))

    if has_credentials(settings.aliyun):
        check(True, "OSS credentials", "present (config or environment)")
        client: Optional[OssClient] = None
        try:
            client = OssClient(settings.aliyun)
        except Exception as exc:
            check(False, "OSS client init", str(exc))
        if client is not None:
            for target in settings.targets:
                try:
                    bucket = client.bucket_for(target)
                    info = client.find_cname(bucket, target.domain)
                    if info is None:
                        check(False, f"CNAME {target.domain}", "not bound to bucket")
                    else:
                        cert_info = info.certificate
                        detail = (
                            f"cert_id={cert_info.cert_id} status={cert_info.status}"
                            if cert_info
                            else "bound, no certificate yet"
                        )
                        check(True, f"CNAME {target.domain}", detail)
                except Exception as exc:
                    check(False, f"CNAME {target.domain}", f"{type(exc).__name__}: {exc}")
    else:
        check(
            False,
            "OSS credentials",
            "missing; set OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET "
            "(upload/sync will refuse to run)",
        )

    for target in settings.targets:
        try:
            socket.getaddrinfo(target.domain, 443)
            check(True, f"DNS {target.domain}")
        except OSError as exc:
            check(False, f"DNS {target.domain}", str(exc))

    return EXIT_OK if failures == 0 else EXIT_ERROR


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cert-uploader",
        description="Push Caddy-managed TLS certificates to Aliyun OSS CNAME domains",
    )
    parser.add_argument(
        "--version", action="version", version=f"cert-uploader {__version__}"
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="only log errors")

    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument(
            "--config",
            type=Path,
            default=None,
            help="config file path (default: CERT_UPLOADER_CONFIG, then auto-discovery)",
        )

    p_sync = sub.add_parser(
        "sync", help="upload certificates that changed since the last successful run"
    )
    add_common(p_sync)
    p_sync.add_argument("--dry-run", action="store_true", help="show what would be uploaded")
    p_sync.add_argument("--force", action="store_true", help="upload even if unchanged")
    p_sync.add_argument(
        "--no-verify", action="store_true", help="skip the post-upload read-back check"
    )
    p_sync.add_argument(
        "--target", action="append", default=[], metavar="DOMAIN", help="only this target"
    )
    p_sync.set_defaults(func=cmd_sync)

    p_status = sub.add_parser(
        "status", help="show local certificates, state file and OSS CNAME certificates"
    )
    add_common(p_status)
    p_status.set_defaults(func=cmd_status)

    p_doctor = sub.add_parser(
        "doctor", help="check dependencies, cert source, targets, OSS access and DNS"
    )
    add_common(p_doctor)
    p_doctor.set_defaults(func=cmd_doctor)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.ERROR if args.quiet else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )
    if args.config is None:
        try:
            args.config = default_config_path()
        except ConfigError as exc:
            log.error("%s", exc)
            return EXIT_CONFIG
    try:
        return args.func(args)
    except ConfigError as exc:
        log.error("%s", exc)
        return EXIT_CONFIG
    except KeyboardInterrupt:
        log.error("interrupted")
        return EXIT_ERROR
