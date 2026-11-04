"""Thin wrapper around oss2 for certificate uploads to OSS CNAME domains."""
from __future__ import annotations

import logging
import os
import time
from typing import List, Optional

try:
    import oss2
except ImportError:  # reported as a friendly error when actually used
    oss2 = None  # type: ignore[assignment]

from .config import AliyunConfig, TargetConfig

log = logging.getLogger(__name__)

_RETRYABLE_STATUS = {-1, 429, 500, 502, 503, 504}


class OssError(Exception):
    pass


def _ensure_sdk() -> None:
    if oss2 is None:
        raise OssError(
            "dependency 'oss2' is missing; install it with: pip install 'oss2>=2.18,<3'"
        )


def has_credentials(cfg: AliyunConfig) -> bool:
    if cfg.access_key_id and cfg.access_key_secret:
        return True
    return bool(os.environ.get("OSS_ACCESS_KEY_ID")) and bool(
        os.environ.get("OSS_ACCESS_KEY_SECRET")
    )


def _provider(cfg: AliyunConfig):
    if cfg.access_key_id and cfg.access_key_secret:
        return oss2.credentials.StaticCredentialsProvider(
            cfg.access_key_id, cfg.access_key_secret
        )
    if has_credentials(cfg):
        return oss2.credentials.EnvironmentVariableCredentialsProvider()
    raise OssError(
        "no OSS credentials: set OSS_ACCESS_KEY_ID / OSS_ACCESS_KEY_SECRET in the "
        "environment (recommended) or access_key_id / access_key_secret in [aliyun]"
    )


def _describe_oss_error(exc: Exception) -> str:
    parts = [type(exc).__name__]
    for attr in ("status", "code", "message", "request_id"):
        value = getattr(exc, attr, None)
        if value:
            parts.append(f"{attr}={value}")
    return " ".join(parts)


class OssClient:
    """Authenticated access to one Aliyun account's OSS buckets (V4 signatures)."""

    def __init__(self, cfg: AliyunConfig):
        _ensure_sdk()
        if not cfg.region:
            raise OssError("aliyun.region is required for V4 signatures")
        self._cfg = cfg
        self._auth = oss2.ProviderAuthV4(_provider(cfg))

    def bucket_for(self, target: TargetConfig):
        region = self._cfg.region
        endpoint = (
            target.endpoint
            or self._cfg.endpoint
            or f"https://oss-{region}.aliyuncs.com"
        )
        return oss2.Bucket(self._auth, endpoint, target.bucket, region=region)

    @staticmethod
    def list_cnames(bucket) -> List:
        return list(bucket.list_bucket_cname().cname)

    @classmethod
    def find_cname(cls, bucket, domain: str):
        for info in cls.list_cnames(bucket):
            if info.domain == domain:
                return info
        return None

    def upload_certificate(
        self,
        bucket,
        domain: str,
        cert_pem: str,
        key_pem: str,
        attempts: int = 3,
    ) -> None:
        """Attach/replace the HTTPS certificate of an already bound CNAME domain.

        Uses an inline certificate + Force=true (no PreviousCertId), which is the
        documented way to replace the certificate of an existing CNAME binding.
        """
        cert = oss2.models.CertInfo(
            certificate=cert_pem,
            private_key=key_pem,
            force=True,
            delete_certificate=False,
        )
        request = oss2.models.PutBucketCnameRequest(domain=domain, cert=cert)
        last_error: Optional[Exception] = None
        for attempt in range(1, attempts + 1):
            try:
                bucket.put_bucket_cname(request)
                return
            except oss2.exceptions.OssError as exc:
                status = getattr(exc, "status", None)
                if status not in _RETRYABLE_STATUS:
                    raise OssError(_describe_oss_error(exc)) from exc
                last_error = exc
                delay = min(2 ** attempt, 30)
                log.warning(
                    "upload attempt %d/%d failed (status=%s), retrying in %ds: %s",
                    attempt,
                    attempts,
                    status,
                    delay,
                    exc,
                )
                time.sleep(delay)
        raise OssError(f"upload failed after {attempts} attempts: {last_error}")
