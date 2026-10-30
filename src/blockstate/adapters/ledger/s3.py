"""Amazon S3 LedgerSink implementation using aiobotocore.

Provides object-lock / WORM compliant append-only persistence of TurnLedger records
partitioned by session identifier and turn index.
"""

import asyncio
import contextlib
from typing import Any

import aiobotocore.session  # type: ignore[import-untyped]

from blockstate.ports.ledger import TurnLedgerRecord


class S3LedgerSink:
    """Audit sink persisting TurnLedger records to Amazon S3 via aiobotocore."""

    def __init__(
        self,
        bucket_name: str,
        *,
        prefix: str = "turn_ledger",
        client: Any | None = None,
        region_name: str = "us-east-1",
        endpoint_url: str | None = None,
        aws_access_key_id: str | None = None,
        aws_secret_access_key: str | None = None,
    ) -> None:
        self.bucket_name = bucket_name
        self.prefix = prefix.strip("/")
        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key

        self._lock = asyncio.Lock()
        if client is not None:
            self._client = client
            self._client_cm: Any | None = None
            self._client_owned = False
        else:
            self._client = None
            self._client_cm = None
            self._client_owned = True
            self._session = aiobotocore.session.get_session()

    async def _get_client(self) -> Any:
        """Lazily initialise and enter the underlying aiobotocore S3 client."""
        if self._client is not None:
            return self._client

        async with self._lock:
            if self._client is None:
                self._client_cm = self._session.create_client(
                    "s3",
                    region_name=self.region_name,
                    endpoint_url=self.endpoint_url,
                    aws_access_key_id=self.aws_access_key_id,
                    aws_secret_access_key=self.aws_secret_access_key,
                )
                self._client = await self._client_cm.__aenter__()
            return self._client

    def _make_key(self, record: TurnLedgerRecord) -> str:
        """Construct deterministic S3 object key partitioned by session and turn."""
        return (
            f"{self.prefix}/{record.session_id}/{record.turn_index:08d}_{record.record_hash}.json"
        )

    async def append(self, record: TurnLedgerRecord) -> None:
        """Append a validated turn record to S3 partitioned storage idempotently."""
        client = await self._get_client()
        key = self._make_key(record)
        body = record.model_dump_json().encode("utf-8")

        await client.put_object(
            Bucket=self.bucket_name,
            Key=key,
            Body=body,
            ContentType="application/json",
        )

    async def flush(self) -> None:
        """Flush buffered turn records to durable storage."""
        # S3 put_object is durable immediately upon completion
        pass

    async def close(self) -> None:
        """Close the underlying aiobotocore client if owned."""
        async with self._lock:
            if self._client_owned and self._client_cm is not None:
                await self._client_cm.__aexit__(None, None, None)
                self._client = None
                self._client_cm = None

    async def get_records(self, session_id: str | None = None) -> list[TurnLedgerRecord]:
        """Retrieve stored turn records optionally filtered by session identifier."""
        client = await self._get_client()
        search_prefix = f"{self.prefix}/{session_id}/" if session_id else f"{self.prefix}/"

        records: list[TurnLedgerRecord] = []
        paginator = None
        if hasattr(client, "get_paginator"):
            try:
                paginator = client.get_paginator("list_objects_v2")
            except Exception:
                paginator = None

        if paginator is not None:
            async for page in paginator.paginate(Bucket=self.bucket_name, Prefix=search_prefix):
                for item in page.get("Contents", []):
                    key = item.get("Key", "")
                    if not key.endswith(".json"):
                        continue
                    with contextlib.suppress(Exception):
                        res = await client.get_object(Bucket=self.bucket_name, Key=key)
                        body_bytes = await res["Body"].read()
                        records.append(TurnLedgerRecord.model_validate_json(body_bytes))
        else:
            continuation_token: str | None = None
            while True:
                kwargs: dict[str, Any] = {
                    "Bucket": self.bucket_name,
                    "Prefix": search_prefix,
                }
                if continuation_token:
                    kwargs["ContinuationToken"] = continuation_token

                resp = await client.list_objects_v2(**kwargs)
                for item in resp.get("Contents", []):
                    key = item.get("Key", "")
                    if not key.endswith(".json"):
                        continue
                    with contextlib.suppress(Exception):
                        res = await client.get_object(Bucket=self.bucket_name, Key=key)
                        body_bytes = await res["Body"].read()
                        records.append(TurnLedgerRecord.model_validate_json(body_bytes))

                if resp.get("IsTruncated"):
                    continuation_token = resp.get("NextContinuationToken")
                    if not continuation_token:
                        break
                else:
                    break

        records.sort(key=lambda r: (r.session_id, r.turn_index))
        return records


__all__: list[str] = ["S3LedgerSink"]
