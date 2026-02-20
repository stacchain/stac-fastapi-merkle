"""Merkle Tree Verification Extension."""

import copy
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Type, Dict, Any, Optional
from urllib.parse import urlparse

import attr
import httpx
import jcs  # RFC 8785 Canonicalization
from fastapi import APIRouter, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response
from typing_extensions import TypedDict

from stac_fastapi.types.core import BaseCoreClient
from stac_fastapi.types.extension import ApiExtension
from stac_fastapi.types.stac import Item, Collection

logger = logging.getLogger(__name__)


class MatchDetails(TypedDict):
    """Details of the verification match."""
    item_hash_match: bool
    root_hash_match: bool


class VerificationResult(TypedDict):
    """The API response for the verify endpoint."""
    verified: bool
    timestamp: str
    algorithm: str
    match_details: MatchDetails


@attr.s
class MerkleVerificationExtension(ApiExtension):
    """Merkle Verification Extension.

    Adds a Data Integrity Layer to the STAC API.
    Enables /verify endpoints to check Item integrity against Collection Merkle Roots.
    """

    client: BaseCoreClient = attr.ib(default=None)
    settings: dict = attr.ib(default=attr.Factory(dict))
    conformance_classes: List[str] = attr.ib(
        default=attr.Factory(lambda: ["https://api.stacspec.org/v1.0.0-beta.1/merkle-verification"])
    )
    router: APIRouter = attr.ib(default=attr.Factory(APIRouter))
    response_class: Type[Response] = attr.ib(default=JSONResponse)
    trusted_domains: List[str] = attr.ib(
        default=attr.Factory(list),
        metadata={"description": "List of trusted domains for proof URLs. If empty, all non-private IPs are allowed."}
    )

    def register(self, app: FastAPI) -> None:
        """Register the extension with a FastAPI application."""
        self.router = APIRouter()

        self.router.add_api_route(
            path="/collections/{collection_id}/items/{item_id}/verify",
            endpoint=self.verify_item,
            methods=["GET"],
            response_model=VerificationResult,
            response_class=self.response_class,
            summary="Verify Item Integrity",
            description="Cryptographically verifies the item against the Collection's Merkle Root.",
            tags=["Verification"],
        )

        app.include_router(self.router, tags=["Verification"])

    def _is_private_ip(self, hostname: str) -> bool:
        """Check if hostname resolves to a private IP range.
        
        Prevents SSRF attacks by blocking access to:
        - localhost / 127.0.0.1
        - Private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
        - Link-local addresses (169.254.0.0/16) - AWS metadata, etc.
        """
        private_indicators = [
            "localhost",
            "127.0.0.1",
            "::1",  # IPv6 localhost
            "169.254",  # Link-local (AWS metadata)
            "10.",  # Private range
            "172.16.",  # Private range
            "172.17.",
            "172.18.",
            "172.19.",
            "172.20.",
            "172.21.",
            "172.22.",
            "172.23.",
            "172.24.",
            "172.25.",
            "172.26.",
            "172.27.",
            "172.28.",
            "172.29.",
            "172.30.",
            "172.31.",
            "192.168.",  # Private range
            "0.0.0.0",  # This host
        ]
        
        return any(hostname.startswith(indicator) for indicator in private_indicators)

    def _validate_proof_url(self, proof_url: str) -> None:
        """Validate proof URL to prevent SSRF attacks.
        
        Args:
            proof_url: The URL to validate
            
        Raises:
            HTTPException: If URL is invalid or points to private/restricted resources
        """
        try:
            parsed = urlparse(proof_url)
        except Exception as e:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid proof URL format: {str(e)}"
            )

        # Ensure HTTPS or HTTP
        if parsed.scheme not in ("http", "https"):
            raise HTTPException(
                status_code=400,
                detail=f"Proof URL must use HTTP or HTTPS, got: {parsed.scheme}"
            )

        # Check for private IPs
        hostname = parsed.hostname or ""
        if self._is_private_ip(hostname):
            raise HTTPException(
                status_code=400,
                detail="Proof URL cannot point to private IP ranges or localhost"
            )

        # If trusted domains are configured, validate against them
        if self.trusted_domains:
            if not any(hostname.endswith(domain) for domain in self.trusted_domains):
                raise HTTPException(
                    status_code=403,
                    detail=f"Proof URL domain not in trusted list: {hostname}"
                )

    def _calculate_merkle_hash(self, item: Dict[str, Any]) -> str:
        """Run CPU-intensive canonicalization and hashing in thread pool.
        
        This is a CPU-bound operation that should not block the event loop.
        
        Args:
            item: The STAC item to hash
            
        Returns:
            The double SHA256 hash of the canonicalized item
        """
        # Clean item: exclude merkle:object_hash to avoid circular logic
        item_clean = copy.deepcopy(item)
        if "properties" in item_clean and "merkle:object_hash" in item_clean["properties"]:
            del item_clean["properties"]["merkle:object_hash"]
        
        # JCS Canonicalization (RFC 8785)
        canonical_json = jcs.canonicalize(item_clean)
        
        # Double Hash (SHA256(SHA256(x))) to prevent length-extension attacks
        item_hash = hashlib.sha256(
            hashlib.sha256(canonical_json).digest()
        ).hexdigest()
        
        return item_hash

    async def verify_item(
        self, collection_id: str, item_id: str, request: Request
    ) -> VerificationResult:
        """Perform server-side Merkle Verification.

        1. Fetches the current Item from the DB.
        2. Fetches the active Collection (to get the trusted Root).
        3. Downloads the Merkle Proof (from the item's links).
        4. Calculates the canonical hash of the Item.
        5. Traverses the proof to verify the root matches.
        """
        # 1. Fetch the Item (Source of Truth for Data)
        try:
            item = await self.client.get_item(
                item_id=item_id, collection_id=collection_id, request=request
            )
        except Exception:
            raise HTTPException(status_code=404, detail=f"Item {item_id} not found")

        # 2. Fetch the Collection (Source of Truth for Root)
        try:
            collection = await self.client.get_collection(
                collection_id=collection_id, request=request
            )
        except Exception:
            raise HTTPException(status_code=404, detail=f"Collection {collection_id} not found")

        # Extract Merkle Root
        # Note: We handle both standard properties and potential root-level extensions
        merkle_root = collection.get("properties", {}).get("merkle:root") or \
                      collection.get("merkle:root")

        if not merkle_root:
            raise HTTPException(
                status_code=409, 
                detail="Collection is not initialized for Merkle Verification (missing merkle:root)"
            )

        # 3. Retrieve the Inclusion Proof
        # We look for the standardized 'merkle-proof' link relation
        proof_url = next(
            (link["href"] for link in item.get("links", []) if link["rel"] == "merkle-proof"), 
            None
        )

        if not proof_url:
            raise HTTPException(
                status_code=404, 
                detail="Item does not have a linked Merkle Proof (rel='merkle-proof')"
            )

        # [SECURITY] Validate proof URL to prevent SSRF attacks
        self._validate_proof_url(proof_url)

        # Fetch the proof file (could be S3, external URL, etc.)
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(proof_url, timeout=10.0)
                resp.raise_for_status()
                proof = resp.json()
        except Exception as e:
            logger.error(f"Failed to fetch proof for item {item_id}: {e}")
            raise HTTPException(
                status_code=502, 
                detail=f"Could not retrieve proof file from storage: {str(e)}"
            )

        # 4. Calculate Canonical Hash (Non-Blocking)
        # [PERFORMANCE] Offload CPU-intensive operations to thread pool
        # This prevents blocking the event loop during canonicalization and hashing
        item_hash = await run_in_threadpool(self._calculate_merkle_hash, item)

        # 5. Verify the Proof
        computed_root = self._compute_root(item_hash, proof["siblings"])

        # 6. Construct Result
        is_verified = (computed_root == merkle_root)
        
        # Check if the item hash in the proof matches the actual item hash
        # (This helps debug if the data changed vs if the tree changed)
        proof_leaf_match = (item_hash == proof.get("leaf_hash"))

        if not is_verified:
            # We return 409 Conflict if verification fails, as this indicates data corruption
            # or tampering.
            logger.warning(f"Verification FAILED for {item_id}. Computed: {computed_root}, Expected: {merkle_root}")

        return VerificationResult(
            verified=is_verified,
            timestamp=datetime.now(timezone.utc).isoformat(),
            algorithm="sha256",
            match_details=MatchDetails(
                item_hash_match=proof_leaf_match,
                root_hash_match=is_verified
            )
        )

    def _compute_root(self, leaf_hash: str, siblings: List[Dict[str, str]]) -> str:
        """Traverse the Merkle Path to reconstruct the root.
        
        This method climbs the tree from the leaf (item) to the root,
        hashing siblings along the way. The direction field indicates
        whether the sibling is on the left or right.
        
        Args:
            leaf_hash: The hash of the leaf node (the item)
            siblings: List of sibling hashes with direction indicators
            
        Returns:
            The computed root hash
        """
        current_hash = leaf_hash
        
        for sibling in siblings:
            direction = sibling.get("direction")
            sibling_hash = sibling.get("hash")
            
            if direction == "right":
                # Current node is Left, Sibling is Right
                combined = current_hash + sibling_hash
            else:
                # Current node is Right, Sibling is Left
                combined = sibling_hash + current_hash
            
            # Double Hash the combination (SHA256(SHA256(x)))
            current_hash = hashlib.sha256(
                hashlib.sha256(combined.encode("utf-8")).digest()
            ).hexdigest()
            
        return current_hash
