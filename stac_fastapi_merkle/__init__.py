"""STAC FastAPI Merkle Verification Extension.

A stac-fastapi extension that adds cryptographic data integrity verification
to STAC APIs. Enables server-side validation of STAC Items against Merkle Roots
using Inclusion Proofs and RFC 8785 canonicalization.
"""

from stac_fastapi_merkle.extension import (
    MerkleVerificationExtension,
    VerificationResult,
    MatchDetails,
)

__version__ = "0.1.0"
__all__ = [
    "MerkleVerificationExtension",
    "VerificationResult",
    "MatchDetails",
]
