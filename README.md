# stac-fastapi-merkle

A stac-fastapi extension that adds cryptographic data integrity verification to STAC APIs. Enables server-side validation of STAC Items against Merkle Roots using Inclusion Proofs and RFC 8785 canonicalization.

## Features

- **Backend Agnostic**: Works with any stac-fastapi backend (SFEOS, PgSTAC, etc.) via `BaseCoreClient`
- **RFC 8785 Canonicalization**: Uses JCS (JSON Canonicalization Scheme) for deterministic JSON hashing
- **Double Hashing**: Implements SHA256(SHA256(x)) to prevent length-extension attacks
- **Robust Error Handling**: Comprehensive error responses for missing proofs, uninitialized collections, and storage failures
- **Async-Ready**: Full async/await support for high-performance verification

## Installation

### Prerequisites

Install the required dependencies:

```bash
pip install -r requirements.txt
```

Or using `pyproject.toml`:

```bash
pip install -e .
```

### Required Packages

- `jcs>=0.2.1` - RFC 8785 JSON Canonicalization
- `httpx>=0.24.0` - Async HTTP client for proof retrieval
- `fastapi>=0.100.0` - Web framework
- `stac-fastapi>=2.4.0` - STAC FastAPI core
- `attrs>=22.0.0` - Class decorators
- `typing-extensions>=4.0.0` - Type hints

## Quick Start

### 1. Register the Extension

```python
from fastapi import FastAPI
from stac_fastapi_merkle import MerkleVerificationExtension
from stac_fastapi.sfeos.client import SFEOSClient

app = FastAPI()
client = SFEOSClient()

# Register the Merkle Verification extension
merkle_ext = MerkleVerificationExtension(client=client)
merkle_ext.register(app)
```

### 2. Optional: Configure Trusted Domains

For enhanced security, restrict proof URLs to specific domains:

```python
# Only allow proofs from your S3 bucket
merkle_ext = MerkleVerificationExtension(
    client=client,
    trusted_domains=["s3.amazonaws.com", "proofs.example.com"]
)
merkle_ext.register(app)
```

If `trusted_domains` is empty (default), the extension allows any non-private IP address.

### 3. Verify an Item

Make a GET request to verify an item's integrity:

```bash
curl "http://localhost:8000/collections/{collection_id}/items/{item_id}/verify"
```

### Response Format

```json
{
  "verified": true,
  "timestamp": "2026-02-05T19:20:00+00:00",
  "algorithm": "sha256",
  "match_details": {
    "item_hash_match": true,
    "root_hash_match": true
  }
}
```

## How It Works

### Verification Process

1. **Fetch the Item** - Retrieves the current item from the database
2. **Fetch the Collection** - Gets the trusted Merkle Root from the collection
3. **Download the Proof** - Retrieves the Merkle inclusion proof from the item's links
4. **Calculate Hash** - Computes the canonical hash of the item using JCS + double SHA256
5. **Verify Root** - Traverses the proof to verify the computed root matches the trusted root

### Verification Flow

```
┌──────────────────────────────────────────────────────────────────┐
│                  Merkle Verification Flow                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. GET /collections/{id}/items/{id}/verify                      |
│     ↓                                                            │
│  2. Fetch Item from Database                                     |
│     ↓                                                            │
│  3. Fetch Collection (get merkle:root)                           |
│     ↓                                                            │
│  4. Download Merkle Proof from Item Link                         |
│     ↓                                                            │
│  5. Canonicalize Item (JCS)                                      |
│     ↓                                                            │
│  6. Double Hash: SHA256(SHA256(canonical_json))                  |
│     ↓                                                            │
│  7. Traverse Proof Siblings (bottom-up)                          │
│     ├─ Combine with sibling hash                                 │
│     ├─ Double hash combination                                   │
│     └─ Move to parent level                                      │ 
│     ↓                                                            │
│  8. Compare Computed Root with Collection's merkle:root          |
│     ↓                                                            │
│  9. Return VerificationResult                                    |
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### Merkle Tree Proof Logic

```
                        Root Hash
                       /         \
                      /           \
                    H(AB)         H(CD)
                   /    \        /    \
                  A      B      C      D
                  
Proof for Leaf A:
  - Sibling: B (direction: right)
  - Sibling: H(CD) (direction: right)
  
Verification:
  1. Hash(A) = leaf_hash
  2. Hash(Hash(A) + B) = H(AB)
  3. Hash(H(AB) + H(CD)) = Root
  4. Root == merkle:root ✓
```

## API Endpoints

### Verify Item Integrity

**Endpoint**: `GET /collections/{collection_id}/items/{item_id}/verify`

**Parameters**:
- `collection_id` (path): The collection ID
- `item_id` (path): The item ID to verify

**Response**: `VerificationResult`

**Error Codes**:
- `404` - Item or collection not found
- `409` - Collection not initialized for Merkle verification (missing `merkle:root`)
- `502` - Could not retrieve proof file from storage

## Data Requirements

### Collection Properties

Collections must include a Merkle Root:

```json
{
  "id": "my-collection",
  "properties": {
    "merkle:root": "abc123def456..."
  }
}
```

### Item Links

Items must include a link to their Merkle proof:

```json
{
  "id": "my-item",
  "links": [
    {
      "rel": "merkle-proof",
      "href": "https://storage.example.com/proofs/my-item.json"
    }
  ]
}
```

### Proof File Format

Merkle proofs must be JSON files conforming to the standard specification:

```json
{
  "type": "MerkleProof",
  "version": "1.0.0",
  "leaf_hash": "8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4",
  "root_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "index": 4,
  "total_leaves": 15,
  "siblings": [
    {
      "hash": "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2",
      "direction": "right"
    },
    {
      "hash": "c5d6e7f8g9h0i1j2k3l4m5n6o7p8q9r0s1t2u3v4w5x6y7z8a9b0c1d2e3f4g5",
      "direction": "left"
    }
  ]
}
```

**Field Descriptions**:

- **type** (string): Always `"MerkleProof"` - identifies the proof format
- **version** (string): Proof format version (e.g., `"1.0.0"`)
- **leaf_hash** (string): SHA256(SHA256(canonical_item)) - the item's double hash
- **root_hash** (string): The expected Merkle root hash (for validation reference)
- **index** (integer): Position of this item in the tree (0-indexed)
- **total_leaves** (integer): Total number of items in the collection
- **siblings** (array): Path from leaf to root
  - **hash** (string): Sibling node's hash value
  - **direction** (string): Either `"left"` or `"right"` - position relative to current node

## Development

### Install Development Dependencies

```bash
pip install -r requirements-dev.txt
```

### Run Tests

```bash
pytest
```

### Code Quality

Format code with Black:

```bash
black .
```

Lint with Ruff:

```bash
ruff check . --fix
```

Type check with mypy:

```bash
mypy stac_fastapi_merkle
```

### Pre-commit Hooks

Install pre-commit hooks:

```bash
pre-commit install
```

## Architecture

### Backend Agnostic Design

The extension uses `BaseCoreClient` methods exclusively:
- `get_item(item_id, collection_id, request)` - Fetch items
- `get_collection(collection_id, request)` - Fetch collections

This ensures compatibility with any stac-fastapi backend without requiring backend-specific helpers.

### Security Considerations

- **Canonicalization**: JCS (RFC 8785) ensures deterministic JSON representation
- **Double Hashing**: SHA256(SHA256(x)) prevents length-extension attacks
- **Proof Validation**: Traverses the entire Merkle path to verify integrity
- **Circular Logic Prevention**: Excludes `merkle:object_hash` from item before hashing
- **SSRF Protection**: Validates proof URLs to prevent access to private IP ranges and localhost
- **Trusted Domain Whitelist**: Optional configuration to restrict proof URLs to specific domains

### Performance Optimizations

- **Non-Blocking Hashing**: CPU-intensive canonicalization and hashing operations run in a thread pool to prevent blocking the event loop
- **Async Throughout**: Full async/await support for high-concurrency verification
- **Efficient Proof Traversal**: Merkle path traversal is optimized for typical tree depths (10-30 levels)

## Conformance

This extension conforms to:
- STAC API Specification v1.0.0-beta.1
- RFC 8785 (JSON Canonicalization Scheme)
- STAC Merkle Verification Extension

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:
- Code passes all tests
- Code is formatted with Black
- Code passes Ruff linting
- Type hints are included
- Documentation is updated

## Author

Jonathan Healy

