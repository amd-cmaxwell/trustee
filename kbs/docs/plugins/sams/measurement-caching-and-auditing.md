# Adding Caching & Auditing to the Measurement Endpoints

## Background
There are Two issues we are trying to solve:
1. Requesting ID Blocks from a central authority (SAMS) creates a bottleneck around starting CVMs
2. A true "Trusted Enivornment" should be able to audit all interactions with that system.

This proposal aims to solve both. 

## Requirements
- Avoid redundant `snp_calc_launch_digest` calls for repeated launch configurations
- Record which guest owner requested signing of which IdBlock, under which MAGE, and with which keys
- No new storage dependencies -- reuse the existing `KeyValueStorage` trait from `deps/key-value-storage`
- Measurement cache must not serve stale data when the SAMS keypair rotates

## Solution - Measurement Metadata Auditing (MMA) Protocol

### Advantages
- IdBlock / Measurement Caching avoids unnecessary repeated crypto operations in trustee
- Facilitates a historical overview (an audit log) of IdBlock distribution in SAMS

### Design

#### What is cacheable and what is not

The launch digest (`snp_calc_launch_digest`) is a pure function of VM configuration
parameters. It does not depend on the SAMS signing key, the MAGE, or the guest owner.
This makes it safe to cache indefinitely with no invalidation logic.

The IdBlock is also deterministic given the digest and the metadata fields (family_id,
image_id, guest_policy, guest_svn), so it can be cached alongside the digest.

The following are NOT cacheable:
- **IdAuth** -- ECDSA signature over the IdBlock using the SAMS `id_key`, changes on key rotation
- **IdKey** -- the SAMS public key, changes on key rotation
- **CAGE token** -- JWT signed with `id_key`, includes the MAGE counter which increments

This separation means the cache never needs invalidation on key rotation. The expensive
computation (OVMF page hashing) is what gets cached; the cheap operations (IdBlock packing,
ECDSA signing) still run fresh every request.

#### Storage layout

Both the cache and the audit log use the existing `KeyValueStorage` trait, configured
via the same storage backend as the rest of Trustee (Postgres, Redis, local JSON, local FS,
or in-memory). Two namespaced stores:

**1. Measurement cache** (namespace: `sams-measurement-cache`)
- Key: hex-encoded SHA-256 of the canonicalized measurement inputs
  (`vcpus`, `vcpu_type`, `vmm_type`, `guest_features`, `ovmf_measurement`,
  `kernel_hash_str`, `initrd_hash_str`, `append`)
- Value: serialized `CachedMeasurement` containing
    - The hex-encoded launch digest
    - The base64-encoded IdBlock (when metadata fields were provided)
- On cache hit, skip `snp_calc_launch_digest` and IdBlock construction entirely

**2. Audit log** (namespace: `sams-audit-log`)
- Key: `{mage}-{timestamp}-{digest_prefix}` (sortable by MAGE, then time)
- Value: serialized Measurement Metadata Object (MMO), see below
- Append-only -- `set` with `overwrite: false`

#### Measurement Metadata Object (MMO)

The MMO is the audit record written on each successful `/measurement/snp/signed` request:

- **Launch params**: vcpus, vcpu_type, vmm_type, guest_features, ovmf_measurement,
  kernel_hash_str, initrd_hash_str, append
- **IdBlock metadata**: family_id, image_id, guest_policy, guest_svn
- **Guest owner identity**: hash of the guest-owner certificate (or full PEM if configured).
  When no Bearer Token with a valid guest-owner certificate is provided, the field
  is set to `"anonymous"` or the originating IP address of the request, depending
  on configuration. This covers the case where an authorized set of launch params
  is submitted to `/measurement/snp/signed` without guest-owner identification.
- **MAGE**: the measurement audit generation epoch at time of signing
- **SAMS key fingerprint**: hash of the SAMS public key used to sign the IdAuth
- **Timestamp**: ISO 8601 UTC

### Process

#### Adding Audit Log Entries
- When a set of launch params passes Authorization Policy scrutiny on the
  `/measurement/snp/signed` path, an MMO for that launch configuration is created.
- The MMO is written with a composite key prefixed by the current MAGE,
  making it possible to enumerate all entries for a given epoch.
- Audit log writes happen after successful signing but before returning the response,
  so a signed IdBlock is never delivered without a corresponding audit record.

#### Retrieving Audit Log Entries
- List all keys with `list()`, filter by MAGE prefix client-side
- Fetch individual entries with `get(key)`
- Primary access pattern: "what was signed under MAGE N?" -- scan keys starting with `{N}-`

#### Managing Audit Log Entries
- When the MAGE changes, walk keys with the old MAGE prefix to produce a summary or archive
- Entries are append-only and should not be deleted in normal operation
- The measurement cache can be cleared freely at any time without data loss --
  it will repopulate on the next request for each configuration

### Questions & Concerns
- If reducing latency on CVM launch is the goal, is it actually better to have trustee eat the compute cost (5+ rounds of SHA-384 per request) than to add database latency & cache invalidation semantics?
    - With this design, cache invalidation is not a concern -- the cached value (launch digest)
      is a pure function that never goes stale. Database latency for a key-value lookup
      is negligible compared to the OVMF page hashing in `snp_calc_launch_digest`.
- The `KeyValueStorage` trait does not support range queries or secondary indexes.
  If richer audit queries are needed (e.g. "all IdBlocks signed for guest owner X"),
  the Postgres backend could be extended, or a dedicated query endpoint could filter
  client-side. For now, MAGE-prefixed key scans cover the primary access pattern.

## Conclusion
> Stop fighting the system. Take up MMA, today.
