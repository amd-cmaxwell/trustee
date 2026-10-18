# What SAMS Changes in the Trustee Attestation Flow

SAMS is a KBS plugin that adds **pre-launch verification** to the attestation
flow. It computes CVM launch measurements server-side, signs ID Blocks, and
embeds a Trustee endorsement into the attestation report. The RCAR handshake
is unchanged.

SAMS is opt-in and additive. Without the `requirePreVerification` annotation
on a pod, the standard flow is used unchanged.

## Before and After

```
STANDARD                              WITH SAMS
────────                              ─────────
                                      Kata Runtime ──> SAMS
                                        POST /measurement/snp/signed
                                      SAMS:
                                        pre-verify params (policy)
                                        compute measurement
                                        sign ID Block + produce CAGE
                                      SAMS ──> Kata Runtime
                                        id-block, id-auth, id-key
                                      ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
Launch CVM (no ID Block)              Launch CVM with ID Block
                                        SNP firmware verifies
                                        sigs + measurement in
                                        ID Block matches
                                        actual measurement
                                      ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
CVM boots ──> RCAR handshake          CVM boots ──> RCAR handshake
  (same)                                (same, but report carries
                                         IDBlock/IDAuth fields)
AS verifies report                    AS verifies report
  measurement vs RVPS blobs             broker checks IDKeyDigest
                                          against SAMS pubkey in RVPS
                                        broker checks AuthKeyDigest
                                          against owner pubkeys in RVPS
                                        policy sees endorsed flags
                                          + guest_svn (guest-owner-
                                           controlled), family_id, ...
                                      ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
Secret release (same)                 Secret release (same)
```

**Key difference:** With SAMS, a CVM whose launch configuration does not match
the signed ID Block is **prevented from booting entirely** by SNP firmware --
a misconfigured guest never reaches the attestation phase.

## What Changes

| Area | Standard | With SAMS |
|---|---|---|
| **Verification timing** | After boot only | Before boot (firmware) **and** after boot |
| **Measurement computation** | Offline by admin, uploaded to RVPS | Server-side by SAMS from launch params |
| **ID Block** | Not used | SAMS signs it; firmware enforces at boot |
| **Trustee endorsement** | Not in report | IDKeyDigest = SAMS key hash; broker verifies against RVPS and injects `sams_id_key_endorsed` |
| **Guest-owner identity** | Not in report | AuthKeyDigest = owner key hash; broker injects `author_key_endorsed` + parsed `guest_owner_certs` (subject, issuer, extensions) for policy assertions |
| **Bad config at boot** | Boots, fails attestation later | Fails to boot |

## New Concepts

- **MAGE/CAGE** -- MAGE is a monotonic counter tracking audit generations. SAMS produces a CAGE Token (Current Audit Generation Epoch), a signed JWT containing the full IdBlock, IdAuth, MAGE, and guest-owner identity. The CAGE Token is returned alongside signed ID Blocks and expected to be placed in CVM InitData for verification during attestation.
- **Signing-policies** -- Guest-owners upload Rego policies (over mTLS) mapping launch params to signing keypairs. SAMS evaluates server-side; private keys never reach the untrusted host.
- **Authorization policy** -- Admin Rego policy gating ID Block issuance. Rejects non-compliant configs before they can boot.
- **MMA (Measurement Metadata Auditing)** -- Every successful `/measurement/<tee>/signed` request writes a Measurement Metadata Object (MMO) to the audit log, recording launch params, IdBlock metadata, guest-owner identity (or `"anonymous"`), MAGE, and SAMS key fingerprint. Launch digest computation is cached to avoid redundant crypto. See [Measurement Caching & Auditing](measurement-caching-and-auditing.md).

## New API Surface

All under `/kbs/v0/sams/`. Guest-owner endpoints use mTLS.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /measurement/<tee>/` | None | Compute measurement (+ ID Block if metadata provided) |
| `POST /measurement/<tee>/signed` | Bearer (optional) | Signed ID Block + IdAuth |
| `GET /signing/identity-provider` | None | Discover CA URL for obtaining mTLS client certificates |
| `POST /signing/policy` | mTLS | Register guest-owner signing-policy |
| `DELETE /signing/policy` | mTLS | Revoke signing-policy + certs from RVPS |
| `DELETE /signing/key/<digest>` | mTLS | Revoke specific key endorsement |
| `POST /authorization/policy` | Admin | Set authorization policy (+ bump MAGE) |
| `GET /authorization/policy` | Admin | Retrieve current authorization policy and MAGE value |

## What Does Not Change

RCAR protocol, KBS resource policy engine, CDH / guest-components.

> **Note:** The SNP verifier now emits additional claims (`id_block_en`,
> `id_key_digest`, `author_key_digest`, `family_id`, `image_id`, `guest_svn`)
> and the EAR token broker performs key endorsement checks (gated on
> `id_block_en`) before policy evaluation. These are additive — existing
> policies and flows are unaffected.

## Use w/ Kata-CoCo
Guest Owners who wish to run confidential workloads with pre-verification should:
1. Obtain an mTLS client certificate from the CA that SAMS is configured to trust
    - **Work with your Trustee admin to obtain an appropriate certificate.**
    - If Trustee has been configured to use a TLS certificate issued by a commerical/automated identify provider, then guest-owners can query the `GET /sams/signing/identity-provider` endpoint to obtain the URL of the issuing certificate authority.
2. **From a trusted environment,** register a signing-policy with SAMS over mTLS via `POST /kbs/v0/sams/signing/policy`
3. Finally, add these annotations to their pods on the Untrusted Host & run `kubectl rollout restart`:
   - `"io.katacontainers.config.hypervisor.requirePreVerification": "true"`
   - `"io.katacontainers.config.hypervisor.guestOwnerIdentity": "<base64 of mTLS client cert>"`

> **Note:** Kata Runtime must be patched to intercept these annotations, request a
signed ID Block from SAMS, and pass `id-block`, `id-auth`, and
`author-key-enabled=on` to the hypervisor when launching the CVM. This
integration is not yet upstream in kata-containers.
