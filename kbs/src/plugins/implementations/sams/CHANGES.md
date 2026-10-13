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
                                        POST /measurement/snp/auth
                                      SAMS:
                                        pre-verify params (policy)
                                        compute measurement
                                        sign ID Block (GUEST_SVN=MAGS)
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
                                          + guest_svn, family_id, ...
                                      ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
Secret release (same)                 Secret release (same)
```

[COMMENT_MG] it seems to me that the closer you are to the guest (image), the closer you would be to the ID key --> ID key is owner, auth key is Trustee

**Key difference:** With SAMS, a CVM whose launch configuration does not match
the signed ID Block is **prevented from booting entirely** by SNP firmware --
a misconfigured guest never reaches the attestation phase.

[COMMENT_MG] under non-malicious conditions. Under malicious conditions, I don't think anything can prevent CVM launch. That said, no security difference between CVM launch prevention and not releasing keys to the CVM.

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

- **MAGS** -- Monotonic counter in RVPS embedded as GUEST_SVN in ID Blocks. Lets verifier policies reject stale blocks without key rotation.

[COMMENT_MG] this would be novel. Normally, GUEST_SVN is purely a property of the guest image, for example, if the guest image corresponding to a new release contains code that addresses CVEs, then bump the GUEST_SVN, else don't bump. It's also important to keep in mind GUEST_SVN's role in key derivation: it can optionally be mixed into derived keys and, if it is, then derived keys can be requested for any GUEST_SVN value <= current GUEST_SVN. This reflects the convention in the example above where higher GUEST_SVN means more secure. Is this proposal consistent/compatible with this?

- **Signing-policies** -- Guest-owners upload Rego policies (over mTLS) mapping launch params to signing keypairs. SAMS evaluates server-side; private keys never reach the untrusted host.

[COMMENT_MG] examples of "launch params that map to signing keypairs"? FAMILY_ID and IMAGE_ID?

- **Authorization policy** -- Admin Rego policy gating ID Block issuance. Rejects non-compliant configs before they can boot.

## New API Surface

All under `/kbs/v0/sams/`. Guest-owner endpoints use mTLS.

| Endpoint | Auth | Purpose |
|---|---|---|
| `POST /measurement/<tee>/` | None | Compute measurement (+ ID Block if metadata provided) |
| `POST /measurement/<tee>/auth` | Bearer (optional) | Signed ID Block + IdAuth |
| `POST /signing/policy` | mTLS | Register guest-owner signing-policy |
| `DELETE /signing/policy` | mTLS | Revoke signing-policy + certs from RVPS |
| `DELETE /signing/key/<digest>` | mTLS | Revoke specific key endorsement |
| `POST /authorization/policy` | Admin | Set authorization policy (+ bump MAGS) |

[COMMENT_MG] This proposal involves SAMS putting something of value - rustee endorsement - in the ID Block. Since verifiers presumably pay attention to this, then all the APIs may need max auth/security (mTLS).

## What Does Not Change

RCAR protocol, KBS resource policy engine, CDH / guest-components.

> **Note:** The SNP verifier now emits additional claims (`id_key_digest`,
> `author_key_digest`, `family_id`, `image_id`, `guest_svn`) and the EAR token
> broker performs key endorsement checks before policy evaluation. These are
> additive — existing policies and flows are unaffected.

## Use w/ Kata-CoCo
Guest Owners who wish to run confidential workloads with pre-verification should:
1. Obtain an mTLS client certificate from the CA that SAMS is configured to trust (ask your Trustee admin)
2. **Then from a trusted environment,** register a signing-policy with SAMS over mTLS via `POST /kbs/v0/sams/signing/policy`
3. Finally, add these annotations to their pods & run `kubectl rollout restart`:
   - `"io.katacontainers.config.requirePreVerification": "true"`
   - `"io.katacontainers.config.guestOwnerIdentity": "<base64 of mTLS client cert>"`

[COMMENT_MG] Is 1 just telling guest owner to send cert. signing request (CSR) to "CA that SAMS is configured to trust"? 

> **Note:** Kata Runtime must be patched to intercept these annotations, request a
signed ID Block from SAMS, and pass `id-block`, `id-auth`, and
`author-key-enabled=on` to the hypervisor when launching the CVM. This
integration is not yet upstream in kata-containers.
