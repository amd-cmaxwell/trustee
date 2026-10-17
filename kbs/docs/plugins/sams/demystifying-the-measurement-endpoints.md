# POST /kbs/v0/sams/measurement/snp

> **Field naming convention:** The JSON request body uses `snake_case` field names
> (e.g. `guest_policy`, `family_id`). The prose and SNP spec references use
> UPPER_CASE (e.g. GUEST_POLICY, FAMILY_ID). They refer to the same fields.

## Headers
None
## Request Body
```json
{
    vcpus: <Number of CPUs available to the CVM as a u32>,
    vcpu_type: "<CpuType enum variant identifying the CPU generation, e.g. EPYC, EpycV1, EpycV2, ...>",
    vmm_type: "<VMMType enum variant identifying the hypervisor, e.g. QEMU, EC2, KRUN>",
    guest_features: <Kernel Guest Features Bitflag as a u64>,
    ovmf_measurement: "<base64-encoded OvmfMeasurement containing the OVMF metadata and launch digest, produced by get_snp_ovmf_measurement()>",
    initrd_hash_str: "<Precalculated Cryptographic Hash of the initial filesystem the CVM will use>",
    kernel_hash_str: "<Precalculated Cryptographic Hash of the kernel file the CVM will use>",
    append: "<Kernel Cmdline Arguments...>",
    guest_policy: <Guest Policy bitflag as an integer>,
    guest_svn: <Guest Security Version Number as a u32 (optional, defaults to 0)>,
    family_id: "<Hex-encoded 16-byte identifier for the group to which the ID Block belongs>",
    image_id: "<Hex-encoded 16-byte identifier for the CVM image>"
}
```

## Responses
1. If you send your CVM Launch Params, then the response body contains: 
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>"
        }
        ```
    - Error Codes
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
2. If you ALSO send IDBlock Metadata (`GUEST_POLICY`, `FAMILY_ID`, & `IMAGE_ID`), then
the response body contains:
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>",
            "id-block": "base64({
                LaunchMeasurement = "<measurement>",
                GuestPolicy,
                FamilyID,
                ImageID,
                GuestSVN = guest-owner-specified SVN (defaults to 0),
                ...
            })"
        }
        ```
    - Error Codes
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
# POST /kbs/v0/sams/measurement/snp/signed
## Headers
`Authorization: Bearer <JWT containing the field "certificate": "<guest-owner client certificate (PEM)>">` _(optional)_

## Request Body
```json
{
    vcpus: <Number of CPUs available to the CVM as a u32>,
    vcpu_type: "<CpuType enum variant identifying the CPU generation, e.g. EPYC, EpycV1, EpycV2, ...>",
    vmm_type: "<VMMType enum variant identifying the hypervisor, e.g. QEMU, EC2, KRUN>",
    guest_features: <Kernel Guest Features Bitflag as a u64>,
    ovmf_measurement: "<base64-encoded OvmfMeasurement containing the OVMF metadata and launch digest, produced by get_snp_ovmf_measurement()>",
    initrd_hash_str: "<Precalculated Cryptographic Hash of the initial filesystem the CVM will use>",
    kernel_hash_str: "<Precalculated Cryptographic Hash of the kernel file the CVM will use>",
    append: "<Kernel Cmdline Arguments...>",
    guest_policy: <Guest Policy bitflag as an integer (REQUIRED for /auth)>,
    guest_svn: <Guest Security Version Number as a u32 (optional, defaults to 0)>,
    family_id: "<Hex-encoded 16-byte identifier (REQUIRED for /auth)>",
    image_id: "<Hex-encoded 16-byte identifier (REQUIRED for /auth)>"
}
```

## Responses

1. If you send Launch Parameters & IDBlock Metadata 
**AND** the authorization policy approves of your submitted launch params & ID Block Metadata, then
the response body contains:
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>",
            "id-block": "base64({
                LaunchMeasurement = "<measurement>",
                GuestPolicy,
                FamilyID,
                ImageID,
                GuestSVN = guest-owner-specified SVN (defaults to 0),
                ...
            })",
            "id-auth": "base64({
                IdBlockSig = IdBlockAlgo(SAMS Private Key, IDBlock), 
                IdBlockAlgo = <integer rep of Ecdsa-384>,
                IdKeyDigest = SHA-384(SAMS Public Key),
                IdKeySig = 0,
                AuthKeyAlgo = 0,
                AuthKeyDigest = 0
            })",
            "id-key": "<SAMS Public Key (DER, base64-encoded)>",
            "cage": {
                "mage": <Current Measurement Audit Generation Epoch as u32>,
                "id_block_hash": "<SHA-384 hex digest of the IdBlock bytes>",
                "signature": "<base64 ECDSA-SHA384 signature over canonical JSON {\"id_block_hash\": \"...\", \"mage\": N, \"salt\": \"...\"}>"
            }
        }
        ```
    > **CAGE (SAGE Protocol):** The CAGE binds the audit generation epoch to this
    > specific IdBlock. The signature covers the `id_block_hash`, `mage`, and a
    > per-epoch salt (mixed into the signature but not returned in the response),
    > preventing a malicious host from pairing a CAGE with an IdBlock it was
    > not issued for. The salt prevents replay if the MAGE is ever reset; verifiers
    > retrieve the salt for each epoch directly from RVPS. See
    > [Reclaiming the Guest SVN Field](reclaiming-the-guest-svn-field.md) for the full
    > design rationale.
    - Error Codes:
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
        2. If you fail to provide the IDBlock Metadata fields (`FAMILY_ID` & `IMAGE_ID`):
            `400 - Bad Request`
        3. If CVM Launch is Forbidden by the authorization policy:
            `403 - Forbidden` 
2. **If ON TOP OF THAT, YOU SEND A Bearer Token containing a client certificate for a *REGISTERED* guest-owner (one who has uploaded a signing-policy via `POST /signing/policy`),** 
***AND* the authorization policy approves of your launch params, ID Block Metadata, & parsed client certificate** (the cert is provided to the policy as a structured `guest_owner_cert` object with `subject`, `issuer`, `serial`, `not_before`, `not_after`, and `extensions` fields)**, then**
SAMS evaluates the guest-owner's **signing-policy** with the launch params as input. The policy selects which signing keypair to use by outputting `data.policy.pubkey` and `data.policy.privkey`. The response body contains:
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>",
            "id-block": "base64({
                LaunchMeasurement = "<measurement>",
                GuestPolicy,
                FamilyID,
                ImageID,
                GuestSVN = guest-owner-specified SVN (defaults to 0),
                ...
            })",            
            "id-auth": "base64({
                IdBlockSig = IdBlockAlgo(SAMS Priv Key, IDBlock), 
                IdBlockAlgo = <integer rep of Ecdsa-384>,
                IdKeyDigest = SHA-384(SAMS Pub Key),
                IdKeySig = AuthKeyAlgo(Policy-Selected Guest Owner Priv Key, SAMS Pub Key),
                AuthKeyAlgo = <integer rep of Ecdsa-384>,
                AuthKeyDigest = SHA-384(Policy-Selected Guest Owner Pub Key)
            })",
            "id-key": "<SAMS Public Key (DER, base64-encoded)>",
            "author-key": "<Guest Owner Public Key (selected by signing-policy)>",
            "cage": {
                "mage": <Current Measurement Audit Generation Epoch as u32>,
                "id_block_hash": "<SHA-384 hex digest of the IdBlock bytes>",
                "signature": "<base64 ECDSA-SHA384 signature over canonical JSON {\"id_block_hash\": \"...\", \"mage\": N, \"salt\": \"...\"}>"
            }
        }
        ```
    Additionally, SAMS:
    - Appends the guest-owner's mTLS certificate to the RVPS `"guest-owner-certs"` list for the AuthKeyDigest of the policy-selected key. Multiple guest-owners sharing a signing key are stored as separate entries under the same digest.
    - Stores the guest-owner's public signing key in the RVPS `"guest-owner-pubkeys"` map, keyed by AuthKeyDigest, so that verifiers can retrieve the full public key using the digest from the attestation report.
    - Error Codes:
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
        2. If you fail to provide the IDBlock Metadata fields (`FAMILY_ID` & `IMAGE_ID`):
            `400 - Bad Request`
        3. If your Bearer Token is malformed:
            `401 - Unauthorized`
        5. If your Bearer Token is expired:
            `401 - Unauthorized`
        4. If your Bearer Token doesn't contain a valid client certificate:
            `401 - Unauthorized`
        4. If no signing-policy is registered for the client certificate in your Bearer Token:
            `401 - Unauthorized`
        5. If the signing-policy does not produce valid keys for these launch params:
            `403 - Forbidden`
        6. If the authorization policy rejects your Launch Params, ID Block Metadata, &/or client cert:
            `403 - Forbidden`
