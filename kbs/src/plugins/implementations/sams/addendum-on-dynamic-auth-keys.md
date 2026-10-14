# Revisiting ID Block Author Keys...
> **Predicate:** 
> Since SAMS runs in the trusted environment (Trustee), Guest-Owners should feel comfortable entrusting signing-policy definitions to SAMS.
## Background:
### The Ask: 
    Guest Owners need their ID Block AuthorKey fields to reflect Keys owned directly by them
### The Rub: 
    Guest Owners cannot entrust their Private Keys to the software requesting the creation & signing of the ID Block (eg Kata-Runtime) as it's running on the Untrusted Host
### The Solution: 
    Have Guest Owners upload a signing-policy to Trustee (since it's running in a Trusted Environment) that defines which signing keypairs to use based on the launch parameters

## Updated Flow:
### Guest Owner Registration
- ***FROM A TRUSTED ENVIRONMENT:*** 
Guest Owners should "register" a "signing-policy" with SAMS over an mTLS connection.
The mTLS handshake is terminated by a reverse proxy (e.g. nginx, envoy) which forwards the
verified client certificate to SAMS via the `X-Client-Cert` header.
- ***Inside of Trustee:***
    - **SAMS validates and stores the signing-policy** in SAMS internal storage, keyed by the SHA-384 hash of the guest-owner's mTLS client certificate.

The signing-policy is a Rego policy that receives launch params as input and outputs
`data.policy.pubkey` and `data.policy.privkey` (PEM-encoded EC key strings). This allows
guest-owners to define multiple signing keypairs and have SAMS select the appropriate one
based on the launch parameters,

#### Example Usage:

```shell
# Guest Owner registers a signing-policy w/ SAMS
encoded_policy=$(base64 signing-policy.rego)
curl \
    --cert guest-owner-client.crt \
    --key guest-owner-client.key \
    --cacert ca.crt \
    -X POST https://$kbs_host:$kbs_api_port/kbs/v0/sams/signing/policy \
    -H "Content-Type: application/json" \
    -d "{\"signing_policy\": \"$encoded_policy\"}"
```

> **Note**: the ca.crt is the CA certificate that SAMS (or its mTLS proxy) is configured to trust for client certificate verification. The guest owner's client cert must be issued by this CA.

#### Example Signing Policies:
##### The Elementary Signing Policy:
```rego
# The most basic signing policy is as follows:

# In all cases, 
#  IDBlocks generated for this guest-owner
#  should be signed with the provided keypair

package policy
import rego.v1

pubkey := "<PEM public key>"
privkey := "<PEM private key>"
```

##### An Advanced Signing Policy:
```rego
# An advanced policy that selects different keypairs based on launch params:

package policy
import rego.v1

# Use one keypair for production family, another for staging
pubkey := "<prod PEM public key>" if {
    input.family_id == "0123456789abcdef"
}
pubkey := "<staging PEM public key>" if {
    input.family_id == "fedcba9876543210"
}

privkey := "<prod PEM private key>" if {
    input.family_id == "0123456789abcdef"
}
privkey := "<staging PEM private key>" if {
    input.family_id == "fedcba9876543210"
}
```

### Requesting an ID Block
- ***From the UNTRUSTED Host:***
The ID Block Requester (Kata-Runtime) can opt to send the `/sams/measurement/snp/auth` Endpoint a Bearer Token containing a JWT with the Guest Owner's client certificate in the `"certificate"` claim. Since the certificate is public, it is safe to give to the untrusted host.
Doing so will trigger SAMS to evaluate the Guest Owner's signing-policy and use the resulting keypair in the produced `IDAuth` information.

    > **Security Note:** Possession of the public certificate does NOT grant the ability to register or revoke signing-policies — that requires the mTLS private key for the TLS handshake with the proxy. This separation ensures it is safe to give the certificate to the untrusted kata-runtime.

    > **NOTE: For the full explaination see *[Demystifying the Measurement Endpoints](demystifying-the-measurement-endpoints.md)***
- ***Inside of Trustee:***

    - **IF ADEQUATE LAUNCH PARAMS WERE PROVIDED,**
    SAMS will calculate the Launch Measurement for the provided launch params & include them in the response body under the `"measurement"` field.
        
    - **IF the *`GUEST_POLICY`*, *`FAMILY_ID`* & *`IMAGE_ID`* fields were included in the request,** then
    SAMS will create an IDBlock containing the Launch Measurement, Guest Policy, Family ID, Image ID, & the current Minimum Acceptable Guest SVN (MAGS) pulled from RVPS.

        **This IDBlock will be included, *base64-encoded*, in the response body under the *`"id-block"`* field.**
    
    - **IF the request headers include a Bearer Token containing a JWT with the guest-owner's client certificate in the `"certificate"` claim,** then
    SAMS will:
        1. Extract the certificate from the JWT's `"certificate"` claim and hash it (SHA-384)
        2. Check that a signing-policy is stored for that cert hash
        3. Reject the request with `401 - Unauthorized` if no signing-policy is found
        4. Parse the certificate into a structured JSON object (`guest_owner_cert`) containing `subject`, `issuer`, `serial`, `not_before`, `not_after`, and `extensions` fields, and pass it into the authorization policy engine alongside the CVM launch parameters & ID Block metadata.
            - This allows SAMS policy owners to make assertions about the Guest Owner's client certificate fields, e.g. `input.guest_owner_cert.subject.O == "Acme Corp"` or `input.guest_owner_cert.extensions.subject_alt_names[0] == "guest.example.com"`
    
    - **If evaluation of the authorization policy returns "authorized",**
    SAMS will:
        1. Evaluate the guest-owner's signing-policy with the launch params as input
        2. Extract `data.policy.pubkey` and `data.policy.privkey` from the policy result
        3. Reject with `403 - Forbidden` if the policy does not produce valid keys for these launch params
        4. Create an IdBlockSig, a Signature of the IDBlock using SAMS' private key
        5. Create an IdKeySig, a Signature of the IDKey (SAMS' Public Key) using the policy-selected guest-owner Private Key
        6. Create an IdAuth struct containing
            1. The IdBlockSig
            2. The IDBlockAlgo (an integer identifying which signing function created IdBlockSig)
            3. The IDKeyDigest (SHA-384 hash of the SAMS Pubkey)
            4. The IdKeySig
            4. The AuthKeyAlgo (an integer identifying which signing function created IdKeySig)
            5. The AuthKeyDigest (SHA-384 hash of the policy-selected Guest Owner Pubkey)
        7. **Include the IdAuth struct, base64-encoded, in the reponse body under the *`id-auth`* field**
        8. **Include the following fields in the response body for verification purposes:**
            - The IDKey (SAMS' Public Key)
            - The AuthorKey (Guest Owner's Public Key, as selected by the signing-policy)
        9. **Append the guest-owner's mTLS cert to the RVPS `"guest-owner-certs"` list** for the AuthKeyDigest of the policy-selected key (multiple guest-owners sharing a signing key are stored as separate entries under the same digest)
        10. **Store the guest-owner's public signing key in the RVPS `"guest-owner-pubkeys"` map**, keyed by AuthKeyDigest (so verifiers can retrieve the full public key from the digest in the attestation report)
        
### Verifying an Attestation Report
- The SNP verifier now emits `id_block_en`, `id_key_digest`, `author_key_digest`, `author_key_en`, `family_id`, `image_id`, and `guest_svn` as claims from the attestation report. `id_block_en` is a derived boolean that is `true` when the report's `id_key_digest` is not all zeros.
- Before policy evaluation, the EAR token broker automatically verifies key endorsement (only when `id_block_en` is `true`):
    - It retrieves the SAMS IDKey public key from RVPS (`"sams-id-key"`), computes its SHA-384 digest, and compares it against the report's `id_key_digest`. The result is injected as a `sams_id_key_endorsed` boolean claim.
    - If `author_key_en` is true, the broker checks whether `author_key_digest` exists as a key in the RVPS `"guest-owner-pubkeys"` map. The result is injected as an `author_key_endorsed` boolean claim.
    - If `author_key_en` is true, the broker also retrieves the guest-owner's mTLS certificates from RVPS (`"guest-owner-certs"` list for the AuthKeyDigest), parses each PEM certificate into a structured JSON object, and injects them as `guest_owner_certs` in the claims. Each object contains `subject`, `issuer`, `serial`, `not_before`, `not_after`, and `extensions` fields.
- Verifier Policy Owners can use `sams_id_key_endorsed`, `author_key_endorsed`, and `guest_owner_certs` in their policies to set trust claims accordingly.
- Example policy assertion: `input.guest_owner_certs[i].subject.O == "Acme Corp"` or `input.guest_owner_certs[i].extensions.subject_alt_names[j] == "guest.example.com"`.

### Guest Owner Revocation
- ***FROM A TRUSTED ENVIRONMENT:*** 
Guest Owners can revoke their signing-policy and all associated RVPS endorsements over an mTLS connection (via the same proxy setup as registration):
    - Revoke signing-policy and all signing-key endorsements:
        ```shell
        curl \
            --cert guest-owner-client.crt \
            --key guest-owner-client.key \
            --cacert ca.crt \
            -X DELETE https://$kbs_host:$kbs_api_port/kbs/v0/sams/signing/policy
        ```
    - Upon receiving the revocation request, the handler:
        1. Extracts the client cert from the `X-Client-Cert` header (set by the mTLS proxy)
        2. Hashes the client cert (SHA-384) and deletes the guest-owner's signing-policy from SAMS storage
        3. Removes the guest-owner's cert from all `"guest-owner-certs"` lists in RVPS (matching by certificate value), dropping any AuthKeyDigest entries whose list becomes empty

### Individual Signing-Key Revocation
- Guest Owners can also revoke individual signing-key endorsements from RVPS without removing their signing-policy:
    - Revoke a specific signing-key endorsement:
        ```shell
        auth_key_digest_b64=$(echo -n "<hex-encoded AuthKeyDigest>" | base64)

        curl \
            --cert guest-owner-client.crt \
            --key guest-owner-client.key \
            --cacert ca.crt \
            -X DELETE https://$kbs_host:$kbs_api_port/kbs/v0/sams/signing/key/$auth_key_digest_b64
        ```
    - Upon receiving the request, the handler:
        1. Base64-decodes the AuthKeyDigest from the URL path
        2. Looks up the RVPS `"guest-owner-certs"` list for that AuthKeyDigest
        3. If found, verifies the caller's mTLS cert is in the list (returns `403` if not present)
        4. Removes the caller's cert from the list, dropping the AuthKeyDigest entry if the list becomes empty
        5. If the AuthKeyDigest entry was fully removed, also removes the corresponding entry from `"guest-owner-pubkeys"` in RVPS
        6. Returns `200 OK` (idempotent: deleting a non-existent key also returns `200`)

## Additional Overhead
### For Trustee Admins
- Trustee admins must configure KBS with `tls_client_ca_cert` pointing to the CA certificate for client cert verification, OR deploy a TLS-terminating reverse proxy that enforces mTLS and forwards the `X-Client-Cert` header.
- Trustee admins must remember to rotate CA certs before they expire, else they risk Guest Owners not being able to register signing-policies with SAMS.

### For Guest Owners
- Guest Owners must obtain a client certificate & private key from a trusted TLS Certificate Authority recognized by the mTLS proxy or KBS.
- Guest Owners must remember to rotate their client certs before they expire, else they risk not being able to register or revoke signing-policies with SAMS.
- **After rotating an mTLS certificate, Guest Owners must re-register their signing-policy with SAMS using the new certificate.** The signing-policy is keyed internally by the SHA-384 hash of the client certificate, so a rotated cert is a new identity from SAMS' perspective. The old cert's RVPS endorsements will remain until explicitly revoked via `DELETE /signing/policy` using the old cert (before it expires) or cleaned up by an admin.
- Guest Owners are responsible for embedding their signing keypairs in their Rego signing-policies. The policies should be crafted to select the appropriate keypair based on the expected launch parameters.
