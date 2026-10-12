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

The signing-policy is a Rego policy that receives launch params as input and outputs
`data.policy.pubkey` and `data.policy.privkey` (PEM-encoded EC key strings). This allows
guest-owners to define multiple signing keypairs and have SAMS select the appropriate one
based on the launch parameters:
    - Example Usage:
        **Note**: the ca.crt is the certificate of the TLS Certificate Authority who has issued leaf-certs to both the guest owner & to the mTLS proxy
        ```shell
        # Guest Owner registers a signing-policy w/ SAMS
        encoded_policy=$(base64 <<'EOF'
        package policy
        import rego.v1

        # Simple policy with a single keypair
        pubkey := "<PEM public key>"
        privkey := "<PEM private key>"
        EOF
        )

        curl \
            --cert guest-owner-client.crt \
            --key guest-owner-client.key \
            --cacert ca.crt \
            -X POST https://$kbs_host:$kbs_api_port/kbs/v0/sams/signing/policy \
            -H "Content-Type: application/json" \
            -d "{\"signing_policy\": \"$encoded_policy\"}"
        ```

    An advanced policy that selects different keypairs based on launch params:
        ```rego
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
- ***Inside of Trustee:***
    - **SAMS validates and stores the signing-policy** in SAMS internal storage, keyed by the SHA-384 hash of the guest-owner's mTLS client certificate.
### Requesting an ID Block
- ***From the UNTRUSTED Host:***
The ID Block Requester (Kata-Runtime) can opt to send the `/sams/measurement/snp/auth` Endpoint a Bearer Token containing a JWT with the Guest Owner's client certificate in the `"certificate"` claim. Since the certificate is public, it is safe to give to the untrusted host.
Doing so will trigger SAMS to evaluate the Guest Owner's signing-policy and use the resulting keypair in the produced `IDAuth` information.

    > **Security Note:** Possession of the public certificate does NOT grant the ability to register or revoke signing-policies — that requires the mTLS private key for the TLS handshake with the proxy. This separation ensures it is safe to give the certificate to the untrusted kata-runtime.

    > **NOTE: For the full explaination see *[Demystifying the Measurement Endpoints](demystifying-the-measurement-endpoints.md)***
- ***Inside of Trustee:***

    - **IF ADEQUATE LAUNCH PARAMS WERE PROVIDED,**
    SAMS will calculate the Launch Measurement for the provided launch params & include them in the response body under the `"measurement"` field.
        
    - **IF the *`FAMILY_ID`* & *`IMAGE_ID`* fields were included in the request,** then
    SAMS will create an IDBlock containing the Launch Measurement, Family ID, Image ID, & the current Minimum Acceptable Guest SVN (MAGS) pulled from RVPS.

        **This IDBlock will be included, *base64-encoded*, in the response body under the *`"id-block"`* field.**
    
    - **IF the request headers include a Bearer Token containing a JWT with the guest-owner's client certificate in the `"certificate"` claim,** then
    SAMS will:
        1. Extract the certificate from the JWT's `"certificate"` claim and hash it (SHA-384)
        2. Check that a signing-policy is stored for that cert hash
        3. Reject the request with `401 - Unauthorized` if no signing-policy is found
        4. Pass the certificate into the authorization policy engine, alongside the CVM launch parameters & ID Block metadata, for SAMS Policy Owners to make assertions about.
            - This allows SAMS policy owners to make assertions about all the data contained inside the Guest Owner's client certificate, including but not limited to the contents of the `Subject` & `Extensions` fields
    
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
        9. **Register the guest-owner's mTLS cert in RVPS** under the `"guest-owner-certs"` reference value, keyed by the AuthKeyDigest of the policy-selected key
        
### Verifying an Attestation Report
- Verifier Policy Owners will be able to look up Guest Owner client certs from RVPS and make assertions about them in Verifier policies.
- Verifiers can find the certificate for a guest owner using the Rego expression: `query_reference_value("guest-owner-certs")[<AuthKeyDigest>]` where `<AuthKeyDigest>` is the AuthKeyDigest field from the attestation report.
    - This allows Verifier policies to make assertions about all the data contained inside the Guest Owner's client certificate, including but not limited to the contents of the `Subject` & `Extensions` fields.

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
        3. Removes all of the guest-owner's cert entries from the RVPS `"guest-owner-certs"` map (matching by certificate value)

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
        2. Looks up the RVPS `"guest-owner-certs"` entry for that AuthKeyDigest
        3. If found, verifies the stored cert matches the caller's mTLS cert (returns `403` if mismatched)
        4. Removes the entry from RVPS
        5. Returns `200 OK` (idempotent: deleting a non-existent key also returns `200`)

## Additional Overhead
### For Trustee Admins
- Trustee admins must configure KBS with `tls_client_ca_cert` pointing to the CA certificate for client cert verification, OR deploy a TLS-terminating reverse proxy that enforces mTLS and forwards the `X-Client-Cert` header.
- Trustee admins must remember to rotate CA certs before they expire, else they risk Guest Owners not being able to register signing-policies with SAMS.

### For Guest Owners
- Guest Owners must obtain a client certificate & private key from a trusted TLS Certificate Authority recognized by the mTLS proxy or KBS.
- Guest Owners must remember to rotate their client certs before they expire, else they risk not being able to register or revoke signing-policies with SAMS.
- Guest Owners are responsible for embedding their signing keypairs in their Rego signing-policies. The policies should be crafted to select the appropriate keypair based on the expected launch parameters.
