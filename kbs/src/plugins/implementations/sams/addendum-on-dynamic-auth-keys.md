# Revisiting ID Block Author Keys...
> **Predicate:** 
> Since SAMS runs in the trusted environment (Trustee), Guest-Owners should feel comfortable sending Private-Key data to SAMS for storage in KBS.
## Background:
### The Ask: 
    Guest Owners need their ID Block AuthorKey fields to reflect Keys owned directly by them
### The Rub: 
    Guest Owners cannot entrust their Private Keys to the software requesting the creation & signing of the ID Block (eg Kata-Runtime) as it's running on the Untrusted Host
### The Solution: 
    Have Guest Owners entrust their Private Signing Keys to Trustee (since it's running in a Trusted Environment)

## Updated Flow:
### Guest Owner Registration
- ***FROM A TRUSTED ENVIRONMENT:*** 
Guest Owners should "register" a "signing keypair" with SAMS over an mTLS encrpyted connection:
    - Example Usage:
        **Note**: the ca.crt is the certificate of the TLS Certificate Authority who has issued leaf-certs to both the guest owner & to SAMS
        ```shell
        # Guest Owner registers a signing keypair w/ SAMS
        curl \
            --cert guest-owner-mTLS-leaf-cert-chain.crt \
            --key guest-owner-mTLS-leaf-cert-private-key.key \
            --cacert ca.crt \
            -X POST /kbs/v0/sams/guest-owner \
            -d '{
                "pubkey": "...",
                "privkey": "..."
            }' 
        ```
- ***Inside of Trustee:***
    - **SAMS should store the Guest Owner's mTLS leaf cert in RVPS.**
        - Store as `hash(<pubkey>)`: `<leaf-cert>`
    - **SAMS should store the Guest Owner's Signing-Keypair in KBS.**
        - Store as `hash(leaf-cert)`: `{"pubkey": "...", "privkey": "..."}`
### Requesting an ID Block
- ***From the UNTRUSTED Host:***
***Over a NON-mTLS*** connection, 
The ID Block Requester (Kata-Runtime) can opt to send the `/sams/measurement/snp/auth` Endpoint a Bearer Token containing the Guest Owner's mTLS certificate (publicly available) 
alongside the desired CVM Launch Params & ID Block Metadata. 
Doing so will trigger SAMS to include the Guest Owner's signing-keypair info in the produced `IDAuth` information.
    > **NOTE: For the full explaination see *[Demystifying the Measurement Endpoints](demystifying-the-measurement-endpoints.md)***
- ***Inside of Trustee:***

    - **IF ADEQUATE LAUNCH PARAMS WERE PROVIDED,**
    SAMS will calculate the Launch Measurement for the provided launch params & include them in the response body under the `"measurement"` field.
        
    - **IF the *`FAMILY_ID`* & *`IMAGE_ID`* fields were included in the request,** then
    SAMS will create an IDBlock containing the Launch Measurement, Family ID, Image ID, & the current Minimum Acceptable Guest SVN (MAGS) pulled from RVPS.

        **This IDBlock will be included, *base64-encoded*, in the response body under the *`"id-block"`* field.**
    
    - **IF the request headers include a Bearer Token containing the guest-owner's mTLS certificate,** then
    SAMS will:
        1. Hash the certificate parsed from the Bearer Token
        2. Check that that hash is present in KBS
        3. Reject the request with `401 - Unauthorized` if the hash is not present in KBS
        4. Pass the certificate into the policy engine, alongside the CVM launch parameters & ID Block metadata, for SAMS Policy Owners to make assertions about.
            - This allows SAMS policy owners to make assertions about all the data contained inside the Guest Owner's mTLS certificate, including but not limited to the contents of the `Subject` & `Extentions` fields
    
    - **If evaluation of the SAMS Policy returns "authorized",**
    SAMS will:
        1. Create an IdBlockSig, a Signature of the IDBlock using SAMS' private key, 
        2. Use the hash of the certificate to retrieve the guest-owner's signing-keypair from KBS
        3. Create an IdKeySig, a Signature of the IDKey (SAMS' Public Key) using the guest-owner's Private Key
        4. Create an IdAuth struct containing
            1. The IdBlockSig
            2. The IDBlockAlgo (an integer identifying which signing function created IdBlockSig)
            3. The IDKeyDigest (SHA-384 hash of the SAMS Pubkey)
            4. The IdKeySig
            4. The AuthKeyAlgo (an integer identifying which signing function created IdKeySig)
            5. The AuthKeyDigest (SHA-384 hash of Guest Owner Pubkey)
        5. **Include the IdAuth struct, base64-encoded, in the reponse body under the *`id-auth`* field**
        6. **Include the following fields in the response body for verification purposes:**
            - The IDKey (SAMS' Public Key)
            - The AuthorKey (Guest Owner's Public Key)
        
### Verifying an Attestation Report
- Verifier Policy Owners will also be able to pull Guest Owner mTLS Leaf Certs from RVPS and make assertions about them in Verifier policies.
- Verifiers can find the Certificate for a guest owner by using the AuthKeyDigest field of the attestation report as the retrieval key when querying RVPS.
    - This allows Verifier policies to make assertions about all the data contained inside the Guest Owner's mTLS certificate, including but not limited to the contents of the `Subject` & `Extentions` fields.

### Guest Owner Revocation
- ***FROM A TRUSTED ENVIRONMENT:*** 
Guest Owners should be able to "revoke" their "signing-keypairs" over an mTLS encrypted connection:
    - Example usage:
        **Note**: the ca.crt is the certificate of the TLS Certificate Authority who has issued leaf certs to both the guest owner & to SAMS
        ```shell
        # Guest Owner revokes their registered signing keypair w/ SAMS
        curl \
            --cert guest-owner-mTLS-leaf-cert-chain.crt \
            --key guest-owner-mTLS-leaf-cert-private-key.key \
            --cacert ca.crt \
            -X DELETE /kbs/v0/sams/guest-owner 
        ```
    - Upon completion of the mTLS handshake, the "revocation" handler, should:
        1. Hash the guest-owner's leaf-cert
        2. Use that hash to retrieve the guest-owner's signing-keypair from KBS
        3. Hash the pubkey of the guest-owner signing-keypair 
        4. Use that hash to remove the guest-owner's leaf-cert from RVPS
        5. Use the hash of the guest-owner leaf-cert to remove the guest-owner's signing-keypair from KBS

## Additional Overheead 
### For Trustee Admins
- Trustee admins must obtain an mTLS certificate & private-key from a trusted TLS Certificate Authority, then they must configure SAMS to use this mTLS cert & private-key, and to trust the TLS Certificate Authority's Root Certificate.
- Trustee admins must remember to rotate their mTLS certs BEFORE they expire, else they risk Guest Owners not being able to register signing keypairs with SAMS.
- Trustee admins must remember to rotate their mTLS certs when the upstream CA that issued the certs' own certificate expires, else they risk Guest Owners not being able to register signing keypairs with SAMS.

### For Trustee Admins
- Guest Owners must obtain an mTLS certificate & private-key from a trusted TLS Certificate Authority, configure the machine they intend to use mTLS on to trust the TLS Certificate Authority's Root Certificate, then they must configure their HTTP client to use the Guest Owner's mTLS cert & private-key when making requests to the `/sams/guest-owner` endpoint.
- Guest Owners must remember to rotate their mTLS certs BEFORE they expire, else they risk not being able to register signing keypairs with SAMS.
- Guest Owners must remember to rotate their mTLS certs when the upstream CA that issued the certs' own certificate expires, else they risk not being able to register signing keypairs with SAMS.

