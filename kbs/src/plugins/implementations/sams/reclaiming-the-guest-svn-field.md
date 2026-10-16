# Reclaiming the Guest SVN Field

## Background
It was previously proposed that the Guest Security Version Number (GSVN) field of SAMS-distributed ID Blocks would effectively serve as an "Issued under SAMS Authorization Policy Version" number, solely dedicated to versioning signed ID Blocks.

This appropriates the original intended use of this field, which was to allow VM Image mantainers to quickly signal security changes across their VM Images.

The following proposes a new take on SAMS Auth Policy Versioning which frees up the GSVN field to be used for its intended purpose.

## The Need
- Guest Owners MUST to be able to specify the GSVN of their ovmf/kernel/initrd tuple to SAMS.
- SAMS MUST NOT obsure Guest Owner control of the GSVN Field.

## The Criteria
The Definition of Done for any solution must meet these 3 criteria:
1. An immutable monotonic version tag MUST be tied to all attestation reports which include a Trustee-endorsed IdBlock
2. The version tag MUST NOT occupy the the Guest SVN field of the IdBlock
3. The version tag MUST show an endorsement from Trustee which CANNOT be unduely replicated

## The Solution -- Signed Authorization Generation Epoch (SAGE) Protocol
- SAMS still holds a monotonic counter in RVPS for tracking security changes to the SAMS Authorization policy.
- Instead of Minimum Accepted Guest SVN (MAGS), we call this counter the Minimum Authorized Generation Epoch (MAGE)
- Trustee Admins will still be able to conditionally increase the monotonic counter when updating the SAMS Authorization Policy
- When signing an IDBlock, SAMS will 
    1. Hash the IdBlock struct 
        - (base64 should do since the IdBlock contains public data anyway)
    2. Retrieve the MAGE & the current Salt from RVPS
    3. Combine the MAGE, IdBlock Hash, & Salt into a structure 
    4. Sign that structure using SAMS' private key. 
- The combination of MAGE + IDBlock Hash + Signature constitutes the Current Authorized Generation Epoch (CAGE), as endorsed by Trustee.
    >Rationale: 
    > - The CAGE should be **bound to the IdBlock it tags** to avoid a malicious host pairing a CAGE with an IdBlock that it was not intended to be paired with
    >   - **To account for this, we should include a Hash of the IdBlock in the CAGE**
    >       - We could use SHA-384 for consistency with the other crypto things happening in the SNP ecosystem...
    >       - But, since the IdBlock data is not secret, there's no harm in base64-encoding it...
    > - Also, we should take steps to prevent replay attacks if the MAGE ever does get reset to a lower value in RVPS
    >   - **To account for this, we should mix a Salt into the CAGE Sig**
    >   - **To allow Verifier Policy Owners to account for Authorization Policy drift, We should store the Salt for each *iteration* of the MAGE in RVPS**
    >       - That way the SNP Verifier can affirm that a CAGE was valid ***at the time it was issued***, even if it was issued in a previous AGE
    >       - In turn, that would allow Verifier Policy Owners to safely make rules spanning multiple AGEs
    >           - E.g, "Accept the report IFF The Attester is using an IdBlock that was generated in AGE=2 OR AGE=3"
- Upon Authorizing a launch configuration, SAMS' Measurement Endpoints will return the CAGE alongside the generated ID Block
- ID Block users will be expected to include the CAGE in their CVM InitData.
- During the verification step of the RCAR handshake, crucially AFTER the SNP Verifier has confirmed the hash of the provided initData matches the HOST_DATA field of the attestation report, the SNP Verifier will:
    1. Extract the CAGE from the provided initData
    2. Extract the AGE from the CAGE
    3. Extract the IdBlockHash from the CAGE
    4. Pull SAMS's public key & the Salt for the specified AGE from RVPS
    5. Reconstruct an IDBlock Struct from the fields embedded in the Attestation Report
    6. Hash the reconstructed IDBlock
    7. Verify the hash of the reconstructed IDBlock matches the IdBlockHash extracted from the CAGE
    8. Verify the signature in the CAGE using SAMS' public key and a struct containing the non-signature fields of the CAGE, i.e.:
        - The numeric portion of the CAGE (i.e. the CVM's AGE)
        - The reconstructed IdBlockHash
        - The expected Salt for the AGE
- If the signature verification check passes, SAMS then compares the CVM's AGE against the current MAGE in RVPS
- If the CVM's AGE < the MAGE then we conclude that the IdBlock is outdated, i.e. it was generated under a previous Authentication Generation Epoch (AGE).
- **Verifier policies should enforce the withholding of secret data from CVM's using outdated IdBlocks**
- **Non-compliant CVMs will need to be re-launched after obtaining NEW IdBlocks from SAMS pertaining to the *Current* AGE**.

## In Summary
The SAGE protocol can be summarized in one pnuemonic:
> **You put the *MAGE* in the *CAGE* and verify its *AGE*.**


## Special Thanks to:
- Katherine Kim
- Diego Gonzalez
- Amanda Liem
- Mark Gentry