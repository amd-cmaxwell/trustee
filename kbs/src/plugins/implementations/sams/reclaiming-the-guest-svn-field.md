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
- When signing an IDBlock, SAMS will retrieve the MAGE from RVPS & sign it using SAMS' private key. 
    >Note: 
    > - The CAGE should be **bound to the IdBlock it tags** to avoid a malicious host pairing a CAGE with an IdBlock that it was not intended to be paired with
    >   - **To account for this, we should mix the IdBlock's IdBlockSig into the CAGE Sig**
    > - Also, we should take steps to prevent replay attacks if the MAGE ever does get reset to a lower value,
    >   - **To account for this, we should *also* mix a Salt into the CAGE Sig**
    >   - **To allow Verifier Policy Owners to account for Authorization Policy drift, We should store the Salt for each *iteration* of the MAGE in RVPS**
    >       - That way the SNP Verifier can affirm that a CAGE was valid ***at the time it was issued***, even if it was issued in a previous AGE
    >       - In turn that would allow Verifier Policy Owners to make rules spanning multiple AGEs,  
    >           - E.g, "Accept the report IFF it was generated in AGE=2 OR AGE=3"
- The combination of MAGE + Signature constitutes the Current Authorized Generation Epoch (CAGE), as endorsed by Trustee.
- Upon Authorizing a launch configuration, SAMS' Measurement Endpoints will return the CAGE alongside the generated ID Block
- ID Block users will be expected to include the CAGE in their CVM InitData.
- During the verification step of the RCAR handshake, crucially AFTER the SNP Verifier has confirmed the hash of the provided initData matches the HOST_DATA field of the attestation report, the SNP Verifier will extract the CAGE from the provided initData, pull SAMS's public key from RVPS, & verify the signature in the CAGE against SAMS' public key and the numeric portion of the CAGE (i.e. the CVM's AGE). 
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