# POST /kbs/v0/sams/measurement/snp
## Headers
None
## Request Body
```json
{
    vcpus: <Number of CPUs available to the CVM as a u32>,
    vcpu_type: "<The Codename identifying the CPU Generation of the Host>",
    vmm_type: "<The Type of Virtual Machine (Hypervisor Specific) to be launched>",
    guest_features: <Kernel Guest Features Bitflag as a u64>,
    ovmf_hash_str: "<Precalculated Cryptographic Hash of the OpenVM Firmware file the hypervisor will use to launch the CVM>",
    initrd_hash_str: "<Precalculated Cryptographic Hash of the initial filesystem the CVM will use>"
    kernel_hash_str: "<Precalculated Cryptographic Hash of the kernel file the CVM will use>",
    append: "<Kernel Cmdline Arguments...>",
    guest_policy: <Guest Policy Bitflag as a u32>,
    family_id: "<String Identifying which group to which the ID Block belongs (16 bytes max)",
    image_id: "<String Identifying which CVM the ID Block belongs (16 bytes max)",
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
2. If you ALSO send IDBlock Metadata (`FAMILY_ID` & `IMAGE_ID`), then
the response body contains:
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>",
            "id-block": "base64({
                LaunchMeasurement = "< measurement >",
                FamilyID,
                ImageID,
                GuestSVN = The current Minimum Acceptable Guest SVN (MAGS), as pulled from RVPS,
                ...
            })"
        }
        ```
    - Error Codes
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
# POST /kbs/v0/sams/measurement/snp/auth
## Headers
`Authorization: Bearer <signed JWT identifying the guest owner>`

## Request Body
```json
{
    vcpus: <Number of CPUs available to the CVM as a u32>,
    vcpu_type: "<The Codename identifying the CPU Generation of the Host>",
    vmm_type: "<The Type of Virtual Machine (Hypervisor Specific) to be launched>",
    guest_features: <Kernel Guest Features Bitflag as a u64>,
    ovmf_hash_str: "<Precalculated Cryptographic Hash of the OpenVM Firmware file the hypervisor will use to launch the CVM>",
    initrd_hash_str: "<Precalculated Cryptographic Hash of the initial filesystem the CVM will use>"
    kernel_hash_str: "<Precalculated Cryptographic Hash of the kernel file the CVM will use>",
    append: "<Kernel Cmdline Arguments...>",
    guest_policy: <Guest Policy Bitflag as a u32>,
    family_id: "<String Identifying which group to which the ID Block belongs (16 bytes max)",
    image_id: "<String Identifying which CVM the ID Block belongs (16 bytes max)",
}
```

## Responses

1. If you send Launch Parameters & IDBlock Metadata 
**AND** SAMS Policy Approves of your submitted launch params & ID Block Metadata, then
the response body contains:
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>",
            "id-block": "base64({
                LaunchMeasurement = "<measurement>",
                FamilyID,
                ImageID,
                GuestSVN = The current Minimum Acceptable Guest SVN (MAGS), as pulled from RVPS,
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
            "id-key": "<SAMS Public Key>"
        }
        ```
    - Error Codes:
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
        2. If you fail to provide the IDBlock Metadata fields (`FAMILY_ID` & `IMAGE_ID`):
            `400 - Bad Request`
        3. If CVM Launch is Forbidden by SAMS Policy:
            `403 - Forbidden` 
2. **If ON TOP OF THAT, YOU SEND A Bearer Token containing a JWT for a *REGISTERED* guest-owner,** 
***AND* SAMS Policy Approves of your launch params, ID Block Metadata, & guest-owner JWT,** then
the response body contains:
    - Success Codes
        `200 - OK`
        ```json
        {
            "measurement": "<CVM Launch Measurement>",
            "id-block": "base64({
                LaunchMeasurement = "<measurement>",
                FamilyID,
                ImageID,
                GuestSVN = The current Minimum Acceptable Guest SVN (MAGS), as pulled from RVPS,
                ...
            })",            
            "id-auth": "base64({
                IdBlockSig = IdBlockAlgo(SAMS Priv Key, IDBlock), 
                IdBlockAlgo = <integer rep of Ecdsa-384>,
                IdKeyDigest = SHA-384(SAMS Pub Key),
                IdKeySig = AuthKeyAlgo(Guest Owner Priv Key, SAMS Pub Key),
                AuthKeyAlgo = <integer rep of Ecdsa-384>,
                AuthKeyDigest = SHA-384(Guest Owner Pub Key)
            })",
            "id-key": "<SAMS Public Key>",
            "author-key": "<Guest Owner Public Key>"
        }
        ```
    - Error Codes:
        1. If you fail to provide the minimum set of Launch Params to calculate a measurement:
            `400 - Bad Request`
        2. If you fail to provide the IDBlock Metadata fields (`FAMILY_ID` & `IMAGE_ID`):
            `400 - Bad Request`
        3. If your Bearer Token is malformed:
            `401 - Unauthorized`
        5. If your Bearer Token is expired:
            `401 - Unauthorized`
        4. If your Bearer Token doesn't contain a valid JWT:
            `401 - Unauthorized`
        4. If the JWT in your Bearer Token is unknown to SAMS:
            `401 - Unauthorized`
        6. If SAMS Policy rejects your Launch Params, ID Block Metadata, &/or guest-owner JWT:
            `403 - Forbidden`


