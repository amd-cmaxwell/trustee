# SAGEv2 : The SAGEST Protocol

## Background
SAGE stands for Signed Authentication Generation Epoch. It is a versioning protocol designed for use with SNP IDBlock based attestation.
While the process behind the protocol is fairly sound, the initial implementation failed to choose a standard and well-defined format for its data exchange.
This proposal aims to rectify that.

## The Breakdown -- Signed Authentication Generation Epoch over Stateless Token (SAGEST)

SAGEST copies the process from its predecessor, but implements it using Signed JSON Web Tokens (JWTs), thus expanding the capacity of each individual CAGE.

## Advantages over SAGEv1:
- JSON Web Tokens are a portable, well defined, and widely adopted standard for sharing self-contained "stateless" data
- JSON Web Tokens decode into standard JSON Objects, making them highly flexible for transporting variable size structed data
- JSON Web Tokens have well defined signing sementics already included in their spec, meaning the SAMS implemeters don't need to fuss over which crypto standards to use
- JSON Web Tokens allow for the encoding of even more structured identity data inside each distributed CAGE. They can enable the graceful storage of whole IDBlock / IdAuth structures (which are not present in the attestion report itself) inside of the CAGE

## Usage details in SAMS
- SAMS Measurement Endpoints will switch from distrubuting Current Authorized Generation Epoch (CAGE) blobs alongside issued IdBlocks & IdAuth structures to distributing **CAGE Tokens** (JWTs) alongside the aformentioned structures.
- A single CAGE Token will contain:
    1. The full IdBlock & IdAuth structs for the IDBlock being described, serialized to JSON 
    2. The Current MAGE as pulled from the RVPS
    3. The mTLS certificate provided to the measurement endpoint via the x-client-cert header &/or via Bearer Token Authentication by way of the "certificate" claim, (if any)
    4. The PEMdata for the Guest Owner's Public Signing Key (as determined by their Signing Policy evaluation) & SAMS's Public Key (The Author Key)
    5. A salted hash of the rest of the data in the token, where the SALT is keyed to the specified MAGE
- The CAGE Token will then be signed by the SAMS Private Key
- The CAGE Token remains compact while allowing for all the data contained within to be unpacked at a later date (e.g. during attestation verification by the SNP Verifier)

## In Closing,
> I *SAG-EST* you adopt SAGEv2: SAGEST, today!