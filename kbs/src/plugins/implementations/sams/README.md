Signing, Authorization, & Measurement Service (SAMS)
---
Provides CVM-Launch-Measurement-as-a-Service funtionalities.

## SEV SNP ID-BLOCK
### /generate
#### Request Params:
- A JSON Object containing:
1. All params required to create an SNP Launch Measurement, EXCEPT for the Kernel, Initrd, & OVMF files
2. Precomputed measurements (cryptographic hashes) of the Kernel, Initrd, & OVMF
3. The FAMILY_ID, IMAGE_ID, GUEST_SVN, GUEST_POLICY, & ID-BLOCK ABI VERSION being used to identify the CVM

#### Request Response Body:
- A JSON Object containing 3 fields:
1. A Launch Measurement constructed from the provided params & pre-computed measurements
2. A base64-encoded ID-Block structure generated from the Launch Measurement, fit to be passed into the hypervisor (qemu) when launching the CVM
3. ID_BLOCK_ALO - The signing algorithm used w/ the ID-Block & the ID_KEY to produce the ID_BLOCK_SIG
4. ID_BLOCK_SIG - The signature produced by running the ID-Block & the ID_PRIVATE_KEY (SAMS Private Key) through the ID_BLOCK_ALO algorithm
5. ID_KEY - The Public Key associated with (SAMS) which can be used to verify the ID_BLOCK_SIG

#### Expected usage:
```mermaid
sequenceDiagram
    participant fw as SNP Firmware
    participant hv as Hypervisor <br>(Qemu)
    actor guest_owner as Guest Owner
    participant kataconfig as Kata Config File(s)
    participant spec as Pod Spec File
    participant image_repo as Guest Owner<br> Container Image Repository<br>(Hosts confidential workload images)
    participant k8s@{"type": "control"} as Kubernetes
    participant kata_runtime@{"type": "control"} as Kata Runtime<br>(on Untrusted Host)
    participant kata_agent@{"type": "control"} as Kata Agent<br>(in CVM)
    participant cdh@{"type": "control"} as Confidential Data Hub<br>(in CVM) 
    participant api as Trustee-API<br>(Api-Server-Rest)
    participant sams as Trustee-SAMS<br>(KBS-SAMS Plugin)
    participant trustee_as as Trustee-AS<br>(Attestation Service)
    participant snp_verifier as Trustee-AS-SNP-Verifier<br>(SNP Plugin for<br> Attestation Service)
    participant policy_engine as Policy Engine<br>(Regorous Crate)
    participant rvps as Trustee-RVPS<br>(Reference Value <br>Provider Service)
    participant kbs as Trustee-KBS<br>(Key Broker Service)
    participant kbs_resource_plugin as Trustee-KBS<br>Protected Endpoints<br>(KBS Resource Plugin)
    opt configure default Trustee API URL
        guest_owner ->> kataconfig: Set default Trustee API URL in kata_runtime configuration.toml file(s)
        kataconfig -->> kata_runtime: Fwd: Set default Trustee API URL for runtimes
        note over guest_owner,kataconfig:  Trustee API Server URL<br>(cc_kbc)
    end
    critical Request Create Pod
        guest_owner ->> spec: Write Pod Spec
        critical choose runtime
            note over spec: runtimeClass: kata_runtime-coco-qemu-snp-runtime-rs
            k8s -->> kata_runtime: Fwd: Use the SNP Rust Kata-Runtime
        end
        opt configure pod-specific Trustee API URL 
            note over spec: annotations:<br>io.katacontainers.config.hypervisor.kernel_params:<br>"agent.aa_kbc_params=cc_kbc::http://<kbs-ip>:<kbs-port>"
            k8s -->> kata_runtime: Fwd: The Kata-CVM for this pod will use<br> the provided URL for the Trustee API
        end
        opt require pre-verification
            note over spec: annotations:<br>io.katacontainers.config.requirePreVerification:<br> true
            k8s -->> kata_runtime: Fwd: Require & Request a signed ID Block <br>from KBS-SAMS during Kata CVM boot.
        end
        guest_owner ->> k8s: Apply the POD_SPEC file
        note over guest_owner, k8s: kubectl apply -f <POD_SPEC_FILE>
        spec -->> k8s: {Create Pod}
        k8s -->> kata_runtime: Request Launch CVM for Pod
    end
    alt Check the 'requirePreVerification' annotation
        break when not 'true'
            note left of kata_runtime: (Fallback to the current flow)
            kata_runtime->>hv: Request CVM Startup (without ID Block)
            note over kata_runtime,hv: -object sev-snp-guest
            hv ->> fw: SNP_LAUNCH
        end
    else when 'requirePreVerification' is true
        note over kata_runtime,sams: Request an ID Block from KBS-SAMS
        kata_runtime ->> api: POST /generate -- <LaunchParams + ID Block Metadata> 

        api ->> sams: Fwd: POST /generate -- <LaunchParams + ID Block Metadata> 
        note over kata_runtime,sams: LaunchParams = {vcpus,<br> vcpu_type,<br> ovmf_hash,<br> guest_feats,<br> kernel_hash,<br> initrd_hash,<br> kernel_cmdline,<br> vmm_type}
        note over kata_runtime,sams: CVM ID Block Metadata = {family_id,<br> image_id,<br> guest_svn,<br> guest_policy}
        opt Pre-Verification
            loop For each Launch Param / ID Block Metadata Field
                sams ->> rvps: GET refence values
                rvps -->> sams: Array of reference values
                break when provided value NOT in reference values array
                    note over sams,rvps: PRE-VERIFICATION FAILED,<br> ID Block not issued,<br> Kata CVM Fails to start
                end
            end 
        end
        sams -->> sams: Calculate Launch Measurement<br>(SEV-SNP-MEASURE / CREATE_ID_BLOCK)
        sams -->> kata_runtime: Expected Launch Measurement + Trustee Metadata
        Note over sams,kata_runtime: - IDBlock (Expected Measurement + Metadata Fields)<br>- IDKey (SAMS PubKey)<br>- IDKeyAlgo<br>- IDBlockSig = IDKeyAlgo(SAMS PrivKey, IDBlock)

        kata_runtime ->> kata_runtime: Add Author Metadata
        note over kata_runtime: AuthKey = <br>AuthKeyAlgo(Guest Owner PrivKey, IDKey) 
        kata_runtime ->> kata_runtime: Prep Hypervisor Params
        note over kata_runtime: id-block = base64(IDBlock)
        note over kata_runtime: id-auth = base64({<br>ID_KEY_ALGO,<br> AUTH_KEY_ALGO,<br> ID_BLOCK_SIG,<br> ID_KEY,<br> ID_KEY_SIG,<br> AUTHOR_KEY})
        kata_runtime ->> hv: Request CVM Startup (w/ ID Block)
        note over kata_runtime,hv: -object<br>sev-snp-guest,<br>id-block=...,<br>author-key-enabled=1,<br>id-auth=...
        hv ->> fw: SNP_LAUNCH
        critical Verify ID-Block<br> (Expected Launch Measurement)<br> &<br> ID-Auth Context
            critical SNP_LAUNCH_FINALIZE
                fw -->> fw: Check Signature Fields
                fw -->> fw: Calculate actual Launch Measurement
                fw -->> fw: Compare actual Launch Measurement vs the expected launch measurement
                alt Pre-validate Succeeds
                    fw ->> hv: ALLOW Create CVM<br> (w/ guest context)
                    hv -->> hv: *Launches CVM*
                    note over fw,hv: CVM boots!<br> CVM guest-context (gctx) <br>contains the ID-Block & ID Auth
                    hv -->> kata_runtime: CVM Booted (w/ guest context)!
                else Pre-Validation Fails
                    break when AuthKeyDigest doesn't match Guest Owner PubKey
                        fw ->> hv: Abort CVM Boot
                    end
                    break when IDKeyDigest doesn't match SAMS' PubKey
                        fw ->> hv: Abort CVM Boot
                    end
                    
                    break when Actual Launch Measurement doesn't match IDBlock LaunchDigest
                        fw ->> hv: Abort CVM Boot
                    end
                    note over fw,hv: CVM FAILS TO START
                end
            end
        end
        
        critical Launch Pod
            kata_runtime ->> kata_agent: Request Launch Pod from encrypted image
            kata_agent ->> cdh: Pull [Encrypted] Image
            loop For each Image Layer
                cdh ->> image_repo: Fetch/Decompress Image Layer
                opt Layer is Encrypted
                    cdh ->> cdh: Extract Decryption Key URI from Layer Annotations
                    critical Retreive Image-Layer Decryption Key
                        alt URI points to KBS Resource
                            critical Request image decryption key from Trustee KBS
                                note over cdh: Request Authorization to pull secrets from KBS via RCAR Protocol
                                critical Perform RCAR Handshake
                                    critical Get RCAR Challenge (w/ Nonce)
                                        cdh ->> api: POST /kbs/v0/auth 
                                        note over cdh,api: Send body: {"version", "tee","extra-params"}
                                        api -->> trustee_as: Fwd: Request Auth 
                                        trustee_as -->> cdh: Session Cookie + Challenge (Containing Nonce & Optional ExtraParams)
                                    end
                                    critical Get Attestation Report (bound to Challege Nonce)
                                        cdh ->> fw: Request Attestation Report<br> (set the GUEST_DATA field to contain<br> the RCAR Challenge Nonce <br>+ The TEE Public Key and its metadata)
                                        fw -->>cdh: Attestation Report 
                                        note over fw,cdh:(Note the report contains the RCAR Nonce & TEE Pubkey <br> encoded into the GUEST_DATA field,<br> as well as the IDBlock & IDAuth structures in their own respective fields)
                                    end
                                    critical Request Verification of Report
                                        cdh ->> api: POST /kbs/v0/attest
                                        note over cdh,api: Send Header:  "Cookie kbs-session-id=..." <br>Send body: {*"init-data", "runtime-data", "tee-evidence"}
                                        note over cdh,api: Where "init-data" is an OPTIONAL structure containing the text provided to the CVM as "initData" during Boot & the format to parse that text as
                                        note over cdh,api: Where "runtime-data" is a REQUIRED structure containing the RCAR Challenge Nonce + The TEE Public Key.<br> Its hash MUST match the contents of the Attestation Report GUEST_DATA field. 
                                        note over cdh,api: Where "tee-evidence" is a REQUIRED structure containing the Attestation Report as the "primary_evidence" field.
                                    end
                                    critical Verify the Attestation Report using the provided claims
                                        trustee_as -->> snp_verifier: Evaluate Hardware Claims
                                        
                                        critical Verify Report is signed by Hardware Manufacturer
                                            snp_verifier -->> snp_verifier: Verify Attestation Report is signed<br> by AMD Cert Chain<br> (Endorsements)
                                            break when not signed / signature mismatch
                                                note over snp_verifier: Attestation Report Not Trusted by Hardware Manufactorer
                                            end
                                        end
                                        
                                        critical Verify the user-defined fields of the report match the expected state
                                            snp_verifier -->> snp_verifier: Hash the provided Initdata & GuestData
                                            snp_verifier -->> snp_verifier: Verify the hashes respectively match<br> the HOST_DATA & GUEST_DATA fields<br> in the Attestation Report
                                            break when initdata hash mismatch
                                                note over snp_verifier: CVM Potentially in a different (non-compliant) state then when the report was generated
                                            end
                                            break when guestdata hash mismatch
                                                alt Challenge Nonce mismatch
                                                    note over snp_verifier: Potential Replay attack detected 
                                                else Tee PubKey mismatch
                                                    note over snp_verifier: Potential M-it-M attack detected
                                                end
                                            end
                                        end
                                    end

                                    critical Determine the level of compliance the represented TEE is in with the Trustee Verifier Policy (Apprasal Policy) 
                                        critical Evaluate the claims against the Attestaion Service Apprasal Policy
                                            snp_verifier ->> policy_engine: Register the query_reference_value extension,<br> allowing policies to call the query_reference_value() function
                                            snp_verifier ->> policy_engine: Evaluate the EAR  Policy for the specified TEE Class with data = None,<br> input = <claims parsed from the Attestation Report, provided InitData, & provided RuntimeData> <br>& eval_rules = ["data.policy.trust_claims", "data.policy.extensions"] 
                                            loop For each rule in the policy
                                                opt Compare avalable claims against a list of acceptable reference values
                                                    policy_engine ->> rvps: Retrieve reference values
                                                    rvps -->> policy_engine: Return reference values
                                                    policy_engine -->> policy_engine: Compare input fields against reference values
                                                end
                                            end
                                            note over snp_verifier,policy_engine: (This roughly translates to <br>"Return the structures "trust_claims" & "extensions" if ANY rule in the KBS resource policy evaluates to make them exist<br> provided that data = data & input = input)
                                            policy_engine -->> snp_verifier: Trust Claims describing the TEE trust rating as a map of 8-bit integers
                                            snp_verifier ->> snp_verifier: Convert the claims into an AR4SI Trustwothiness Vector<br>
                                        end
                                    end

                                    critical Return Evaluated Attestation Result Token
                                        snp_verifier -->> snp_verifier: Create an EAR Token (jwt), bound to this HTTP Session, containing the Trustworthiness Vector describing the TEE and a token expiration date.
                                        note left of snp_verifier: Until the token expires (default TTL is 5mins), it authorizes the KBC to comunicate with protected KBS endpoints<br> such as the "resource" plugin endpoints which are responsible for releasing secrets.
                                        snp_verifier -->> cdh: Return the EAR Token to KBC, completing the RCAR handshake.
                                    end
                                end
                                    
                                critical Request access to image decryption key<br> (provide EAR Token for KBS (ACL) Policy Evaluation) 
                                    cdh ->> api: GET /resource/v0/<repository>/<type>/<tag>, (+ EAR Token)
                                    api -->> kbs: Fwd: GET /resource/v0/<repository>/<type>/<tag>, (+ EAR Token)
                                    critical Evaluate EAR Token
                                        kbs -->> kbs: Enforce KBS Resource Policy
                                        critical Evaluate Request Path + Token against the KBS Resource Policy
                                            kbs-->>kbs: Parse the URL as /<plugin>/v0/<resource-path[0]>/<resource-path[1]>/<resource-path[2]>[?<query[0]>,[<query[1]>], ...]
                                            kbs ->> policy_engine: Evaluate the KBS Resource Policy with data = {plugin, resource-path, query},<br> input = <claims parsed from EAR Token> <br>& eval_rules = ["data.policy.allow"] 
                                            note over kbs,policy_engine: (This roughly translates to <br>"Check whether ANY rules in the KBS resource policy make<br> "data.policy.allow" evaluate true,<br> provided that data = data & input = input)
                                        end
                                    end
                                    critical Release Secret
                                        break when data.policy.allow != true
                                            policy_engine ->> kbs: ACCESS DENIED
                                        end
                                        policy_engine -->> kbs: Allow Access
                                        kbs -->> kbs_resource_plugin: Retreive resource from path 
                                        kbs_resource_plugin -->> kbs: Requested resource
                                        opt Encrypt Response Payload
                                            kbs ->> kbs: Encrypt plugin response payload w/ TEE Pubkey
                                        end
                                        kbs -->> cdh: Image Decryption Key Payload 
                                    end
                                end
                            end
                        end
                    end
                    cdh ->> cdh: Decrypt Image Layer
                end
            end
                    
            cdh -->> kata_agent: Image ready for use!
            kata_agent ->> kata_agent: *Creates Pod*
            kata_agent -->> kata_runtime: Pod Created 
            kata_runtime -->> k8s: Fwd: Pod Created
            
        end
    end
```

### /verify

WIP