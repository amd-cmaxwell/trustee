Improvement / Open Questions:
- ~Add check to SAMS for Family_id, image_id, & guest_policy (anything going into the IDBlock) -- want SAMS Policy owners to make assertions~
- Need an audit  trail for which launch params created which idBlock
- ~~Add notes on IMAGE_ID & FAMILY_ID in Verification step~~
    - **Done:** `family_id`, `image_id`, and `guest_svn` are now emitted as claims by the SNP verifier and available to EAR appraisal policies.
- ~~Update `ear_default_policy_cpu.rego` to check `sams_id_key_endorsed` and `author_key_endorsed` claims and adjust trustworthiness vector accordingly~~
    - **Done:** The default EAR policy now includes a SAMS-specific SNP rule that requires `id_block_en`, `sams_id_key_endorsed`, `author_key_endorsed`, and `guest_svn >= snp_minimum_acceptable_guest_svn`.
- The use of Guest SVN as a monotonic counter tracking security updates of the SAMS Authorization Policy as opposed to tracking security updates for the guest image itself is novel. Normally, GUEST_SVN is purely a property of the guest image, for example, if the guest image corresponding to a new release contains code that addresses CVEs, then bump the GUEST_SVN, else don't bump. It's also important to keep in mind GUEST_SVN's role in key derivation: it can optionally be mixed into derived keys and, if it is, then derived keys can be requested for any GUEST_SVN value <= current GUEST_SVN. This reflects the convention in the example above where higher GUEST_SVN means more secure. Is this proposal consistent/compatible with this?
- To harden the SAGE protocol against replay attacks, the CAGE signatures SAMS' Measurement endpoints give out should probably mix in a salt that changes independently with each increment of the MAGE value. The current salt should also be stored in RVPS.
