Improvement / Open Questions:
- ~Add check to SAMS for Family_id, image_id, & guest_policy (anything going into the IDBlock) -- want SAMS Policy owners to make assertions~
- Need an audit  trail for which launch params created which idBlock
- ~~Add notes on IMAGE_ID & FAMILY_ID in Verification step~~
    - **Done:** `family_id`, `image_id`, and `guest_svn` are now emitted as claims by the SNP verifier and available to EAR appraisal policies.
- Update `ear_default_policy_cpu.rego` to check `sams_id_key_endorsed` and `author_key_endorsed` claims and adjust trustworthiness vector accordingly
