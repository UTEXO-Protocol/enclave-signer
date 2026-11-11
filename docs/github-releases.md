# Publish an EIF release for signers

`Publish EIF Release` publishes an existing **Stage / Public Bitcoin Signet**
build as a GitHub prerelease. Its EVM network is **Arbitrum One (42161)**.
It does not build an EIF, deploy to EC2, approve a KMS policy or register a signer.
The build and deployment workflows are independent.

## Repository setup

An administrator configures these settings before the first publication:

- Repository variables `AWS_REGION` and `EIF_S3_BUCKET`: the location used by
  Build EIF. `EIF_RELEASE_AWS_ACCOUNT_ID`: the account that owns the read role.
- Repository secret `EIF_RELEASE_READ_ROLE_ARN`: a dedicated GitHub OIDC role
  with `s3:GetObject` on
  `arn:aws:s3:::<artifact-bucket>/eif/*/stage-signet/rgb-*/*` only. For a bucket
  using a customer-managed encryption key, grant the necessary `kms:Decrypt`
  permission too. It needs no S3 writes, EC2 or SSM access.
- The read role's trust policy allows the repository's `dev` and `stage` refs,
  with audience `sts.amazonaws.com`. The prepare job has no GitHub environment,
  so its OIDC subjects are `repo:<owner>/<repo>:ref:refs/heads/dev` and
  `repo:<owner>/<repo>:ref:refs/heads/stage`. Do not allow arbitrary refs or forks.
- GitHub environment `eif-release`: restrict deployment branches to `dev` and
  `stage`; configure required reviewers to approve publication. Environment
  approval controls the publication job, not the earlier read-only preparation.
- Allow the publication job's `GITHUB_TOKEN` to create tags/releases
  (`contents: write`). Repository rules must permit `stage-signet-v*` tags.
  The preparation job has read-only GitHub access and a separate AWS role.

The workflow file must be on the repository's default branch for manual
dispatch to be available. Select `dev` or `stage` in **Use workflow from**;
that ref must contain the publisher. This chooses the workflow implementation,
not the EIF source. Other workflow refs are skipped before assuming AWS access.

## Publish

1. Run **Build EIF** with `stage-signet` and wait for both Mint and Burn jobs
   to succeed. Both sets must be uploaded to S3.
2. Open **Actions → Publish EIF Release → Run workflow**.
3. Set `source_branch` to `stage` (or `dev`). The selected build commit must
   belong to that branch's history. Publication never rebuilds the branch tip.
4. Set `git_sha` to the full 40-character commit SHA of that build.
5. Set `build_run_id` to the numeric ID in its Actions URL:
   `https://github.com/<owner>/<repo>/actions/runs/<build_run_id>`.
6. Set a new `release_tag`, for example `stage-signet-v0.1.0`.
7. Review the prepared `verified-eif-release` Actions artifact and approve the
   `eif-release` environment if a reviewer is required.
8. Open the release URL in the publication job summary.

Tags use `stage-signet-v*`, not `v*`: this keeps publication separate from the
existing tag-triggered EIF build. The tag points to the EIF source SHA, which
can differ from the commit running the publisher. Existing tags or releases
are refused; the workflow never moves a tag or replaces published assets.

## Verification before publication

The publisher checks a successful Build EIF run from this repository, its SHA
and approved source history. It downloads the eight expected files for each
role from S3 and compares every byte by SHA-256 against the corresponding
Actions artifact from that run. It then checks the EIF/host checksum manifests,
role/profile/commit/run metadata, nonzero SHA-384 PCR0/PCR1/PCR2, Signet and
Arbitrum settings, and the same RGB asset in both images.

This comparison is required because the build's S3 path can be overwritten,
including by a rerun with different repository variables. A missing, expired
or deleted Actions artifact blocks publication. Publish while those artifacts
are retained; there is no S3-only bypass. Mixed outputs from reruns are refused.
The publisher does not execute downloaded code or independently recompute PCRs
with Nitro. It trusts the approved Build EIF run's recorded measurements and
requires S3 to contain exactly those build outputs.

A release is created as a draft. All assets are uploaded and downloaded again
to check their hashes before the draft becomes a prerelease. Upload or final
verification failure leaves an unpublished draft (or just a reserved tag if
creation failed). Review and explicitly remove that failed draft/tag before
retrying, or use a new version. The workflow does not clean them up automatically.

## What the signer receives

The release body identifies the source SHA, source branch, build run, network,
profile and separate Burn/Mint PCR0/PCR1/PCR2. Assets are:

- `<tag>-burn.tar.gz` and `<tag>-mint.tar.gz`: each contains the role's EIF,
  `PCR.json`, `IMAGE-ENV.json`, `metadata.json`, Parent, CLI, `SHA256SUMS` and
  `HOST-SHA256SUMS`, under a `burn/` or `mint/` directory. Executable permissions
  are set for Parent and CLI in the archives.
- `PCR-burn.json` and `PCR-mint.json`: measurements available without extracting
  the archives.
- `release-manifest.json`: source/build information and SHA-256 hashes for
  every original file in each role bundle, including JSON manifests.
- `SHA256SUMS`: hashes of every other release asset.

Download all assets and run `sha256sum --check SHA256SUMS` before extracting
the appropriate archive. A Burn cosigner uses the Burn archive and its PCRs.
Use the verifier/CLI belonging to the same release. Verify the running signer's
AWS attestation and approved identity separately; see [verify a signer](verify-a-signer.md).

This workflow never changes GitHub's production **Latest** marker. Stage
versions appear under **Releases** as **Pre-release**, with Public Signet in
the title. Share the exact approved tag URL with cosigners; GitHub's
`releases/latest` URL is not a Stage channel. Publishing an older build for
rollback does not automatically make it the current approved deployment.

Publication is an operator's release approval, not evidence that Stage is
running that image. The profile's validation assumptions are recorded in the
source commit's `build/profiles/README.md`. A private repository's releases
require repository access; publication here does not make the files public.
No seed, runtime RPC credential, host configuration or AWS attestation bundle
is collected by this workflow. The archives include the existing measured
image environment, including any public Mint KMS account allowlist.
