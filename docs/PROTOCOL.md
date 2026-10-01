# ReleaseGuard protocol

## Boundary

The project owner chooses a baseline and proposes a release. GitHub supplies publicly fetchable, full-commit source snapshots; the GitHub page itself is not treated as a trustworthy reviewer. GenLayer validators independently fetch the locked bytes and verify SHA-256 hashes. The contract owns the three judgments, their recorded findings, the deterministic gate, timelock, and active-version history. An external deployment pipeline may read the decision but must separately authenticate it and enforce it. ReleaseGuard never deploys, executes, or audits binaries.

## Manifest

Each manifest is a UTF-8 JSON document, max 8,000 bytes, served from a full 40-hex commit URL on `raw.githubusercontent.com`. It has `version`, `migration_notes`, and one to three `files`. Each file has `path`, `url`, and lowercase `sha256`. File URLs must be full-commit raw GitHub URLs in the same repository, and their trailing path must match `path`. Their commit may precede the manifest commit: a manifest cannot contain its own commit hash while being committed. Each source file is max 6,000 bytes and must be valid UTF-8. The manifest itself is bound by its submitted SHA-256.

The owner supplies manifest URLs and hashes, but cannot make forged source bytes pass validation. Establishing a baseline verifies its source and version under consensus. A proposal stores the baseline and candidate references, so later reviews cannot silently swap one version. Missing, changed, oversized, or nonmatching evidence fails closed as `INSUFFICIENT_EVIDENCE`.

## Review lifecycle

1. `establish_baseline` verifies and records the original version. It is a declared starting point, not proof that a prior release was safe or deployed.
2. `propose_upgrade` freezes the baseline reference, candidate reference, and project review policy. One proposal can be pending at a time.
3. `assess_dimension` independently compares all locked source for `PERMISSIONS`, `EXTERNAL_CALLS`, or `MIGRATION`. Each transaction stores source-change paths, evidence status, a dimension-specific finding code, an outcome, and a concise rationale. Validators rerun the fetch and judgment and must agree on the substantive finding code and outcome; the rationale is advisory, not a consensus field.
4. `finalize_review` requires all three assessments. A `FAIL` gives `REJECTED`; an `INSUFFICIENT_EVIDENCE` or `CONCERN` gives `NEEDS_REVIEW`; three `PASS` results give `TIMELOCKED`.
5. After the configured delay (60 seconds to 30 days), only the owner may call `activate_upgrade`. The contract records the new active manifest and keeps version history. The 60-second minimum supports a short live demonstration; operational deployments should choose a governance-appropriate delay. The owner may cancel an assessing or timelocked proposal; rejected or review-needed proposals cannot activate.

Finding codes differ by dimension: permissions distinguish no expansion, controlled expansion, and unapproved expansion; external calls distinguish no new destination, reviewable new destination, and unapproved destination; migration distinguishes compatibility, uncertainty, and data-loss risk. These findings make the on-chain result more precise than a single generic classification.

## Limitations

AI comparison can be wrong. The contract verifies the *listed* files, not repository completeness, compiled artifacts, runtime behavior, or security of unlisted dependencies. A malicious manifest can omit relevant files; users should pair this with a build provenance/coverage process. The owner could choose a weak policy or a bad initial baseline. The contract does not force an external deployment service to obey its active version. GitHub and network outages may cause review to remain incomplete or return insufficient evidence. Do not call this a production security guarantee.
