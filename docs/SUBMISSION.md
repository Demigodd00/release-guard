# Contribution submission

The public repository, live deployment, and observed lifecycle are verified. Submission does not guarantee steward acceptance.

**Category:** Intelligent Contracts  
**Title:** ReleaseGuard — Consensus-Governed Software Upgrade Review

**Notes / Description:**

```text
ReleaseGuard is a GenLayer-native Intelligent Contract for evidence-bound software upgrade governance. A project owner registers a SHA-256-verified baseline and proposes a candidate release through full-commit GitHub manifests. For each proposal, GenLayer validators independently fetch and hash the listed baseline and candidate source, then separately assess permission changes, external destinations, and migration risk. Each dimension stores a distinct finding code, changed-file paths, and evidence status; validators compare the substantive findings, not just JSON formatting. Contract logic rejects a concrete failure, flags concerns or missing evidence for review, and timelocks three passes before owner activation. Version history remains auditable. ReleaseGuard records a reviewed release decision; it does not deploy code or guarantee that unlisted files are safe.
```

**Evidence links:** add these separately as URL evidence:

1. Public repository: `https://github.com/Demigodd00/release-guard`
2. Exact deployed source: `https://github.com/Demigodd00/release-guard/blob/bcbbd9880c8d66323e0b45024876661de451699f/contracts/ReleaseGuard.py`
3. StudioNet contract: `https://explorer-studio.genlayer.com/address/0x00046b66f829c5841AFB8fb448d5609CE5037842`
4. Deployment and live transaction record: `https://github.com/Demigodd00/release-guard/blob/main/deployments/studionet.json`
5. Baseline and candidate manifests: `https://github.com/Demigodd00/release-guard/tree/bcbbd9880c8d66323e0b45024876661de451699f/evidence/demo`
6. Successful lint and 11-test CI run: `https://github.com/Demigodd00/release-guard/actions/runs/36860010543`

The observed on-chain proposal status is `ACTIVATED` and active version is `1.1.0`. The demo owner's private key was intentionally not retained, so describe this as a completed demonstration, not an operational upgrade account.
