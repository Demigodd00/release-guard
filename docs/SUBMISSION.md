# Contribution submission

Use only after the public repository, deployment, and observed live results are verified.

**Category:** Intelligent Contracts  
**Title:** ReleaseGuard — Consensus-Governed Software Upgrade Review

**Notes / Description:**

```text
ReleaseGuard is a GenLayer-native Intelligent Contract for evidence-bound software upgrade governance. A project owner registers a SHA-256-verified baseline and proposes a candidate release through full-commit GitHub manifests. For each proposal, GenLayer validators independently fetch and hash the listed baseline and candidate source, then separately assess permission changes, external destinations, and migration risk. Each dimension stores a distinct finding code, changed-file paths, and evidence status; validators compare the substantive findings, not just JSON formatting. Contract logic rejects a concrete failure, flags concerns or missing evidence for review, and timelocks three passes before owner activation. Version history remains auditable. ReleaseGuard records a reviewed release decision; it does not deploy code or guarantee that unlisted files are safe.
```

**Evidence links:** add the public repository, exact deployed contract source commit, StudioNet Explorer contract URL, deployment record, sample manifests, and successful CI run separately. Do not claim live activation until it is observed on-chain.

