# ReleaseGuard

ReleaseGuard is a GenLayer Intelligent Contract for reviewing a proposed software upgrade against an approved baseline. It is a release-governance record, not a software deployment service or security certification.

The owner establishes a baseline from a SHA-256-verified, full-commit GitHub manifest. A candidate release then receives three separate, persistent assessments: **permissions**, **external calls**, and **state migration**. For each assessment, validators independently fetch and hash the baseline and candidate manifests and source files, compare the material finding code, and bind the result to one proposal. Contract logic combines all three findings: any failure rejects, unresolved concern or missing evidence requires review, and three passes enter a configurable timelock. Only the owner can activate after the timelock; the old version remains in history.

This is deliberately different from AgentPermit. It does not authorize one agent action, issue consumable receipts, or execute the new code. It governs *which reviewed release manifest is considered active*.

## Repository layout

- `contracts/ReleaseGuard.py` — complete single-file Intelligent Contract
- `tests/direct/test_release_guard.py` — evidence, consensus replay, authorization, and lifecycle tests
- `docs/PROTOCOL.md` — evidence and security protocol
- `docs/SUBMISSION.md` — contribution wording and evidence checklist
- `evidence/demo/module.py` — sample source with baseline and candidate versions in Git history
- `evidence/demo/*.json` — commit-pinned review manifests (added after source commits)
- `deployments/studionet.json` — live deployment record, once verified

## Local verification

```shell
python -m pip install -r requirements.txt
genvm-lint check contracts/ReleaseGuard.py
python -m pytest tests/direct -q
```

The pinned GenVM runner is declared in the first line of the contract. Test mocks do not replace a live consensus/deployment check. See `docs/PROTOCOL.md` for what the on-chain record does and does not prove.

