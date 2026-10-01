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
- `deployments/studionet.json` — verified live deployment and lifecycle record

## Verified StudioNet demonstration

The [deployed contract](https://explorer-studio.genlayer.com/address/0x00046b66f829c5841AFB8fb448d5609CE5037842) established baseline `1.0.0`, independently reviewed all three dimensions of candidate `1.1.0`, finalized three `PASS` findings, observed the timelock, and activated `1.1.0`. The [deployment record](deployments/studionet.json) lists every transaction, finding, pinned manifest URL, and exact deployed source commit (`bcbbd9880c8d66323e0b45024876661de451699f`). The [GitHub validation run](https://github.com/Demigodd00/release-guard/actions/runs/36860010543) passed lint and 11 direct tests.

This instance used a disposable StudioNet-only owner wallet, whose private key was not retained. It demonstrates the full lifecycle but cannot be controlled for future upgrades. Redeploy with a retained owner wallet for operational use; choose a longer timelock and add independent build/provenance checks.

## Local verification

```shell
python -m pip install -r requirements.txt
genvm-lint check contracts/ReleaseGuard.py
python -m pytest tests/direct -q
```

The pinned GenVM runner is declared in the first line of the contract. See `docs/PROTOCOL.md` for what the on-chain record does and does not prove.
