"""Deploy and exercise ReleaseGuard with disposable StudioNet-only signers."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from eth_account import Account
from eth_utils import to_checksum_address
from genlayer_py import create_client
from genlayer_py.assertions import tx_execution_succeeded
from genlayer_py.chains import studionet
from genlayer_py.types import TransactionHashVariant, TransactionStatus


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "contracts" / "ReleaseGuard.py"
RECORD = ROOT / "deployments" / "studionet.json"
REVIEW_POLICY = (
    "A release may not add permissions or outbound domains. Its migration must "
    "preserve every existing record field and value; adding an optional schema marker is allowed."
)


def run_git(*args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True).stdout


def tx_hex(value: object) -> str:
    rendered = str(value)
    return rendered if rendered.startswith("0x") else "0x" + bytes(value).hex()


def wait(client, transaction, *, allow_disagreement: bool = False) -> dict:
    receipt = client.wait_for_transaction_receipt(
        transaction_hash=tx_hex(transaction),
        status=TransactionStatus.FINALIZED,
        interval=5_000,
        retries=120,
        full_transaction=True,
    )
    if (receipt.get("status_name") or receipt.get("statusName")) != TransactionStatus.FINALIZED.value:
        raise RuntimeError("transaction did not finalize: " + tx_hex(transaction))
    if not tx_execution_succeeded(receipt):
        raise RuntimeError("execution failed: " + json.dumps(receipt, default=str))
    result = receipt.get("result_name") or receipt.get("resultName")
    if result not in (None, "AGREE", "MAJORITY_AGREE") and not allow_disagreement:
        raise RuntimeError("consensus failed: " + json.dumps(receipt, default=str))
    return receipt


def write(client, address: str, method: str, args: list, *, retry: bool = False) -> tuple[str, list[str]]:
    attempts = []
    for attempt in range(3 if retry else 1):
        tx = client.write_contract(address=address, function_name=method, args=args)
        attempts.append(tx_hex(tx))
        print(json.dumps({"step": method, "attempt": attempt + 1, "transaction": tx_hex(tx)}), flush=True)
        receipt = wait(client, tx, allow_disagreement=retry)
        if (receipt.get("result_name") or receipt.get("resultName")) in (None, "AGREE", "MAJORITY_AGREE"):
            return tx_hex(tx), attempts
    raise RuntimeError(method + " did not reach consensus: " + json.dumps(attempts))


def read(client, address: str, method: str, args: list):
    return client.read_contract(
        address=address,
        function_name=method,
        args=args,
        transaction_hash_variant=TransactionHashVariant.LATEST_FINAL,
    )


def extract_address(receipt: dict) -> str:
    for key in ("tx_data_decoded", "data"):
        item = receipt.get(key)
        if isinstance(item, dict) and item.get("contract_address"):
            return to_checksum_address(str(item["contract_address"]))
    raise RuntimeError("deployment receipt omitted contract address")


def verify_public(commit: str, path: str) -> tuple[str, str]:
    expected = run_git("show", "HEAD:" + path)
    url = "https://raw.githubusercontent.com/Demigodd00/release-guard/" + commit + "/" + path
    with urllib.request.urlopen(url, timeout=25) as response:
        actual = response.read()
    if actual != expected:
        raise RuntimeError("public evidence differs from committed bytes: " + path)
    return url, hashlib.sha256(expected).hexdigest()


def verify_deployed_source(client, address: str, expected: str) -> str:
    encoded = client.provider.make_request("gen_getContractCode", [address]).get("result")
    if not isinstance(encoded, str):
        raise RuntimeError("deployed contract code unavailable")
    actual = base64.b64decode(encoded, validate=True).decode("utf-8")
    normalized = lambda value: value.replace("\r\n", "\n")
    if normalized(actual) != normalized(expected):
        raise RuntimeError("deployed source differs from public commit")
    return hashlib.sha256(normalized(expected).encode("utf-8")).hexdigest()


def main() -> None:
    if run_git("status", "--porcelain"):
        raise RuntimeError("commit and push the exact source before deploying")
    commit = run_git("rev-parse", "HEAD").decode("ascii").strip()
    source = SOURCE.read_text(encoding="utf-8")
    tracked = run_git("show", "HEAD:contracts/ReleaseGuard.py").decode("utf-8")
    if source.replace("\r\n", "\n") != tracked.replace("\r\n", "\n"):
        raise RuntimeError("local source differs from committed source")
    baseline_url, baseline_sha = verify_public(commit, "evidence/demo/baseline.json")
    candidate_url, candidate_sha = verify_public(commit, "evidence/demo/candidate.json")
    verify_public(commit, "contracts/ReleaseGuard.py")

    owner = Account.create()
    client = create_client(chain=studionet, account=owner)
    deployment = client.deploy_contract(code=source, account=owner, args=[REVIEW_POLICY, 60])
    print(json.dumps({"step": "deploy", "transaction": tx_hex(deployment)}), flush=True)
    address = extract_address(wait(client, deployment))
    print(json.dumps({"step": "deployed", "address": address}), flush=True)

    baseline_tx, _ = write(client, address, "establish_baseline", ["1.0.0", baseline_url, baseline_sha], retry=True)
    state = read(client, address, "get_state", [])
    if state.get("active_version") != "1.0.0":
        raise RuntimeError("baseline not visible after finalization: " + json.dumps(state))
    proposal_tx, _ = write(client, address, "propose_upgrade", ["1.1.0", candidate_url, candidate_sha])
    assessments = {}
    for dimension in ("PERMISSIONS", "EXTERNAL_CALLS", "MIGRATION"):
        tx, attempts = write(client, address, "assess_dimension", [1, dimension], retry=True)
        proposal = read(client, address, "get_proposal", [1])
        finding = proposal.get("assessments", {}).get(dimension)
        if not isinstance(finding, dict) or not finding.get("evidence_verified"):
            raise RuntimeError(dimension + " evidence was not verified: " + json.dumps(proposal))
        assessments[dimension] = {"transaction": tx, "attempts": attempts, "finding": finding}
        print(json.dumps({"dimension": dimension, "finding": finding}), flush=True)

    finalize_tx, _ = write(client, address, "finalize_review", [1])
    proposal = read(client, address, "get_proposal", [1])
    activate_tx = None
    if proposal.get("status") == "TIMELOCKED":
        wait_seconds = max(0, int(proposal["ready_at"]) - int(time.time()) + 2)
        if wait_seconds:
            print(json.dumps({"step": "waiting_for_timelock", "seconds": wait_seconds}), flush=True)
            time.sleep(wait_seconds)
        activate_tx, _ = write(client, address, "activate_upgrade", [1])
        proposal = read(client, address, "get_proposal", [1])
        state = read(client, address, "get_state", [])
        if proposal.get("status") != "ACTIVATED" or state.get("active_version") != "1.1.0":
            raise RuntimeError("upgrade was not activated: " + json.dumps(proposal))

    record = {
        "network": "studionet",
        "chain_id": 61999,
        "status": "VERIFIED",
        "source_commit": commit,
        "source_sha256": verify_deployed_source(client, address, source),
        "contract_address": address,
        "explorer": "https://explorer-studio.genlayer.com/address/" + address,
        "deploy_transaction": tx_hex(deployment),
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "wallet_policy": "disposable StudioNet-only owner; private key not retained",
        "owner": owner.address,
        "baseline": {"url": baseline_url, "sha256": baseline_sha, "transaction": baseline_tx},
        "candidate": {"url": candidate_url, "sha256": candidate_sha, "proposal_transaction": proposal_tx},
        "assessments": assessments,
        "finalize_transaction": finalize_tx,
        "activate_transaction": activate_tx,
        "observed_proposal_status": proposal["status"],
        "observed_active_version": read(client, address, "get_state", [])["active_version"],
    }
    RECORD.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"contract": address, "status": proposal["status"], "record": str(RECORD)}), flush=True)


if __name__ == "__main__":
    main()

