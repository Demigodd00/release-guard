from pathlib import Path
import hashlib
import json


CONTRACT = Path(__file__).resolve().parents[2] / "contracts" / "ReleaseGuard.py"
SDK = "v0.2.16"
ROOT = "https://raw.githubusercontent.com/example/release-guard/" + "a" * 40 + "/"
BASE_SOURCE = "permissions = ['read']\nendpoint = 'https://api.example.com'\nstate = {'v': 1}\n"
GOOD_SOURCE = "permissions = ['read']\nendpoint = 'https://api.example.com'\nstate = {'v': 2}\n"
BAD_SOURCE = "permissions = ['read', 'admin']\nendpoint = 'https://evil.example.com'\nstate = {}\n"


def digest(body):
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def setup(vm, direct_deploy, owner, *, source=GOOD_SOURCE, source_digest=None):
    vm.warp("2026-10-01T00:00:00Z")
    vm.sender = owner
    contract = direct_deploy(
        str(CONTRACT),
        "No new admin permissions or unapproved outbound domains; state migration must preserve existing records.",
        3600,
        sdk_version=SDK,
    )
    base_url, base_hash = mock_bundle(vm, "1.0.0", BASE_SOURCE, "baseline.json")
    contract.establish_baseline("1.0.0", base_url, base_hash)
    candidate_url, candidate_hash = mock_bundle(
        vm, "1.1.0", source, "candidate.json", source_digest=source_digest
    )
    return contract, candidate_url, candidate_hash


def mock_bundle(vm, version, source, manifest_name, *, source_digest=None, manifest_body=None):
    source_url = ROOT + manifest_name.replace(".json", ".py")
    manifest_url = ROOT + manifest_name
    body = manifest_body or json.dumps(
        {
            "version": version,
            "migration_notes": "State v1 records are preserved and v2 adds an optional key.",
            "files": [{
                "path": manifest_name.replace(".json", ".py"),
                "url": source_url,
                "sha256": source_digest or digest(source),
            }],
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    vm.mock_web(manifest_url, {"status": 200, "body": body})
    vm.mock_web(source_url, {"status": 200, "body": source})
    return manifest_url, digest(body)


def mock_assessments(vm, *, permissions="PASS", external="PASS", migration="PASS"):
    codes = {
        "PERMISSIONS": {"PASS": "NO_EXPANSION", "CONCERN": "CONTROLLED_EXPANSION", "FAIL": "UNAPPROVED_EXPANSION"},
        "EXTERNAL_CALLS": {"PASS": "NO_NEW_DESTINATION", "CONCERN": "REVIEW_NEW_DESTINATION", "FAIL": "UNAPPROVED_DESTINATION"},
        "MIGRATION": {"PASS": "COMPATIBLE", "CONCERN": "UNCLEAR_MIGRATION", "FAIL": "DATA_LOSS_RISK"},
    }
    for dimension, outcome in (
        ("PERMISSIONS", permissions),
        ("EXTERNAL_CALLS", external),
        ("MIGRATION", migration),
    ):
        vm.mock_llm(
            "Assess only " + dimension,
            json.dumps({"finding_code": codes[dimension][outcome], "reason": dimension + " review finding."}),
        )


def propose(contract, url, sha):
    return contract.propose_upgrade("1.1.0", url, sha)


def assess_all(contract, vm, proposal_id):
    mock_assessments(vm)
    for dimension in ("PERMISSIONS", "EXTERNAL_CALLS", "MIGRATION"):
        assert contract.assess_dimension(proposal_id, dimension) == "PASS"


def test_full_upgrade_lifecycle_and_separate_bound_findings(
    direct_vm, direct_deploy, direct_alice, direct_bob
):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice)
    proposal_id = propose(contract, url, sha)
    mock_assessments(direct_vm)
    assert contract.assess_dimension(proposal_id, "PERMISSIONS") == "PASS"
    leader = direct_vm._captured_validators[-1][0]
    assert direct_vm.run_validator(leader_result=leader) is True
    for dimension in ("EXTERNAL_CALLS", "MIGRATION"):
        assert contract.assess_dimension(proposal_id, dimension) == "PASS"
    proposal = contract.get_proposal(proposal_id)
    assert len(proposal["assessments"]) == 3
    assert proposal["assessments"]["PERMISSIONS"]["evidence_verified"] is True
    assert proposal["assessments"]["MIGRATION"]["changed_files"] == ["baseline.py", "candidate.py"]
    assert contract.finalize_review(proposal_id) == "TIMELOCKED"
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("owner_required"):
        contract.activate_upgrade(proposal_id)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("timelock_active"):
        contract.activate_upgrade(proposal_id)
    # Simulate a later block; direct VM clock behavior differs by platform.
    proposal = contract.get_proposal(proposal_id)
    proposal["ready_at"] = 0
    contract.proposals[str(int(proposal_id))] = json.dumps(proposal, sort_keys=True, separators=(",", ":"))
    contract.activate_upgrade(proposal_id)
    assert contract.get_state()["active_version"] == "1.1.0"
    assert contract.get_version("1.1.0")["proposal_id"] == 1
    assert contract.get_proposal(proposal_id)["status"] == "ACTIVATED"


def test_incomplete_and_duplicate_assessment_rejected(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice)
    proposal_id = propose(contract, url, sha)
    with direct_vm.expect_revert("assessments_incomplete"):
        contract.finalize_review(proposal_id)
    mock_assessments(direct_vm)
    contract.assess_dimension(proposal_id, "PERMISSIONS")
    with direct_vm.expect_revert("dimension_already_assessed"):
        contract.assess_dimension(proposal_id, "PERMISSIONS")
    with direct_vm.expect_revert("dimension_invalid"):
        contract.assess_dimension(proposal_id, "UNRELATED")


def test_concern_requires_review_and_cannot_activate(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice)
    proposal_id = propose(contract, url, sha)
    mock_assessments(direct_vm, migration="CONCERN")
    for dimension in ("PERMISSIONS", "EXTERNAL_CALLS", "MIGRATION"):
        contract.assess_dimension(proposal_id, dimension)
    assert contract.finalize_review(proposal_id) == "NEEDS_REVIEW"
    assert contract.get_state()["pending_id"] == "0"
    with direct_vm.expect_revert("proposal_not_timelocked"):
        contract.activate_upgrade(proposal_id)


def test_fail_rejects_even_if_other_dimensions_pass(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice, source=BAD_SOURCE)
    proposal_id = propose(contract, url, sha)
    mock_assessments(direct_vm, external="FAIL")
    for dimension in ("PERMISSIONS", "EXTERNAL_CALLS", "MIGRATION"):
        contract.assess_dimension(proposal_id, dimension)
    assert contract.finalize_review(proposal_id) == "REJECTED"
    assert contract.get_state()["active_version"] == "1.0.0"


def test_tampered_source_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice, source_digest="f" * 64)
    proposal_id = propose(contract, url, sha)
    assert contract.assess_dimension(proposal_id, "PERMISSIONS") == "INSUFFICIENT_EVIDENCE"
    finding = contract.get_proposal(proposal_id)["assessments"]["PERMISSIONS"]
    assert finding["reason"] == "source_hash_mismatch"
    assert finding["evidence_verified"] is False


def test_missing_manifest_fails_closed(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice)
    direct_vm.clear_mocks()
    mock_bundle(direct_vm, "1.0.0", BASE_SOURCE, "baseline.json")
    direct_vm.mock_web(url, {"status": 404, "body": "not found"})
    proposal_id = propose(contract, url, sha)
    result = contract.assess_dimension(proposal_id, "MIGRATION")
    assert result == "INSUFFICIENT_EVIDENCE"
    assert contract.get_proposal(proposal_id)["assessments"]["MIGRATION"]["reason"] == "manifest_http_status"


def test_validator_rejects_material_disagreement(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice)
    proposal_id = propose(contract, url, sha)
    mock_assessments(direct_vm, permissions="PASS")
    contract.assess_dimension(proposal_id, "PERMISSIONS")
    leader = direct_vm._captured_validators[-1][0]
    direct_vm.clear_mocks()
    mock_bundle(direct_vm, "1.0.0", BASE_SOURCE, "baseline.json")
    mock_bundle(direct_vm, "1.1.0", GOOD_SOURCE, "candidate.json")
    mock_assessments(direct_vm, permissions="FAIL")
    assert direct_vm.run_validator(leader_result=leader) is False


def test_owner_baseline_and_proposal_constraints(direct_vm, direct_deploy, direct_alice, direct_bob):
    direct_vm.warp("2026-10-01T00:00:00Z")
    direct_vm.sender = direct_alice
    contract = direct_deploy(str(CONTRACT), "Never add admin permissions.", 3600, sdk_version=SDK)
    base_url, base_sha = mock_bundle(direct_vm, "1.0.0", BASE_SOURCE, "baseline.json")
    direct_vm.sender = direct_bob
    with direct_vm.expect_revert("owner_required"):
        contract.establish_baseline("1.0.0", base_url, base_sha)
    direct_vm.sender = direct_alice
    with direct_vm.expect_revert("baseline_required"):
        contract.propose_upgrade("1.1.0", base_url, base_sha)
    contract.establish_baseline("1.0.0", base_url, base_sha)
    with direct_vm.expect_revert("baseline_already_established"):
        contract.establish_baseline("1.0.0", base_url, base_sha)
    with direct_vm.expect_revert("full_commit_raw_github_url_required"):
        contract.propose_upgrade("1.1.0", ROOT.replace("a" * 40, "main") + "candidate.json", base_sha)
    candidate_url, candidate_sha = mock_bundle(direct_vm, "1.1.0", GOOD_SOURCE, "candidate.json")
    proposal_id = propose(contract, candidate_url, candidate_sha)
    with direct_vm.expect_revert("pending_proposal_exists"):
        propose(contract, candidate_url, candidate_sha)
    contract.cancel_proposal(proposal_id)
    assert contract.get_proposal(proposal_id)["status"] == "CANCELLED"


def test_manifest_rejects_foreign_repo_source(direct_vm, direct_deploy, direct_alice):
    contract, url, sha = setup(direct_vm, direct_deploy, direct_alice)
    other_root = ROOT.replace("example/release-guard", "unrelated/foreign-repo")
    body = json.dumps({
        "version": "2.0.0",
        "migration_notes": "No migration.",
        "files": [{"path": "wrong.py", "url": other_root + "wrong.py", "sha256": digest("print(1)\n")}],
    }, sort_keys=True, separators=(",", ":"))
    second_url = ROOT + "bad.json"
    direct_vm.mock_web(second_url, {"status": 200, "body": body})
    proposal_id = contract.propose_upgrade("2.0.0", second_url, digest(body))
    assert contract.assess_dimension(proposal_id, "PERMISSIONS") == "INSUFFICIENT_EVIDENCE"
    assert contract.get_proposal(proposal_id)["assessments"]["PERMISSIONS"]["reason"] == "file_not_repo_bound"


def test_no_change_cannot_pass(direct_vm, direct_deploy, direct_alice):
    contract, _, _ = setup(direct_vm, direct_deploy, direct_alice)
    # Different manifest, but exactly the same source path and hash as the baseline.
    candidate_url = ROOT + "same-source.json"
    body = json.dumps({
        "version": "1.1.0",
        "migration_notes": "No change to code.",
        "files": [{"path": "baseline.py", "url": ROOT + "baseline.py", "sha256": digest(BASE_SOURCE)}],
    }, sort_keys=True, separators=(",", ":"))
    direct_vm.mock_web(candidate_url, {"status": 200, "body": body})
    candidate_sha = digest(body)
    proposal_id = propose(contract, candidate_url, candidate_sha)
    assert contract.assess_dimension(proposal_id, "PERMISSIONS") == "FAIL"
    assert contract.get_proposal(proposal_id)["assessments"]["PERMISSIONS"]["reason"] == "no_source_change"
