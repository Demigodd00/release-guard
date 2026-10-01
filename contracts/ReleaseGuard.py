# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }

from genlayer import *
from datetime import datetime
import hashlib
import json
import re


ERROR_EXPECTED = "[EXPECTED]"
RAW_GITHUB = re.compile(
    r"https://raw\.githubusercontent\.com/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/"
    r"([0-9a-fA-F]{40})/([A-Za-z0-9_./-]+)"
)
DIMENSIONS = ("PERMISSIONS", "EXTERNAL_CALLS", "MIGRATION")
FINDINGS = {
    "PERMISSIONS": {
        "NO_EXPANSION": "PASS",
        "CONTROLLED_EXPANSION": "CONCERN",
        "UNAPPROVED_EXPANSION": "FAIL",
    },
    "EXTERNAL_CALLS": {
        "NO_NEW_DESTINATION": "PASS",
        "REVIEW_NEW_DESTINATION": "CONCERN",
        "UNAPPROVED_DESTINATION": "FAIL",
    },
    "MIGRATION": {
        "COMPATIBLE": "PASS",
        "UNCLEAR_MIGRATION": "CONCERN",
        "DATA_LOSS_RISK": "FAIL",
    },
}
MAX_MANIFEST_BYTES = 8000
MAX_SOURCE_BYTES = 6000
MAX_FILES = 3


def _fail(code: str) -> None:
    raise gl.vm.UserError(f"{ERROR_EXPECTED} {code}")


def _now() -> int:
    return int(datetime.fromisoformat(gl.message_raw["datetime"]).timestamp())


def _sha(value: str) -> str:
    clean = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", clean) is None:
        _fail("invalid_sha256")
    return clean


def _url(value: str) -> tuple:
    match = RAW_GITHUB.fullmatch(value)
    if match is None or ".." in match.group(4) or "//" in match.group(4):
        _fail("full_commit_raw_github_url_required")
    return match.groups()


def _text(value: str, label: str, limit: int) -> str:
    clean = value.strip()
    if not clean or len(clean) > limit or "\x00" in clean:
        _fail(label + "_invalid")
    return clean


def _dump(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


class ReleaseGuard(gl.Contract):
    owner: Address
    review_policy: str
    min_delay_seconds: u256
    active_version: str
    active_manifest_url: str
    active_manifest_sha256: str
    proposal_count: u256
    pending_id: u256
    proposals: TreeMap[str, str]
    version_history: TreeMap[str, str]

    def __init__(self, review_policy: str, min_delay_seconds: u256):
        self.owner = gl.message.sender_address
        self.review_policy = _text(review_policy, "review_policy", 1200)
        delay = int(min_delay_seconds)
        if delay < 3600 or delay > 30 * 86400:
            _fail("delay_out_of_bounds")
        self.min_delay_seconds = min_delay_seconds
        self.active_version = ""
        self.active_manifest_url = ""
        self.active_manifest_sha256 = ""
        self.proposal_count = u256(0)
        self.pending_id = u256(0)

    def _only_owner(self) -> None:
        if gl.message.sender_address != self.owner:
            _fail("owner_required")

    def _get_proposal(self, proposal_id: u256) -> dict:
        number = int(proposal_id)
        if number < 1 or number > int(self.proposal_count):
            _fail("proposal_missing")
        return json.loads(self.proposals[str(number)])

    def _save(self, proposal: dict) -> None:
        self.proposals[str(proposal["id"])] = _dump(proposal)

    def _read_bytes(self, url: str, limit: int) -> tuple:
        try:
            response = gl.nondet.web.get(url)
        except Exception:
            return "fetch_failed", b""
        if response.status != 200:
            return "http_status", b""
        body = response.body
        if not body or len(body) > limit:
            return "size_invalid", b""
        return "", body

    def _bundle(self, manifest_url: str, manifest_sha256: str) -> dict:
        root = _url(manifest_url)
        error, raw = self._read_bytes(manifest_url, MAX_MANIFEST_BYTES)
        if error:
            return {"ok": False, "reason": "manifest_" + error}
        if hashlib.sha256(raw).hexdigest() != manifest_sha256:
            return {"ok": False, "reason": "manifest_hash_mismatch"}
        try:
            manifest = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {"ok": False, "reason": "manifest_invalid_json"}
        if not isinstance(manifest, dict):
            return {"ok": False, "reason": "manifest_invalid_shape"}
        version = manifest.get("version")
        files = manifest.get("files")
        notes = manifest.get("migration_notes")
        if (
            not isinstance(version, str)
            or not version.strip()
            or len(version) > 64
            or not isinstance(notes, str)
            or not notes.strip()
            or len(notes) > 1200
            or not isinstance(files, list)
            or not 1 <= len(files) <= MAX_FILES
        ):
            return {"ok": False, "reason": "manifest_invalid_shape"}
        sources = {}
        hashes = {}
        for item in files:
            if not isinstance(item, dict):
                return {"ok": False, "reason": "file_invalid_shape"}
            path = item.get("path")
            source_url = item.get("url")
            digest = item.get("sha256")
            if (
                not isinstance(path, str)
                or not isinstance(source_url, str)
                or not isinstance(digest, str)
                or re.fullmatch(r"[A-Za-z0-9_./-]+", path) is None
                or ".." in path
                or "//" in path
                or path in hashes
                or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            ):
                return {"ok": False, "reason": "file_invalid_shape"}
            try:
                source_root = _url(source_url)
            except gl.vm.UserError:
                return {"ok": False, "reason": "file_url_invalid"}
            # The manifest's commit cannot contain its own commit hash. Source
            # files may therefore be pinned to an earlier commit in this repo.
            if source_root[:2] != root[:2] or source_root[3] != path:
                return {"ok": False, "reason": "file_not_repo_bound"}
            error, body = self._read_bytes(source_url, MAX_SOURCE_BYTES)
            if error:
                return {"ok": False, "reason": "source_" + error}
            if hashlib.sha256(body).hexdigest() != digest:
                return {"ok": False, "reason": "source_hash_mismatch"}
            try:
                sources[path] = body.decode("utf-8")
            except UnicodeDecodeError:
                return {"ok": False, "reason": "source_not_utf8"}
            hashes[path] = digest
        return {
            "ok": True,
            "reason": "",
            "version": version.strip(),
            "notes": notes.strip(),
            "sources": sources,
            "hashes": hashes,
        }

    def _verified_baseline(self, manifest_url: str, manifest_sha256: str, version: str) -> bool:
        def inspect() -> dict:
            bundle = self._bundle(manifest_url, manifest_sha256)
            return {
                "ok": bundle["ok"] and bundle.get("version") == version,
                "reason": bundle["reason"] if not bundle["ok"] else "",
                "hashes": bundle.get("hashes", {}),
            }

        def validate(leader: gl.vm.Result) -> bool:
            if not isinstance(leader, gl.vm.Return):
                return False
            ours = inspect()
            theirs = leader.calldata
            return (
                isinstance(theirs, dict)
                and theirs.get("ok") == ours["ok"]
                and theirs.get("reason") == ours["reason"]
                and theirs.get("hashes") == ours["hashes"]
                and ours["reason"] != "manifest_fetch_failed"
            )

        return bool(gl.vm.run_nondet_unsafe(inspect, validate)["ok"])

    @gl.public.write
    def establish_baseline(self, version: str, manifest_url: str, manifest_sha256: str) -> None:
        self._only_owner()
        if self.active_version:
            _fail("baseline_already_established")
        version = _text(version, "version", 64)
        _url(manifest_url)
        manifest_sha256 = _sha(manifest_sha256)
        if not self._verified_baseline(manifest_url, manifest_sha256, version):
            _fail("baseline_evidence_invalid")
        self.active_version = version
        self.active_manifest_url = manifest_url
        self.active_manifest_sha256 = manifest_sha256
        self.version_history[version] = _dump({
            "version": version,
            "manifest_url": manifest_url,
            "manifest_sha256": manifest_sha256,
            "activated_at": _now(),
            "proposal_id": 0,
        })

    @gl.public.write
    def propose_upgrade(self, version: str, manifest_url: str, manifest_sha256: str) -> u256:
        self._only_owner()
        if not self.active_version:
            _fail("baseline_required")
        if int(self.pending_id) != 0:
            _fail("pending_proposal_exists")
        version = _text(version, "version", 64)
        if version == self.active_version or self.version_history.get(version, ""):
            _fail("version_already_used")
        _url(manifest_url)
        manifest_sha256 = _sha(manifest_sha256)
        if manifest_url == self.active_manifest_url or manifest_sha256 == self.active_manifest_sha256:
            _fail("candidate_must_differ")
        number = int(self.proposal_count) + 1
        proposal = {
            "id": number,
            "status": "ASSESSING",
            "base_version": self.active_version,
            "base_manifest_url": self.active_manifest_url,
            "base_manifest_sha256": self.active_manifest_sha256,
            "candidate_version": version,
            "candidate_manifest_url": manifest_url,
            "candidate_manifest_sha256": manifest_sha256,
            "review_policy": self.review_policy,
            "created_at": _now(),
            "ready_at": 0,
            "assessments": {},
        }
        self.proposal_count = u256(number)
        self.pending_id = u256(number)
        self._save(proposal)
        return u256(number)

    def _assess(self, proposal: dict, dimension: str) -> dict:
        def inspect() -> dict:
            baseline = self._bundle(proposal["base_manifest_url"], proposal["base_manifest_sha256"])
            if not baseline["ok"]:
                return {"outcome": "INSUFFICIENT_EVIDENCE", "finding_code": "EVIDENCE_MISSING", "reason": "baseline_" + baseline["reason"], "changed_files": [], "evidence_verified": False}
            candidate = self._bundle(proposal["candidate_manifest_url"], proposal["candidate_manifest_sha256"])
            if not candidate["ok"] or candidate.get("version") != proposal["candidate_version"]:
                reason = candidate["reason"] if not candidate["ok"] else "candidate_version_mismatch"
                return {"outcome": "INSUFFICIENT_EVIDENCE", "finding_code": "EVIDENCE_MISSING", "reason": reason, "changed_files": [], "evidence_verified": False}
            changed = sorted(
                path for path in set(baseline["hashes"]) | set(candidate["hashes"])
                if baseline["hashes"].get(path) != candidate["hashes"].get(path)
            )
            if not changed:
                return {"outcome": "FAIL", "finding_code": "NO_SOURCE_CHANGE", "reason": "no_source_change", "changed_files": [], "evidence_verified": True}
            prompt = (
                "Review this proposed software upgrade. Assess only " + dimension + ". "
                "Compare the approved baseline source with the candidate source and migration notes. "
                "Apply this project review policy: " + proposal["review_policy"] + "\n"
                "Return JSON with finding_code and a concise reason. Choose exactly one finding_code from: "
                + ", ".join(FINDINGS[dimension]) + ". "
                "The first code means no material risk in this dimension, the second means unresolved review, "
                "and the third means a concrete violation or unsafe incompatibility. "
                "Do not infer safety from notes alone.\n"
                "Changed paths: " + _dump({"files": changed}) + "\n"
                "Baseline files: " + _dump(baseline["sources"]) + "\n"
                "Candidate files: " + _dump(candidate["sources"]) + "\n"
                "Migration notes: " + candidate["notes"]
            )
            response = gl.nondet.exec_prompt(prompt, response_format="json")
            if not isinstance(response, dict):
                _fail("llm_invalid_shape")
            finding_code = str(response.get("finding_code", "")).strip().upper()
            reason = str(response.get("reason", "")).strip()
            if finding_code not in FINDINGS[dimension] or not reason or len(reason) > 400:
                _fail("llm_invalid_shape")
            return {
                "outcome": FINDINGS[dimension][finding_code],
                "finding_code": finding_code,
                "reason": reason,
                "changed_files": changed,
                "evidence_verified": True,
            }

        def validate(leader: gl.vm.Result) -> bool:
            if not isinstance(leader, gl.vm.Return):
                return False
            theirs = leader.calldata
            if not isinstance(theirs, dict):
                return False
            ours = inspect()
            return (
                theirs.get("outcome") == ours["outcome"]
                and theirs.get("finding_code") == ours["finding_code"]
                and theirs.get("evidence_verified") == ours["evidence_verified"]
                and theirs.get("changed_files") == ours["changed_files"]
                and (
                    ours["evidence_verified"]
                    or (theirs.get("reason") == ours["reason"] and ours["reason"] not in ("baseline_manifest_fetch_failed", "manifest_fetch_failed", "baseline_source_fetch_failed", "source_fetch_failed"))
                )
            )

        return gl.vm.run_nondet_unsafe(inspect, validate)

    @gl.public.write
    def assess_dimension(self, proposal_id: u256, dimension: str) -> str:
        proposal = self._get_proposal(proposal_id)
        dimension = dimension.strip().upper()
        if dimension not in DIMENSIONS:
            _fail("dimension_invalid")
        if proposal["status"] != "ASSESSING" or int(self.pending_id) != proposal["id"]:
            _fail("proposal_not_assessing")
        if dimension in proposal["assessments"]:
            _fail("dimension_already_assessed")
        result = self._assess(proposal, dimension)
        proposal["assessments"][dimension] = result
        self._save(proposal)
        return result["outcome"]

    @gl.public.write
    def finalize_review(self, proposal_id: u256) -> str:
        proposal = self._get_proposal(proposal_id)
        if proposal["status"] != "ASSESSING" or int(self.pending_id) != proposal["id"]:
            _fail("proposal_not_assessing")
        assessments = proposal["assessments"]
        if any(dimension not in assessments for dimension in DIMENSIONS):
            _fail("assessments_incomplete")
        outcomes = [assessments[dimension]["outcome"] for dimension in DIMENSIONS]
        if "FAIL" in outcomes:
            proposal["status"] = "REJECTED"
        elif "INSUFFICIENT_EVIDENCE" in outcomes or "CONCERN" in outcomes:
            proposal["status"] = "NEEDS_REVIEW"
        else:
            proposal["status"] = "TIMELOCKED"
            proposal["ready_at"] = _now() + int(self.min_delay_seconds)
        if proposal["status"] != "TIMELOCKED":
            self.pending_id = u256(0)
        self._save(proposal)
        return proposal["status"]

    @gl.public.write
    def activate_upgrade(self, proposal_id: u256) -> None:
        self._only_owner()
        proposal = self._get_proposal(proposal_id)
        if proposal["status"] != "TIMELOCKED" or int(self.pending_id) != proposal["id"]:
            _fail("proposal_not_timelocked")
        if _now() < proposal["ready_at"]:
            _fail("timelock_active")
        if proposal["base_version"] != self.active_version:
            _fail("baseline_changed")
        self.active_version = proposal["candidate_version"]
        self.active_manifest_url = proposal["candidate_manifest_url"]
        self.active_manifest_sha256 = proposal["candidate_manifest_sha256"]
        proposal["status"] = "ACTIVATED"
        proposal["activated_at"] = _now()
        self.version_history[self.active_version] = _dump({
            "version": self.active_version,
            "manifest_url": self.active_manifest_url,
            "manifest_sha256": self.active_manifest_sha256,
            "activated_at": _now(),
            "proposal_id": proposal["id"],
        })
        self.pending_id = u256(0)
        self._save(proposal)

    @gl.public.write
    def cancel_proposal(self, proposal_id: u256) -> None:
        self._only_owner()
        proposal = self._get_proposal(proposal_id)
        if proposal["status"] not in ("ASSESSING", "TIMELOCKED") or int(self.pending_id) != proposal["id"]:
            _fail("proposal_not_cancellable")
        proposal["status"] = "CANCELLED"
        self.pending_id = u256(0)
        self._save(proposal)

    @gl.public.view
    def get_state(self) -> dict:
        return {
            "owner": str(self.owner),
            "review_policy": self.review_policy,
            "min_delay_seconds": str(int(self.min_delay_seconds)),
            "active_version": self.active_version,
            "active_manifest_url": self.active_manifest_url,
            "active_manifest_sha256": self.active_manifest_sha256,
            "proposal_count": str(int(self.proposal_count)),
            "pending_id": str(int(self.pending_id)),
        }

    @gl.public.view
    def get_proposal(self, proposal_id: u256) -> dict:
        return self._get_proposal(proposal_id)

    @gl.public.view
    def get_version(self, version: str) -> dict:
        raw = self.version_history.get(version, "")
        if not raw:
            _fail("version_missing")
        return json.loads(raw)
