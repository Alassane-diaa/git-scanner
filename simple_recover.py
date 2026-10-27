#!/usr/bin/env python3

import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = 1
MAX_BLOB_SIZE = 1_000_000

# slug -> (libellé, regex). Un groupe nommé "v" désigne la valeur du secret ;
# sans groupe "v", tout le match est le secret.
PATTERNS = {
    "aws_access_key": ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
    "aws_secret_key": ("AWS secret key",
                       r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?(?P<v>[A-Za-z0-9/+=]{40})"),
    "github_token":   ("GitHub token", r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    "slack_webhook":  ("Slack webhook",
                       r"https://hooks\.slack\.com/services/[A-Z0-9]+/[A-Z0-9]+/[A-Za-z0-9]+"),
    "openai_key":     ("OpenAI key", r"\bsk-[A-Za-z0-9_-]{20,}"),
    "stripe_key":     ("Stripe live key", r"\b[sr]k_live_[A-Za-z0-9]{16,}"),
    "google_api_key": ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "private_key":    ("Private key", r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----"),
    "jwt_token":      ("JWT token",
                       r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "jwt_secret":     ("JWT secret",
                       r"(?i)jwt_secret\w*\s*[=:]\s*['\"]?(?P<v>[^\s'\"]{8,})"),
    "password":       ("Password",
                       r"(?i)(?<![\w$.-])(?:password|passwd|pwd)\b\s*[=:]\s*"
                       r"['\"]?(?P<v>[^\s'\"]{6,})"),
}
COMPILED = {k: (label, re.compile(rx)) for k, (label, rx) in PATTERNS.items()}

# Le code qui LIT un secret n'est pas un secret (faux positifs)
IGNORE = re.compile(r"[=:]\s*['\"]?(?:_require|os\.|getenv|\$\{)")

STATUS_ORDER = {"history": 0, "reflog": 1, "unreachable": 2}


class GitError(Exception):
    pass


def git(repo, *args, input=None, text=False):
    cmd = ["git", "-C", repo, "-c", "core.quotepath=false", *args]
    try:
        res = subprocess.run(cmd, input=input.encode() if isinstance(input, str) else input,
                             capture_output=True, check=True)
    except FileNotFoundError:
        raise GitError("git est introuvable dans le PATH")
    except subprocess.CalledProcessError as e:
        raise GitError(e.stderr.decode(errors="replace").strip() or "erreur git")
    return res.stdout.decode(errors="replace") if text else res.stdout


def object_ids(repo, *rev_args):
    out = git(repo, "rev-list", "--objects", *rev_args, text=True)
    return {l.split(" ", 1)[0] for l in out.splitlines() if l}


def read_blobs(repo, shas):
    for sha in shas:
        yield sha, git(repo, "cat-file", "blob", sha)


def commit_metadata(repo, commits):
    meta = {}
    for sha in commits:
        out = git(repo, "log", "-1", "--format=%an%x1f%ae%x1f%aI%x1f%at%x1f%B", sha, text=True)
        name, email, iso, ts, msg = out.split("\x1f", 4)
        meta[sha] = {"name": name, "email": email, "date": iso,
                     "ts": int(ts), "message": msg}
    return meta


def blob_origins(repo, commits):
    origins = {}
    for sha in commits:
        out = git(repo, "diff-tree", "-r", "-m", "--root", "--no-commit-id",
                  "--no-renames", sha, text=True)
        for line in out.splitlines():
            if not line.startswith(":"):
                continue
            head, _, path = line.partition("\t")
            f = head.split()
            if f[4].startswith("D") or set(f[3]) == {"0"}:
                continue
            origins.setdefault(f[3], []).append((sha, path))
    return origins


def scan_text(text):
    """Renvoie [(slug, secret, ligne)] pour un texte."""
    found, seen = [], set()
    for slug, (_label, rx) in COMPILED.items():
        for m in rx.finditer(text):
            if IGNORE.search(m.group(0)):
                continue
            secret = m.group("v") if "v" in rx.groupindex else m.group(0)
            quoted_value = bool(re.search(r"[=:]\s*['\"]", m.group(0)))
            if slug == "password" and not quoted_value and (
                "." in secret or "(" in secret or ")" in secret
                or "{" in secret or "}" in secret or ";" in secret
            ):
                continue
            line = text.count("\n", 0, m.start("v") if "v" in rx.groupindex else m.start()) + 1
            key = (slug, secret, line)
            if key not in seen:
                seen.add(key)
                found.append((slug, secret, line))
    return found


def build_finding(slug, secret, status, location, commit_info, others):
    f = {
        "type": slug,
        "status": status,
        "location": location,
        "author": ({"name": commit_info["name"], "email": commit_info["email"]}
                   if commit_info else None),
        "date": commit_info["date"] if commit_info else None,
        "also_in_commits": others,
        "secret": secret,
        "secret_length": len(secret),
        "fingerprint": hashlib.sha256(secret.encode()).hexdigest()[:12],
    }
    if location.get("blob"):
        f["recover_command"] = f"git cat-file -p {location['blob']}"
    elif location.get("commit"):
        f["recover_command"] = f"git show -s {location['commit']}"
    return f


def deduplicate_findings(findings):
    """Conserve une occurrence principale par type et fingerprint."""
    unique = {}
    for finding in findings:
        key = (finding["type"], finding["fingerprint"])
        current = unique.get(key)
        if current is None:
            unique[key] = finding
            continue

        if STATUS_ORDER[finding["status"]] < STATUS_ORDER[current["status"]]:
            finding.setdefault("also_in_locations", []).append({
                "status": current["status"],
                "location": current["location"],
                "recover_command": current.get("recover_command"),
            })
            if current.get("also_in_locations"):
                finding.setdefault("also_in_locations", []).extend(
                    current["also_in_locations"]
                )
            unique[key] = finding
        else:
            current.setdefault("also_in_locations", []).append({
                "status": finding["status"],
                "location": finding["location"],
                "recover_command": finding.get("recover_command"),
            })

    return list(unique.values())


def scan_repo(repo):
    # Vérifie que c'est bien un dépôt
    git(repo, "rev-parse", "--git-dir")

    in_history = object_ids(repo, "--all")
    in_reflog = object_ids(repo, "--reflog")

    def status_of(oid):
        if oid in in_history:
            return "history"
        if oid in in_reflog:
            return "reflog"
        return "unreachable"

    blobs, commits = [], []
    for line in git(repo, "cat-file", "--batch-all-objects", "--batch-check",
                    text=True).splitlines():
        oid, typ, size = line.split()
        if typ == "blob" and int(size) <= MAX_BLOB_SIZE:
            blobs.append(oid)
        elif typ == "commit":
            commits.append(oid)

    meta = commit_metadata(repo, commits)
    origins = blob_origins(repo, commits)
    findings = []

    # 1) Contenu des fichiers
    for oid, data in read_blobs(repo, blobs):
        if b"\0" in data[:8000]:
            continue
        hits = scan_text(data.decode(errors="replace"))
        if not hits:
            continue
        refs = sorted(origins.get(oid, []), key=lambda cp: meta.get(cp[0], {}).get("ts", 0))
        first = refs[0] if refs else None
        info = meta.get(first[0]) if first else None
        others = sorted({c for c, _ in refs[1:] if c != (first[0] if first else None)})
        for slug, secret, line in hits:
            location = {"kind": "file",
                        "path": first[1] if first else None,
                        "line": line,
                        "blob": oid,
                        "commit": first[0] if first else None}
            findings.append(build_finding(slug, secret, status_of(oid),
                                          location, info, others))

    # 2) Messages de commit
    for sha, info in meta.items():
        for slug, secret, line in scan_text(info["message"]):
            location = {"kind": "commit_message", "path": None, "line": line,
                        "blob": None, "commit": sha}
            findings.append(build_finding(slug, secret, status_of(sha),
                                          location, info, []))

    findings = deduplicate_findings(findings)
    findings.sort(key=lambda f: (STATUS_ORDER[f["status"]], f["date"] or "", f["type"]))

    by_status, by_type = {}, {}
    for f in findings:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        by_type[f["type"]] = by_type.get(f["type"], 0) + 1

    return {
        "schema_version": SCHEMA_VERSION,
        "repository": repo,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "objects_scanned": {"blobs": len(blobs), "commits": len(commits)},
        "summary": {"total": len(findings), "by_status": by_status, "by_type": by_type},
        "findings": findings,
    }


def main():
    if len(sys.argv) != 2:
        print(f"usage : {sys.argv[0]} <dépôt>", file=sys.stderr)
        return 2
    repo = sys.argv[1]

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except (AttributeError, ValueError):
            pass

    try:
        report = scan_repo(repo)
    except GitError as e:
        print(f"erreur : {e}", file=sys.stderr)
        return 2

    out = json.dumps(report, indent=2, ensure_ascii=False)
    try:
        print(out)
    except BrokenPipeError:
        pass  # ex. `| head` : le lecteur a fermé le tube

    return 1 if report["summary"]["total"] else 0


if __name__ == "__main__":
    sys.exit(main())