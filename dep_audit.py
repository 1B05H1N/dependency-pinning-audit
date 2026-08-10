#!/usr/bin/env python3
"""Audit dependency manifests for unpinned or risky version specs.

Checks Python `requirements.txt` and Node `package.json` for supply-chain
hygiene: unpinned dependencies, floating ranges, wildcards/`latest`, and
VCS/URL/file installs that bypass the registry. Standard library only.
"""
import argparse
import json
import os
import re
import sys

REQ_LINE_RE = re.compile(r"^([A-Za-z0-9._\-]+)\s*(\[[^\]]*\])?\s*(.*)$")
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _finding(file, package, spec, severity, message):
    return {"file": file, "package": package, "spec": spec, "severity": severity, "message": message}


def audit_requirements(text, filename="requirements.txt"):
    findings = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r", "--requirement", "-c", "--constraint", "-i", "--index")):
            continue
        if line.startswith("-e") or "://" in line or line.startswith("git+"):
            pkg = line.split("#egg=")[-1] if "#egg=" in line else line
            findings.append(_finding(filename, pkg, line, "high", "VCS/URL install bypasses the index and is unpinned"))
            continue
        marker = line.split(";", 1)[0].strip()  # drop environment markers
        m = REQ_LINE_RE.match(marker)
        if not m:
            continue
        name, _extras, spec = m.group(1), m.group(2), m.group(3).strip()
        if not spec:
            findings.append(_finding(filename, name, "(none)", "high", "unpinned dependency (no version specifier)"))
        elif "*" in spec:
            findings.append(_finding(filename, name, spec, "high", "wildcard version"))
        elif "==" in spec or "===" in spec:
            continue  # pinned - good
        else:
            findings.append(_finding(filename, name, spec, "medium", "floating version range (not pinned to ==)"))
    return findings


def audit_package_json(obj, filename="package.json"):
    findings = []
    for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        deps = obj.get(section) or {}
        for name, ver in deps.items():
            if not isinstance(ver, str):
                continue
            v = ver.strip()
            low = v.lower()
            if any(tok in low for tok in ("://", "git+", "file:", "github:", "link:", "git:")):
                findings.append(_finding(filename, name, v, "high", "VCS/URL/file install bypasses the registry"))
            elif low in ("*", "latest", "x", ""):
                findings.append(_finding(filename, name, v, "high", "wildcard/latest version"))
            elif v.startswith(("^", "~")):
                findings.append(_finding(filename, name, v, "medium", "caret/tilde range (not exact)"))
            elif re.match(r"^\d+\.\d+\.\d+([\-+].+)?$", v):
                continue  # exact semver - good
            else:
                findings.append(_finding(filename, name, v, "medium", "range or non-exact version"))
    return findings


def audit_file(path):
    base = os.path.basename(path).lower()
    with open(path, encoding="utf-8", errors="replace") as fh:
        content = fh.read()
    if base == "package.json" or base.endswith(".json"):
        return audit_package_json(json.loads(content), path)
    return audit_requirements(content, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Audit dependency manifests for unpinned/risky versions.")
    parser.add_argument("files", nargs="+", help="requirements.txt and/or package.json paths")
    parser.add_argument("--json", dest="json_out", help="write findings to this JSON file")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK), default="high")
    args = parser.parse_args(argv)

    all_findings = []
    for path in args.files:
        findings = audit_file(path)
        all_findings.extend(findings)
        if not findings:
            sys.stdout.write("%s: OK - all dependencies pinned\n" % path)
        for f in findings:
            sys.stdout.write("[%-8s] %s  %s -> %s (%s)\n" % (
                f["severity"].upper(), f["file"], f["package"], f["spec"], f["message"]))

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as out:
            json.dump(all_findings, out, indent=2)

    worst = max((SEVERITY_RANK[f["severity"]] for f in all_findings), default=-1)
    return 1 if worst >= SEVERITY_RANK[args.fail_on] else 0


if __name__ == "__main__":
    raise SystemExit(main())
