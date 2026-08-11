# dependency-pinning-audit

[![CI](https://github.com/1B05H1N/dependency-pinning-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/1B05H1N/dependency-pinning-audit/actions/workflows/ci.yml)

Audit dependency manifests for unpinned or risky version specs - a lightweight
supply-chain hygiene check. Handles Python `requirements.txt` and Node
`package.json`. Pure Python standard library, no dependencies.

> **Goal:** enforce "pin your dependencies" in CI. Floating ranges and
> `latest`/`*` are how you get a surprise malicious version at 2am.

## What it does

- `requirements.txt`: flags unpinned deps (no specifier), floating ranges
  (`>=`, `~=`, `<`, ...), wildcards (`1.34.*`), and `-e`/`git+`/URL installs.
  Respects comments, `-r`/`-c` includes, extras, and environment markers.
- `package.json`: flags `*`/`latest`, caret/tilde ranges (`^`, `~`), other
  non-exact ranges, and git/URL/file installs, across all dependency sections.
- Severity-ranked output, optional JSON, `--fail-on` for CI gating.

## Files

- `dep_audit.py` - CLI and audit engine
- `samples/requirements.txt`, `samples/package.json` - example manifests
- `test_dep_audit.py` - unit tests

## Usage

```bash
python3 dep_audit.py samples/requirements.txt samples/package.json
python3 dep_audit.py requirements.txt --fail-on medium --json findings.json
```

## Test

```bash
python3 -m unittest -v
```

## Disclaimer

This repository reflects personal study and practice; sample manifests are
synthetic. Pinning is one control among many (also use lockfiles, hashes, and a
review process). Provided as-is.

## License

MIT. See [LICENSE](LICENSE).
