#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Block private data from reaching a public repository.

Scans files (a pre-commit hook passes the staged ones), every tracked file
(`--all`), or every line ever added to the git history (`--history`) for:

- secrets: API tokens, private keys, JWTs, credential-looking assignments;
- personal data: home-directory paths, email addresses, French phone numbers,
  IBANs and NIRs (checksum-validated to keep false positives low);
- files that hold credentials by nature (`.env`, cookies, OAuth tokens, keys,
  session stores, databases);
- the user's own denylist (names, addresses, account ids) read from
  `~/.config/privacy-guard/denylist.txt` and `$PRIVACY_GUARD_DENYLIST`.
  Denylist hits are reported by entry number only, so CI logs never echo them.

A line containing `privacy-guard: allow` is skipped. A repo-root
`.privacy-guard-allow` file holds one regex per line; a finding whose matched
text matches one of them is skipped. Stdlib only, so the hook itself adds no
supply-chain surface.
"""

from __future__ import annotations

import argparse
import fnmatch
import logging
import math
import os
import re
import subprocess
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("privacy-guard")

ALLOW_PRAGMA = "privacy-guard: allow"
ALLOW_FILE = ".privacy-guard-allow"
DENYLIST_PATH = Path.home() / ".config" / "privacy-guard" / "denylist.txt"
DENYLIST_ENV = "PRIVACY_GUARD_DENYLIST"

SECRET_RULES: dict[str, re.Pattern[str]] = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY"),
    "aws-key": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    "github-token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})"),
    "slack-token": re.compile(r"\bxox[abcdeprs]-[A-Za-z0-9%-]{10,}"),
    "google-api-key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    "google-oauth-secret": re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{20,}"),
    "google-refresh-token": re.compile(r"\b1//0[A-Za-z0-9_-]{30,}"),
    "llm-api-key": re.compile(r"\bsk-(?:ant-|or-v1-|proj-)?[A-Za-z0-9_-]{32,}"),
    "stripe-key": re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "telegram-bot-token": re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
    "1password-token": re.compile(r"\bops_[A-Za-z0-9_-]{50,}"),
}

# `name = "value"` where the name says credential and the value looks random.
ASSIGNMENT = re.compile(
    r"""(?ix)
    \b[\w.-]*(?:password|passwd|secret|token|api[_-]?key|private[_-]?key|
              access[_-]?key|session[_-]?id|mnemonic|seed[_-]?phrase)[\w.-]*
    ["']?\s*[:=]\s*["']([^"'\s]{16,})["']
    """
)
PLACEHOLDER = re.compile(
    r"[<>{}$*/]|\.\.\.|xxx|example|dummy|fake|stub|test|your|changeme|redacted|"
    r"fixture|synthetic|sample|placeholder",
    re.I,
)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
# Identifiers built from words (`__Secure-next-auth.session-token`) are names, not secrets.
WORDY = re.compile(r"^[A-Za-z_]*(?:[-_.][A-Za-z_]+)*$")

HOME_PATH = re.compile(r"(?:/Users|/home|[A-Za-z]:\\\\?Users)[/\\]+([A-Za-z0-9._-]+)")
HOME_PLACEHOLDERS = {
    "someone", "me", "you", "user", "username", "runner", "example", "name",
    "alice", "bob", "foo", "jdoe", "shared", "public", "default", "admin",
}

EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b")
EMAIL_SAFE_DOMAINS = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|example|test|invalid|localhost|"
    r"users\.noreply\.github\.com)$",
    re.I,
)
EMAIL_SAFE_LOCAL = re.compile(
    r"^(?:git|noreply|no-reply|donotreply|do-not-reply|me|you|user|username|someone|"
    r"name|foo|bar|alice|bob|carol|dan|dave|eve|mallory|jane|john|jdoe)$",
    re.I,
)
# `x.org`-style single-letter domains are placeholders; code-file "TLDs" are not domains.
EMAIL_FAKE_DOMAIN = re.compile(
    r"^(?:[a-z]\.[a-z]{2,3}|.*\.(?:md|py|js|ts|tsx|json|txt|ya?ml|toml|sh|rs|go|html|css|lock|cfg|ini))$",
    re.I,
)
# Digits runs nobody owns: 0123456789, 33600000000, 33612345678.
SYNTHETIC_DIGITS = re.compile(r"12345678|23456789|98765|0000000|(\d)\1{5,}")

# WhatsApp ids: phone-number JIDs (`33612345678[:device]@s.whatsapp.net`), LIDs and groups.
WA_JID = re.compile(r"\b(\d{6,})(?::\d+)?@(?:s\.whatsapp\.net|g\.us|lid|c\.us)\b")
WA_DOMAINS = re.compile(r"(?:^|\.)(?:whatsapp\.net|g\.us|c\.us)$", re.I)

PHONE_FR = re.compile(r"(?<![\w+])(?:(?:\+|00)33[\s.-]?|0)[1-9](?:[\s.-]?\d{2}){4}(?!\w)")
IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
NIR = re.compile(
    r"\b([12]) ?(\d{2}) ?(0[1-9]|1[0-2]|[2-9]\d) ?(\d{2}|2[AB]) ?(\d{3}) ?(\d{3}) ?(\d{2})\b"
)

SENSITIVE_FILES = [
    ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx", "id_rsa*", "id_ed25519*",
    "*cookies*.json", "*cookies*.txt", "cookies.sqlite", "token.json", "*_token.json",
    "client_secret*.json", "credentials.json", "service_account*.json", "*.session",
    "*.session-journal", "*.sqlite", "*.sqlite3", "*.db", ".netrc", ".pypirc",
]
# Formats whose bytes are not prose: scanning them yields noise, not leaks.
OPAQUE_SUFFIXES = {
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svgz", ".epub", ".zip",
    ".gz", ".tgz", ".xz", ".woff", ".woff2", ".ttf", ".otf", ".mp3", ".m4a", ".ogg",
    ".wav", ".mp4", ".mov", ".pyc", ".whl", ".so", ".dylib",
}
SENSITIVE_FILE_EXCEPTIONS = [".env.example", ".env.sample", ".env.template"]


@dataclass(frozen=True)
class Finding:
    """One hit: where it is, which rule fired, and a masked excerpt."""

    location: str
    rule: str
    excerpt: str
    hit: str = field(default="", repr=False, compare=False)

    def render(self) -> str:
        return f"{self.location}: {self.rule}: {self.excerpt}"


def mask(value: str) -> str:
    """Keep enough of a hit to find it, not enough to leak it."""
    return value[:4] + "…" if len(value) > 6 else "…"


def entropy(value: str) -> float:
    counts = {c: value.count(c) for c in set(value)}
    return -sum(n / len(value) * math.log2(n / len(value)) for n in counts.values())


def iban_valid(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    digits = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(digits) % 97 == 1


def nir_valid(m: re.Match[str]) -> bool:
    sex, yy, mm, dept, commune, order, key = m.groups()
    # Corsica departments are encoded as 19 / 18 for the checksum.
    dept_num = {"2A": "19", "2B": "18"}.get(dept, dept)
    body = int(sex + yy + mm + dept_num + commune + order)
    return 97 - body % 97 == int(key)


def load_denylist() -> list[re.Pattern[str]]:
    """Denylist entries: literal terms, or `re:<regex>`; `#` starts a comment."""
    lines: list[str] = []
    path = Path(os.environ.get("PRIVACY_GUARD_DENYLIST_FILE", DENYLIST_PATH))
    if path.is_file():
        lines += path.read_text().splitlines()
    lines += os.environ.get(DENYLIST_ENV, "").splitlines()
    out = []
    for raw in lines:
        entry = raw.strip()
        if not entry or entry.startswith("#"):
            continue
        if entry.startswith("re:"):
            out.append(re.compile(entry[3:], re.I))
        else:
            out.append(re.compile(rf"(?<!\w){re.escape(entry)}(?!\w)", re.I))
    return out


def load_allowlist(root: Path) -> list[re.Pattern[str]]:
    f = root / ALLOW_FILE
    if not f.is_file():
        return []
    return [
        re.compile(line.strip())
        for line in f.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def scan_line(line: str, denylist: list[re.Pattern[str]]) -> Iterator[tuple[str, str]]:
    """Yield (rule, matched text) for every private-data hit on one line."""
    if ALLOW_PRAGMA in line:
        return
    for rule, rx in SECRET_RULES.items():
        for m in rx.finditer(line):
            yield rule, m.group(0)
    for m in ASSIGNMENT.finditer(line):
        value = m.group(1)
        if PLACEHOLDER.search(value) or UUID.match(value) or WORDY.match(value):
            continue
        if entropy(value) > 3.5:
            yield "credential-assignment", value
    for m in HOME_PATH.finditer(line):
        user = m.group(1)
        if user.lower() not in HOME_PLACEHOLDERS and len(user) > 2 and not user.startswith("."):
            yield "home-path", m.group(0)
    for m in WA_JID.finditer(line):
        if not SYNTHETIC_DIGITS.search(m.group(1)):
            yield "whatsapp-id", m.group(0)
    for m in EMAIL.finditer(line):
        local = m.group(0).split("@", 1)[0]
        domain = m.group(1)
        if WA_DOMAINS.search(domain) or EMAIL_SAFE_DOMAINS.search(domain) or EMAIL_FAKE_DOMAIN.match(domain):
            continue
        if EMAIL_SAFE_LOCAL.match(local) or SYNTHETIC_DIGITS.search(local.split(":")[0]):
            continue
        yield "email", m.group(0)
    for m in PHONE_FR.finditer(line):
        if not SYNTHETIC_DIGITS.search(re.sub(r"\D", "", m.group(0))):
            yield "phone-fr", m.group(0)
    for m in IBAN.finditer(line):
        if iban_valid(m.group(0)):
            yield "iban", m.group(0)
    for m in NIR.finditer(line):
        if nir_valid(m):
            yield "nir", m.group(0)
    for i, rx in enumerate(denylist, 1):
        if rx.search(line):
            yield f"denylist#{i}", ""


def sensitive_name(path: str) -> bool:
    name = Path(path).name
    if name in SENSITIVE_FILE_EXCEPTIONS:
        return False
    return any(fnmatch.fnmatch(name, pat) for pat in SENSITIVE_FILES)


def findings_for_text(
    location: str,
    lines: Iterable[tuple[int | str, str]],
    denylist: list[re.Pattern[str]],
    allowlist: list[re.Pattern[str]],
) -> Iterator[Finding]:
    for lineno, line in lines:
        for rule, hit in scan_line(line, denylist):
            if hit and any(a.search(hit) for a in allowlist):
                continue
            yield Finding(f"{location}:{lineno}", rule, mask(hit) if hit else "<hidden>", hit or rule)


def scan_files(paths: Iterable[str], root: Path) -> Iterator[Finding]:
    denylist, allowlist = load_denylist(), load_allowlist(root)
    for p in paths:
        path = Path(p)
        if sensitive_name(p):
            yield Finding(p, "sensitive-file", Path(p).name)
        if not path.is_file() or path.name == ALLOW_FILE or path.suffix.lower() in OPAQUE_SUFFIXES:
            continue
        data = path.read_bytes()
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="replace")
        yield from findings_for_text(p, enumerate(text.splitlines(), 1), denylist, allowlist)


def git(root: Path, *args: str) -> str:
    out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True)
    # History may hold non-UTF-8 blobs; a scan must not die on them.
    return out.stdout.decode("utf-8", errors="replace")


def scan_history(root: Path) -> Iterator[Finding]:
    """Scan every line ever added on any ref, deduplicated per (file, rule, hit)."""
    denylist, allowlist = load_denylist(), load_allowlist(root)
    out = git(root, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
              "--format=commit %H")
    commit, file, seen = "", "", set()
    for line in out.splitlines():
        if line.startswith("commit "):
            commit = line[7:19]
        elif line.startswith("+++ "):
            file = line[6:] if line.startswith("+++ b/") else ""
            if file and sensitive_name(file) and (file, "sensitive-file") not in seen:
                seen.add((file, "sensitive-file"))
                yield Finding(f"{commit}:{file}", "sensitive-file", Path(file).name)
        elif line.startswith("+") and file and Path(file).suffix.lower() not in OPAQUE_SUFFIXES:
            for f in findings_for_text(f"{commit}:{file}", [("+", line[1:])], denylist, allowlist):
                key = (file, f.rule, f.hit)
                if key not in seen:
                    seen.add(key)
                    yield f


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="privacy-guard",
        description=__doc__.split("\n\n")[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  privacy-guard README.md src/app.py   # what pre-commit runs\n"
            "  privacy-guard --all                  # every tracked file\n"
            "  privacy-guard --history              # every line ever committed\n"
        ),
    )
    parser.add_argument("files", nargs="*")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="scan every git-tracked file")
    group.add_argument("--history", action="store_true", help="scan all added lines on every ref")
    parser.add_argument("--repo", default=".", help="repository root (default: .)")
    args = parser.parse_args(argv)
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(message)s")

    root = Path(args.repo).resolve()
    if args.history:
        findings = list(scan_history(root))
    else:
        files = git(root, "ls-files").splitlines() if args.all else args.files
        if args.all:
            os.chdir(root)
        findings = list(scan_files(files, root))

    for f in findings:
        log.error(f.render())
    if findings:
        log.error(
            "%d private-data finding(s). Remove them, or mark a deliberate public "
            "value with `%s` on the line or a regex in %s.",
            len(findings), ALLOW_PRAGMA, ALLOW_FILE,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
