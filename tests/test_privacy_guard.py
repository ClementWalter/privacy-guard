#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest==9.1.1"]
# ///
"""Offline tests for privacy_guard: each rule fires on real-shaped data and stays quiet on look-alikes."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import privacy_guard as pg  # noqa: E402

# Fixtures are assembled at runtime so this file never trips the guard itself.
GH = "ghp_" + "a1B2" * 9
SLACK = "xoxc-" + "1234567890-abcdef"
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
GOOGLE = "AIza" + "S" * 35
JWT = "eyJ" + "hbGciOiJIUzI1NiJ9" + ".eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + ".abcdefghijklmnop"
PEM = "-----BEGIN " + "RSA PRIVATE KEY-----"
ANTHROPIC = "sk-ant-" + "api03-" + "Z" * 40
HOME = "/Us" + "ers/jeanmichel/Documents/x"
EMAIL = "jean.michel" + "@" + "gmail.com"
PHONE = "06 71 42 " + "93 58"
PHONE_INTL = "+33 6 71 42 " + "93 58"
IBAN_OK = "FR76 3000 6000 0112 3456 7890 189"  # privacy-guard: allow
NIR_OK = "1 85 05 78 006 084 91"  # privacy-guard: allow


def rules(line: str, denylist=None) -> set[str]:
    return {rule for rule, _ in pg.scan_line(line, denylist or [])}


@pytest.mark.parametrize(
    ("line", "rule"),
    [
        (f"token = '{GH}'", "github-token"),
        (f"SLACK={SLACK}", "slack-token"),
        (f"key {AWS}", "aws-key"),
        (f"k={GOOGLE}", "google-api-key"),
        (f"auth: Bearer {JWT}", "jwt"),
        (PEM, "private-key"),
        (f"ANTHROPIC_API_KEY={ANTHROPIC}", "llm-api-key"),
        ("api_key = 'q8Zr2Lw9Xp4Nt7Vb3Kd6'", "credential-assignment"),  # privacy-guard: allow gitleaks:allow
        (f"cfg = '{HOME}'", "home-path"),
        (f"contact {EMAIL}", "email"),
        (f"tel {PHONE}", "phone-fr"),
        (f"tel {PHONE_INTL}", "phone-fr"),
        (f"iban {IBAN_OK}", "iban"),
        ("PN = '33669" + "524017@s.whatsapp.net'", "whatsapp-id"),  # privacy-guard: allow
        ("p = '33669" + "524017:25@s.whatsapp.net'", "whatsapp-id"),  # privacy-guard: allow
        ("g = '1203630920" + "17791687@g.us'", "whatsapp-id"),  # privacy-guard: allow
        (f"nir {NIR_OK}", "nir"),
    ],
)
def test_rule_fires(line, rule):
    assert rule in rules(line)


@pytest.mark.parametrize(
    "line",
    [
        "git clone git@github.com:ClementWalter/notion-cli.git",
        "Co-Authored-By: Claude <noreply@anthropic.com>",
        "email = 'alice@example.com'",
        "path = '/Users/someone/Documents/notion-cli'",
        "path = '/home/runner/work'",
        "api_key = '<your-api-key-goes-here>'",
        "password = 'changeme-changeme-changeme'",
        "tx = 0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060",
        "FR76 3000 6000 0112 3456 7890 188",
        "timestamp 1712345678901",
        f"secret = '{GH}'  # privacy-guard: allow",
        'token = "__Secure-next-auth.session-token"',
        'session_id = "01a13cca-82f2-75f9-85a0-7c0f30e0c1cc"',
        '"token": "private-hub-fixture-token-1"',
        'SECRETS_FILE = "/run/ascii-secrets/env.sh"',
        "{'From': 'me@gmail.com', 'To': 'alice@y.org'}",
        'CLAUDE_MD = f"{MARKER}\\n@AGENTS.md"',
        "wa send 33612345678@s.whatsapp.net hi",
        'jid = "33123456789:23@s.whatsapp.net"',
        "imsg read +33600000000",
        "draft-delete r-0987654321",
        "assert path('/home/a%u/repo') and '/Users/x/Documents'",
    ],
)
def test_rule_quiet(line):
    assert rules(line) == set()


def test_denylist_literal_is_case_insensitive():
    deny = [pg.re.compile(r"(?<!\w)Zorglub(?!\w)", pg.re.I)]
    assert "denylist#1" in rules("hello ZORGLUB street", deny)


def test_denylist_hit_never_echoes_the_term(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST", "Zorglub")
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST_FILE", str(tmp_path / "none.txt"))
    f = tmp_path / "a.md"
    f.write_text("met Zorglub today\n")
    assert [x.excerpt for x in pg.scan_files([str(f)], tmp_path)] == ["<hidden>"]


def test_denylist_reads_regex_entries(tmp_path, monkeypatch):
    deny_file = tmp_path / "deny.txt"
    deny_file.write_text("# comment\nre:acct-\\d{6}\n")
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST_FILE", str(deny_file))
    monkeypatch.delenv("PRIVACY_GUARD_DENYLIST", raising=False)
    assert len(pg.load_denylist()) == 1


def test_allowlist_drops_a_denylist_entry(tmp_path, monkeypatch):
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST", "Zorglub\nre:Gl[ou]rb")
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST_FILE", str(tmp_path / "none.txt"))
    (tmp_path / ".privacy-guard-allow").write_text("^deny:Gl\\[ou\\]rb$\n")
    f = tmp_path / "a.md"
    f.write_text("Glorb and Zorglub\n")
    assert [x.rule for x in pg.scan_files([str(f)], tmp_path)] == ["denylist#1"]


def test_excerpt_is_masked():
    assert pg.mask(GH) == "ghp_…"


@pytest.mark.parametrize(
    "name",
    [".env", ".env.production", "token.json", "client_secret_123.json", "cookies.sqlite",
     "tg.session", "chat.db", "id_ed25519", "export_cookies.json"],
)
def test_sensitive_file_names(name):
    assert pg.sensitive_name(name)


@pytest.mark.parametrize("name", [".env.example", "README.md", "tokenizer.py", "session.py"])
def test_ordinary_file_names(name):
    assert not pg.sensitive_name(name)


def test_allowlist_file_skips_matching_hit(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVACY_GUARD_DENYLIST", raising=False)
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST_FILE", str(tmp_path / "none.txt"))
    (tmp_path / ".privacy-guard-allow").write_text("^support@deezer\\.com$\n")
    f = tmp_path / "a.py"
    f.write_text("URL = 'mailto:support@deezer.com'\n")  # privacy-guard: allow
    assert list(pg.scan_files([str(f)], tmp_path)) == []


def test_pdf_is_skipped(tmp_path):
    f = tmp_path / "book.pdf"
    f.write_text(f"%PDF-1.4 {EMAIL}")
    assert list(pg.scan_files([str(f)], tmp_path)) == []


def test_binary_content_is_skipped(tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"\0\0" + EMAIL.encode())
    assert list(pg.scan_files([str(f)], tmp_path)) == []


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVACY_GUARD_DENYLIST", raising=False)
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST_FILE", str(tmp_path / "none.txt"))
    run = lambda *a: subprocess.run(["git", "-C", str(tmp_path), *a], check=True, capture_output=True)  # noqa: E731
    run("init", "-q")
    run("config", "user.email", "t@example.com")
    run("config", "user.name", "t")
    run("config", "commit.gpgsign", "false")
    (tmp_path / "a.txt").write_text(f"leak {EMAIL}\n")
    run("add", ".")
    run("commit", "-qm", "leak")
    (tmp_path / "a.txt").write_text("clean\n")
    run("commit", "-qam", "clean")
    return tmp_path


def test_history_finds_removed_leak(repo):
    assert [f.rule for f in pg.scan_history(repo)] == ["email"]


def test_all_mode_sees_only_current_tree(repo):
    assert pg.main(["--all", "--repo", str(repo)]) == 0


def test_main_exits_nonzero_on_finding(tmp_path, monkeypatch):
    monkeypatch.delenv("PRIVACY_GUARD_DENYLIST", raising=False)
    monkeypatch.setenv("PRIVACY_GUARD_DENYLIST_FILE", str(tmp_path / "none.txt"))
    f = tmp_path / "a.md"
    f.write_text(f"{PHONE}\n")
    assert pg.main([str(f), "--repo", str(tmp_path)]) == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
