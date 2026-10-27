# privacy-guard

A pre-commit hook and CI scan that keep secrets and personal data out of public
repositories. It runs on the standard library only, so the guard adds no
dependencies of its own.

**Visibility: public.** The repo contains rules only. The private terms live in
each user's denylist, outside the repo.

## What it blocks

| Rule | Catches |
| --- | --- |
| secrets | GitHub, Slack, AWS, Google, LLM, Stripe, Telegram bot and 1Password tokens; private keys; JWTs; `token = "<random>"` assignments |
| `home-path` | `/Users/<name>/…`, `/home/<name>/…`, `C:\Users\<name>` (placeholders such as `someone` and `runner` pass) |
| `email` | any address outside `example.*`, `*.test`, `noreply`, `git@`, placeholder names |
| `whatsapp-id` | phone-number JIDs, LIDs and group ids |
| `phone-fr`, `iban`, `nir` | French phone numbers, IBANs and NIRs (both checksum-validated) |
| `sensitive-file` | `.env`, cookies, `token.json`, `client_secret*.json`, keys, `*.session`, databases |
| `denylist#N` | your own terms (see below); reported by number, never echoed |

Synthetic values such as `0123456789`, `33600000000` and `33612345678` pass.

## Use it in a repo

`.pre-commit-config.yaml` (pin `rev` to a commit SHA):

```yaml
repos:
  - repo: https://github.com/ClementWalter/privacy-guard
    rev: <sha>
    hooks:
      - id: privacy-guard
      - id: privacy-guard-files
```

Then run `prek install`.

`.github/workflows/privacy.yml`:

```yaml
name: privacy
on: [push, pull_request]
permissions:
  contents: read
jobs:
  privacy:
    uses: ClementWalter/privacy-guard/.github/workflows/scan.yml@<sha>
    with:
      guard-ref: <sha>
    secrets: inherit
```

CI scans the tree and the full history with privacy-guard, then with gitleaks
(checksum-verified binary).

## Denylist

Put one term per line in `~/.config/privacy-guard/denylist.txt`: names,
addresses, account numbers. Prefix a line with `re:` for a regex; `#` starts a
comment. In CI, store the same content in the `PRIVACY_GUARD_DENYLIST` repo
secret.

## Allowing a deliberate value

- Add `privacy-guard: allow` to the line.
- Or add a regex to `.privacy-guard-allow` at the repo root. Any finding whose
  matched text matches it is skipped.

## Commands

```bash
privacy-guard FILE...        # what the hook runs
privacy-guard --all          # every tracked file
privacy-guard --history      # every line ever added, on every ref
uv run --script privacy_guard.py --history --repo ~/Documents/notion-cli
```

## Tests

```bash
uv run --script tests/test_privacy_guard.py
```
