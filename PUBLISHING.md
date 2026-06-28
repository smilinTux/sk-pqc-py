# Publishing `sk-pqc`

This package ships to [PyPI](https://pypi.org/project/sk-pqc/) through GitHub
Actions using **PyPI Trusted Publishing (OIDC)** — there is **no API token**
stored in the repo, in a GitHub secret, or anywhere else. PyPI mints a
short-lived, single-use credential for exactly one repo + workflow + environment,
verified over OpenID Connect at publish time.

The two workflows involved:

| Workflow | Trigger | Does |
| --- | --- | --- |
| `.github/workflows/test.yml` | push to `main`, every PR | pytest on CPython 3.10 / 3.11 / 3.12 + the cross-impl byte-identity gate |
| `.github/workflows/release.yml` | push of a `v*` tag | build sdist+wheel, re-run the gate, publish to PyPI (OIDC), cut a GitHub Release |

---

## One-time setup (PyPI side, browser, project owner)

Trusted publishing is configured **on PyPI**, not in this repo. Do this once.

### A. If the project does not exist on PyPI yet (first publish)

1. Sign in to <https://pypi.org/manage/account/publishing/>.
2. Under **Add a new pending publisher**, fill in exactly:
   - **PyPI Project Name:** `sk-pqc`
   - **Owner:** `smilinTux`
   - **Repository name:** `sk-pqc-py`
   - **Workflow name:** `release.yml`
   - **Environment name:** `pypi`
3. Save. This "pending publisher" lets the very first tagged run create the
   project and upload, with no token.

### B. If the project already exists on PyPI

1. Go to <https://pypi.org/manage/project/sk-pqc/settings/publishing/>.
2. **Add a new trusted publisher** with the same five values as above
   (owner `smilinTux`, repo `sk-pqc-py`, workflow `release.yml`, environment
   `pypi`).

### C. GitHub environment (this repo)

The workflow declares `environment: name: pypi`. Create it once so you can add
protection if desired:

1. Repo **Settings → Environments → New environment → `pypi`**.
2. (Recommended) Add a **Required reviewer** and/or restrict the environment to
   the `v*` tag pattern, so a publish can't happen without a human ack. The
   environment name **must** stay `pypi` — it is part of the OIDC subject PyPI
   checks.

> The environment name, repo, owner, and workflow filename are **all** part of
> what PyPI verifies. If you rename `release.yml`, move the repo, or change the
> environment, you must update the trusted-publisher entry on PyPI or publishing
> will fail closed (which is the safe direction).

---

## Cutting a release (the tag → release flow)

1. **Update the version** in `pyproject.toml` (`[project] version = "X.Y.Z"`).
   The release workflow asserts the tag matches this value and aborts otherwise.
2. **Update `CHANGELOG.md`** — move items out of `## [Unreleased]` into a new
   `## [X.Y.Z] — YYYY-MM-DD` section, and refresh the compare/links at the
   bottom. See *CHANGELOG discipline* below.
3. **Commit** both on `main` (or merge the PR).
4. **Tag and push:**

   ```bash
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```

5. `release.yml` runs: it builds the sdist+wheel, re-runs the full test suite +
   the byte-identity gate as a publish guard, uploads to PyPI over OIDC, then
   creates the matching GitHub Release with the artifacts attached.

   Re-publishing an already-uploaded version will fail — PyPI versions are
   immutable. Bump the version; never retag.

### Dry run (no publish)

Run `release.yml` from **Actions → release → Run workflow**. On
`workflow_dispatch` (no tag) it builds and runs the gate but **skips** both the
PyPI publish and the GitHub Release. Use it to sanity-check a build before
tagging.

---

## CHANGELOG discipline

- Follow [Keep a Changelog](https://keepachangelog.com/) and
  [SemVer](https://semver.org/). Every user-visible change lands under
  `## [Unreleased]` as it merges, grouped under `Added` / `Changed` / `Fixed` /
  `Removed` / `Security`.
- At release time, rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD`, add a
  fresh empty `## [Unreleased]`, and update the link refs at the file bottom.
- **The wire format and the HKDF combiner are frozen across the `0.x` line.** A
  breaking change to either ships under a **new suite id**, not a patch bump —
  call that out explicitly in the changelog if it ever happens.
- The tag (`vX.Y.Z`), the `pyproject.toml` version, and the changelog heading
  must agree. CI enforces tag == package version.

---

## What this does and does not guarantee

- **Trusted publishing removes the long-lived PyPI token** as a thing that can
  leak. The credential is short-lived and scoped to this exact workflow run.
- It does **not** sign the artifacts or attest the source beyond PyPI's own
  provenance/attestation support. It does not vouch for the cryptographic claims
  of the package.
- `sk-pqc` is **hybrid** X25519 + ML-KEM-768 (FIPS 203): the derived secret stays
  confidential as long as **either** leg is unbroken — the classical leg covers a
  flaw in ML-KEM, the PQ leg covers a quantum attack on X25519. It is **not**
  "quantum-proof" and makes no unconditional security claim. The package is
  pre-1.0, experimental, and **not independently security-audited**. Signatures
  (ML-DSA / SLH-DSA, FIPS 204/205) are out of scope here.
