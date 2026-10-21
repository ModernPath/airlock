# A workspace of repos, with a parent config

One user keeps their work repos under `~/work`. Every one of them needs the
same work tools and credentials, and each should still be its own sandbox
root. See the main [README](../../README.md#parent-configs) for the general
rules; this is a worked example. Read this directory as `~/work`.

- **[`airlock.toml`](airlock.toml)** is `~/work/airlock.toml`, the user's own.
  `cascade = true` applies it to every project below. It binds the GCP and
  Argo CD tokens and declares `gcloud`, `kubectl` and `argocd`.
- **[`api/airlock.toml`](api/airlock.toml)** is the api team's file, checked
  into that repo. It declares the labels it needs without sources, and its
  own `gcloud`, pinned to the api project.
- **[`api/airlock.local.toml`](api/airlock.local.toml)** is the user's
  bindings for the api repo. `from = "parent"` links the repo's GCP label to
  the binding in `~/work/airlock.toml`.
- **[`oss-fork/airlock.local.toml`](oss-fork/airlock.local.toml)** is a fork
  of an outside project. `inherit = false` keeps the work tools and tokens
  out of it.

## What `~/work/api` gets

Started from `~/work/api`, the sandbox root is `~/work/api`, and the session
serves:

| Tool | From | Notes |
|---|---|---|
| `gcloud` | repo | replaces the parent's `gcloud` |
| `gh` | repo | |
| `kubectl` | parent | |
| `argocd` | parent | |

| Secret | From |
|---|---|
| `CLOUDSDK_AUTH_ACCESS_TOKEN` | local → parent (`from = "parent"`) |
| `GH_TOKEN` | local |
| `ARGOCD_AUTH_TOKEN` | parent |

`filesystem.read` includes `~/work/platform/schemas`: the parent's relative
path resolves against `~/work`, not against the project.

The repo's `gcloud` could not have used the parent's token on its own. A
repo item may reference only labels its own file declares, so a cloned repo
cannot point a tool at your work credentials just by naming them. The link
is the one `from = "parent"` line, in a file you approve.

## What `~/work/oss-fork` gets

Only its own `gh`. With `inherit = false`, `~/work/airlock.toml` is not read
for this project at all.

## First run

```
$ cd ~/work/api && airlock run --profile claude
~/work/airlock.toml is not trusted yet. Contents:
    cascade = true   # also applies to projects in subdirectories
    …
Trust this version and continue? [y/N] y
trusted ~/work/airlock.toml

~/work/api/airlock.toml is not trusted yet. Contents:
    …
```

The parent file is approved once. The next repo under `~/work` asks only
about its own files. Editing `~/work/airlock.toml` later asks again, with a
diff, at the next session start in any repo below it. `airlock trust` names
the running sessions, in any of those repos, that still use the previous
version.
