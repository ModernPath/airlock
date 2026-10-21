# A team project, three layers

Three files, three different people writing them, one merged config. See the
main [README](../../README.md#team-and-personal-config) for the general
rules; this is a worked example.

- **[`airlock.toml`](airlock.toml)** — the team's, checked into `acme/app`.
  Declares the tools everyone needs and the secret labels they take, but
  leaves `GH_TOKEN` and `CLOUDFLARE_API_TOKEN` unbound: a PR author doesn't
  know, and shouldn't need to know, how each teammate keeps those
  credentials.
- **[`global.toml`](global.toml)** — one user's `~/.config/airlock/airlock.toml`.
  Binds `GH_TOKEN` to their own 1Password item, adds an `aws` tool and an
  env passthrough they want in every project, and turns on the `rust` kit
  for `airlock run` (isolated mode, the default — see
  [README: Kits](../../README.md#kits)).
- **[`airlock.local.toml`](airlock.local.toml)** — that same user's
  per-project file for `acme/app`. Links the repo's `GH_TOKEN` to their
  global binding with `from = "global"`, binds `CLOUDFLARE_API_TOKEN`
  directly, and adds a `psql` tool nobody else on the team has declared.

## The merged result

What `airlock run` actually registers, with the layer each item came from:

| Item | Value | From |
|---|---|---|
| `timeout` | `120` | repo |
| `secrets.GH_TOKEN` | command `op read op://Private/GitHub/token` | local (`from = "global"`, resolved to the global binding) |
| `secrets.CLOUDFLARE_API_TOKEN` | command `op read op://Private/Cloudflare/token` | local |
| tools | `aws` (global), `gh` (repo), `tofu` (repo), `psql` (local) | — |
| `filesystem.read` | `/opt/homebrew/share` | repo |
| `agent.passthrough_env` | `COLORTERM`, `NO_COLOR` | union (global + repo) |
| `agent.env.LOG_LEVEL` | `"debug"` | local (overrides the repo's `"info"`) |
| `agent.kits` | `rust` | global |

Nobody but this user sees `CLOUDFLARE_API_TOKEN` bound to this 1Password
item, or that `GH_TOKEN` comes from the same place as their other projects'
`GH_TOKEN`. A teammate running the same repo gets the same `gh` and `tofu`
tools, their own bindings for the two labels, and no `psql` unless they
declare it themselves.

## Joining the repo for the first time

The team's `airlock.toml` declares labels and leaves the bindings to each
user. A user whose global config already binds `GH_TOKEN` for every project
sees:

```
$ git clone git@github.com:acme/app ~/src/app && cd ~/src/app
$ airlock run --profile claude
error: 2 secrets in ~/src/app/airlock.toml have no source:
  GH_TOKEN              GitHub token with read access to acme/app
  CLOUDFLARE_API_TOKEN  Cloudflare token, Zone:Read on acme.dev
the project leaves these to you. `airlock init --local` creates
airlock.local.toml with a stub for each.

$ airlock init --local
created ~/src/app/airlock.local.toml
  GH_TOKEN              from = "global" (your global config binds it)
  CLOUDFLARE_API_TOKEN  not bound: edit airlock.local.toml
airlock.local.toml is ignored by git
```

The generated file looks like this before editing:

```toml
# Your bindings for this project. Keep it out of git.
# Run `airlock config` to see the merged result.

# GitHub token with read access to acme/app
[secrets.GH_TOKEN]
from = "global"

# Cloudflare token, Zone:Read on acme.dev
# Uncomment one:
# [secrets.CLOUDFLARE_API_TOKEN]
# source  = "command"
# command = ["op", "read", "op://Private/Cloudflare/token"]
#
# [secrets.CLOUDFLARE_API_TOKEN]
# source = "env"        # read from the environment of `airlock run`
```

If `airlock.local.toml` isn't ignored yet, the last line instead reads:

```
warning: airlock.local.toml is not ignored by git. To ignore it in every repo:
         echo airlock.local.toml >> ~/.config/git/ignore
```

After filling in the Cloudflare binding (as in [`airlock.local.toml`](airlock.local.toml) here):

```
$ airlock run --profile claude
~/src/app/airlock.toml is not trusted yet. Contents:
    …
Trust this version and continue? [y/N] y
trusted ~/src/app/airlock.toml

~/src/app/airlock.local.toml is not trusted yet. Contents:

    [secrets.GH_TOKEN]
    from = "global"       # → global: command op read op://Private/GitHub/token
    …

Trust this version and continue? [y/N] y
trusted ~/src/app/airlock.local.toml
```

Each file is approved on its own. Declining either stops the run, exit
status 125. The `# →` annotation shows what `from = "global"` resolves to
right now; it isn't part of the file, and isn't part of what gets approved —
a later change to the global binding needs no new approval, since the
global file is the user's own.
