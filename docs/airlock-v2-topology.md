# Airlock v2 — topology and the central daemon

**Status:** proposal, companion to [airlock-v2-design.md](airlock-v2-design.md).
The design doc describes one daemon per user whose sessions resolve their
own secrets (option B below). This document records the longer direction, a
central Airlock daemon, what that direction requires, compares the local
topologies against it, and proposes what v2 should change so that it stays
on the path. Nothing here is folded into the design yet.

## The direction

Airlock should be able to run as a central service, not only as a daemon on
the developer's machine:

- A daemon reachable over the network, on a central server.
- Some secrets shared and declared on the daemon's side, resolved by the
  daemon with its own credentials. Others local, resolved on the developer's
  machine, as today.
- Some tools run centrally, next to the shared secrets. Others run locally,
  against the working tree.

The agent keeps one entry point. The local daemon serves local tools and
forwards the rest:

```
developer's machine                             central server
┌───────────────────────────────┐               ┌────────────────────────────────┐
│ agent, sandboxed              │               │ airlock server                 │
│   airlock exec -- gh pr list  │               │   admin-owned config:          │
│   airlock exec -- kubectl …   │               │     shared secrets, policy,    │
│              │                │ TLS, identity │     central tools, proxies     │
│              ▼                │               │                                │
│ local daemon                  ├──────────────►│ runs kubectl in its sandbox,   │
│   project config, approval    │ forwarded     │ streams redacted output back   │
│   local secrets (1Password)   │ exec; secret  │                                │
│   runs gh in its sandbox      │ fetch         │ vends GH_TOKEN to the local    │
│                               │◄──────────────┤ daemon for the local gh        │
└───────────────────────────────┘               └────────────────────────────────┘
```

## What it requires

Four things. v2 provides none of them, which is fine as long as v2 does not
build in their way.

### Identity and policy

Today the daemon trusts whoever reaches the socket as the user, because the
socket is mode 0700 and the agent runs as the same uid. A server has many
users and cannot trust a socket. It needs:

- **Authentication** of each client: mTLS client certificates, an OIDC
  token, or an SSH certificate.
- **Authorization**: which identity may use which tools and which secrets,
  for which project.
- **Audit**: every exec attributed to an identity, not to a session id on
  one machine.

The v2 mechanisms that stand in for this locally are the admin token, the
socket mode, the peer uid, and the binding of a session token to a process
tree. All of them are host-local by construction. The server replaces them;
it does not extend them.

### Two kinds of secrets

| Kind | Declared | Resolved by | Shared |
|---|---|---|---|
| daemon-side | in the daemon's own config: the global layer locally, the admin's config centrally | the daemon, with its own credentials, once; refreshed by the daemon | across every session that may reference the label |
| client-side | in the project layers | the launcher, in the user's terminal, per session | no |

v2 as designed has only client-side secrets. Even a global binding is copied
into the session by `from = "global"` and resolved by the launcher, so two
sessions in one project prompt 1Password twice ([Scope](airlock-v2-design.md#scope)),
and the daemon's own environment is declared irrelevant
([Lifecycle](airlock-v2-design.md#lifecycle)). A central server is the
opposite: its secrets are daemon-side by definition, and it has no terminal
to prompt in. The distinction has to exist in the local daemon first, or the
server is a different program.

### Tool placement

A tool runs where its working tree and its secret are, and the two pull in
different directions:

| Tool | Secret | Runs | Does the secret reach the developer's machine? |
|---|---|---|---|
| `gh` with a shared token | central | locally: it needs the checkout | yes: the server vends it to the local daemon, which injects it into the sandboxed `gh` and redacts the output, as today |
| `curl` as a proxy tool against an API | central | locally; the credential is attached on the server | no |
| `kubectl get pods` with a shared kubeconfig | central | centrally: it needs no checkout | no |
| `tofu plan` | central or local | locally: it needs the working tree | yes |

So "central secret, local CLI" means vending the secret to the laptop. The
laptop's daemon holds it in memory, as it holds every secret today. What the
server adds is policy, rotation and audit, not a secret that never leaves
the server. Only proxy tools and centrally run tools keep the secret off the
developer's machine. The first central cases are therefore proxy tools and
project-less CLIs. Tools that need the working tree stay local; running
them centrally is a remote development problem and out of scope.

### Transport

[Transport](airlock-v2-design.md#transport) in the design doc already keeps
a TCP transport possible: `AIRLOCK_ADDR` is a URI, authorization starts
from a token, and requests carry no file descriptors. A server also needs
TLS on the listener and tokens bound to the client's TLS identity
([F11](airlock-v2-design.md#follow-ups)). Forwarding adds one constraint: an
`Exec` request must be meaningful on another host, so it carries the tool
name, the arguments, the stdin stream and the working directory relative to
the project root, and nothing host-specific beyond that.

## Local topologies compared against the direction

| Option | Shared secrets, one prompt | A crash or a bug reaches | Authentication | What transfers to a central daemon | v2 size |
|---|---|---|---|---|---|
| **A. One daemon per session.** Today's embedded daemon (`run_embedded` in [src/daemon.rs](../src/daemon.rs)), with its socket in the runtime dir and a token in the agent's environment; `session start` is the same daemon detached with a TTL | no: each session resolves its own | that session | the token; the daemon is the launcher, so a peer must descend from it | the protocol shape | small |
| **B. One daemon per user, sessions, launcher-resolved secrets.** The design doc as written | no: sessions resolve their own by design | every session on the machine | admin token, socket mode, PID-tree binding; all host-local | the protocol shape and the multi-session skeleton | large |
| **C. One daemon per user with a daemon-side layer.** As B, but the global layer belongs to the daemon: it resolves and refreshes those secrets once and serves them to every session; sessions carry the project layers and client-side secrets | yes: a global secret is resolved once per daemon | every session on the machine | as B | the protocol, the skeleton, and the daemon-side/client-side split the server needs | B, plus daemon-side config |
| **D. A central server, with the local daemon as the agent's single entry point and relay** | yes, org-wide | the server: every user | TLS identity, policy, audit | is the target | a design of its own |

A is not a dead end: a central server is a separate role that any local
daemon can use as a secret source and a remote executor. But A and B are
equally far from D, since what they share with it is the protocol shape,
and B pays for a multi-session skeleton whose authentication D throws away.
C is the one option that builds something D needs and the others do not.

## What v2 should change

If D is the direction, these changes keep v2 on the path. Each names the
design doc sections it touches.

1. **Choose C over B.** The global config becomes the daemon's: the daemon
   reads it at start, resolves its secrets once, refreshes them, and serves
   them to every session that references them. The launcher still resolves
   project secrets in the user's terminal. `Register` carries client-side
   secret values and the list of daemon-side labels the session may use;
   the daemon checks the list against the approved config and records it on
   the session.
   - *Touches:* [Registering a session](airlock-v2-design.md#registering-a-session)
     (steps 2 and 5), [Scope](airlock-v2-design.md#scope) (the second
     prompt disappears, which answers G10),
     [Lifecycle](airlock-v2-design.md#lifecycle) ("the daemon's own
     environment does not matter" no longer holds for daemon-side secrets),
     [Session isolation](airlock-v2-design.md#session-isolation) (the
     daemon-side store is shared by design; a session reaches it only
     through the label list recorded at `Register`), and the Decisions rows
     "Daemon topology" and "Session state".
   - *Trade:* the daemon's environment matters again for `op` and `gcloud`,
     as it did in v1. An automatically started daemon inherits the
     environment of the launcher that started it. A service daemon has the
     login environment, not the shell's. Both tools work from per-user
     sockets and config directories, so this is a documentation item.

2. **Name the host-local authentication for what it is.** Group the admin
   token, the socket mode, the peer uid and the PID-tree binding under one
   heading, "Unix transport authentication", and state that a network
   transport replaces them. Nothing else in the design should depend on
   them.
   - *Touches:* [Admin credential](airlock-v2-design.md#admin-credential),
     [Token binding](airlock-v2-design.md#token-binding),
     [Transport](airlock-v2-design.md#transport), F11.

3. **Bind labels by the secret's owner, not by a project line.** A
   daemon-side secret is bound to a project label when its owner allows it:
   the user, by approving the repo file's label requests, which the prompt
   annotates with what each would resolve to; the admin, by policy, on a
   central server. `from = "global"` is a per-project ceremony that a server
   would never have, and `init --local` already writes it automatically for
   every label the global layer binds, so it is not the explicit opt-in B3
   asked for.
   - *Touches:* [Secret labels across layers](airlock-v2-design.md#secret-labels-across-layers),
     [Unapproved files at session start](airlock-v2-design.md#unapproved-files-at-session-start)
     (the annotation), B3, `init --local`.

4. **Decide the first remote case and add placement.** A tool gets an
   optional placement: `run = "local"` by default, or the name of a daemon
   the local daemon forwards to. Proxy tools and project-less CLIs are the
   first central cases. The local daemon is the agent's only address; it
   forwards an `Exec` and streams the result back. v2 implements no
   forwarding, but `Exec` is shaped so that a relay can forward it.
   - *Touches:* [Transport](airlock-v2-design.md#transport), F11, the
     `[tools.<name>]` schema.

5. **Give the project an identity that is not a path.** The trust store
   keys a project by the hash of its canonical root, which is host-local. A
   central policy says "this identity may use this secret for this
   project", and needs a project identity that two machines agree on: a
   declared name in `airlock.toml`, or the git remote. v2 can keep the path
   hash for approval and add the declared name when placement lands, but
   the schema should leave room for it.
   - *Touches:* [Trust store](airlock-v2-design.md#trust-store),
     [Scope](airlock-v2-design.md#scope).

## What v2 must keep possible

The constraints a central daemon puts on v2, in one place:

- `AIRLOCK_ADDR` stays a URI; authorization starts from the session token;
  requests carry no file descriptors or other host-local handles. (Already
  in the design.)
- The protocol distinguishes daemon-side from client-side secrets. `Exec`
  never carries a secret value. `List` reports where each secret comes
  from.
- `Exec` carries the working directory relative to the project root, so it
  can be forwarded.
- Session scoping is by project, and the project will need a
  host-independent identity.
- The daemon owns a config layer of its own. Locally that is the global
  file; centrally it is the admin's.

The implementation-level form of these constraints, for the design as it
stands, is in
[airlock-v2-technical-guidance.md](airlock-v2-technical-guidance.md).

## Open questions

- **Relay or two sessions.** Either the local daemon forwards central
  tools, or the agent holds a local and a central session. The relay keeps
  one address and one token in the agent's environment, and lets the local
  daemon log every exec. This document assumes the relay.
- **Daemon-side sources on a server.** `source = "command"` works on a
  server as it does locally. Vault and cloud secret managers may deserve
  first-class sources, which is the same question as the multi-value
  sources in [TODO.md](../TODO.md).
- **Where the audit log lives.** Locally the ring buffer; centrally
  something durable, attributed to an identity.
- **The trust model for central config.** The admin's config is trusted as
  the user's global file is trusted today: by who can write it. Whether the
  user also approves what the server offers a project, or only the server's
  policy decides, is open.
