# Airlock v2 — technical guidance

**Status:** proposal, companion to [airlock-v2-design.md](airlock-v2-design.md)
and [airlock-v2-topology.md](airlock-v2-topology.md). The design doc decides
what v2 does: one daemon per user with sessions that resolve their own
secrets. The topology doc records the direction after that: a central
daemon. This document is for whoever implements v2.

It separates two things:

- **Shapes to use now.** Ways of writing the protocol and the data model
  that v2 needs anyway, or that cost nothing extra, and that let the
  central daemon add variants instead of replacing types.
- **Additions postponed to v2.1 or later.** Things the central daemon will
  need and v2 would not use. Each has a note on why adding it later is
  safe. v2 implements nothing it does not use.

Two facts make the first list worth following in v2 rather than later:

- The daemon starts on demand and outlives the binary that started it, so
  the launcher-to-daemon link is a compatibility boundary from the first
  release, before any network exists.
- The design already keeps a network transport possible
  ([Transport](airlock-v2-design.md#transport)). The shapes below are what
  that promise costs in concrete types, and the answer is: almost nothing.

## Shapes to use now

### Two message families

Keep admin requests (`Register`, `Reload`, session list, revoke, renew,
`Logs`, stop) and session requests (`Exec`, `Stdin`, `StdinEof`, `List`,
`Check`) as two enums on the wire and in code, on top of the existing
client-versus-daemon split. The local daemon gates the admin family on the
admin token, and a server would gate it on a different identity. With one
enum and a token field that gate is a check in every handler; with two it
is one match at the top of the connection. v2 needs the gate either way.

### A principal on every request

Every request carries `auth`, a tagged value: `{"kind": "session",
"token": …}` or `{"kind": "admin", "token": …}`. The Unix listener resolves
it to one `Principal` before any handler runs, applying its own checks
there: the peer uid, and for a session token the process-tree binding.
Handlers receive the principal and the session it resolves to, never the
raw token. v2 needs this lookup anyway; putting the transport checks in the
listener is what keeps the handlers unchanged when a TLS listener builds a
principal from a client certificate instead.

### One protocol version, separate from the binary version

The version handshake the design requires (U9) carries a protocol version,
not the binary version. The protocol version covers the `Register` payload
too: a change to the config wire types bumps it. Two binaries with the same
protocol version interoperate; the launcher's "incompatible daemon" error
compares protocol versions.

### Config on the wire fails closed

`Register` ships the merged config. Reuse the TOML raw types, which already
deny unknown fields ([src/config.rs](../src/config.rs)), so a daemon that
receives a field it does not know rejects the request instead of ignoring
it. An ignored field is usually a policy the launcher expected enforced.
The protocol version catches the mismatch first; this is the backstop.

### Error kinds as an enum

`Error { kind, message }` with `kind` an enum: `NoSession`, `SessionEnded`,
`SessionExpired`, `OutsideProcessTree`, `DaemonUnreachable`, `UnknownTool`,
`BinaryUnusable`, `StaleSecret`, `OutsideRoot`, `Malformed`. The client maps
kinds to the exit codes 125, 126 and 127 in one table. v2 needs the mapping;
an enum is the only way to do it that a relay can later pass through
unchanged.

### The session stores compiled policy

At `Register` the daemon compiles the merged config into a `SessionPolicy`:
per-tool sandbox policy, environment template with secret references,
proxy routes, timeouts, and the secret store. Handlers read the compiled
form only. `Reload` builds a new one and swaps the pointer, which is the
"one step" the design requires. A server-side layer later compiles into the
same form.

### Admin frames have their own size limit

The NDJSON line cap of 1 MiB exists to bound memory from an untrusted
client. `Register` carries a config that may itself be 1 MiB, plus secrets,
an environment snapshot and a filtered `PATH`, so it needs a larger cap or
a split into several frames. Admin requests come from a trusted launcher
and are bounded by the config cap, so a separate limit for that family is
sound. Decide it in v2; otherwise `Register` fails only on large configs.

### Log entries carry the session id

The design logs every `exec` with its session id, and `daemon logs
--session` filters on it. Give the entry a session id field rather than
formatting the id into the message. Nothing more.

### `Exec` stays free of host-specific fields

`Exec { tool, args, cwd }` carries nothing that names the daemon's host
beyond the working directory. Keep it that way as fields are added. Where a
reply must name a host path, as the `Check` reply does for the anchor
paths, make that section optional, so a reply without it is well formed.

## Postponed to v2.1 or later

| Addition | What it would add | Why v2 does not need it | Why later is safe |
|---|---|---|---|
| Capability list in the handshake | `capabilities: ["admin", "session", …]` so a launcher can tell what a daemon does | There is one transport and one daemon kind | An added field, with a protocol version bump |
| Secret origin | `origin: Client \| Daemon` per label, and `secret_refs: [label]` in `Register` | Every v2 secret is resolved by the launcher | Both are added fields; `Register` without them means "all client-side" |
| `Exec.cwd` relative to the project root | Forwardable working directory | Nothing forwards in v2 | The local daemon is the relay and knows its own root, so it can rewrite an absolute path when forwarding lands |
| Binding as an enum | `ProcessTree \| TlsIdentity` on the session | One listener, one binding | A struct becomes a one-variant enum in a local refactor |
| Project `name` in the repo file | A host-independent identity for a central policy | v2 scopes by the root hash and has no policy to key on | An optional field. Approval is byte-based, so files without it are untouched |
| Structured audit records | Records with principal, tool, decision and exit status | The ring buffer with a session id field serves `daemon logs` | The record replaces a string in one place |
| Layer `owner` | `User \| Team` on each layer, for an admin-owned layer | The layer kind implies the owner in v2 | An added field on the layer record |
| Reserved names `run` and `[daemons]` | Placement and named remote daemons | Unknown fields already fail config validation, so a v2 config cannot use them silently | Define them when they land |

Items the design doc already defers, and that this lens would keep
deferred, are listed in its [Planned for v2.1](airlock-v2-design.md#planned-for-v21)
section.

## Unix-transport only

These are right for v2 and are replaced, not extended, by a network
transport. Keep them behind the listener so that nothing else depends on
them:

- the admin token file and the socket mode,
- the lease on the `Register` connection,
- the runtime directory from `confstr` and `/run/user/<uid>`,
- the trust store keyed by the root hash,
- the process-tree binding.

Keep the last-pass global redactor as a daemon property rather than a
session property. It is the per-hop redaction a relay needs: each daemon
redacts what it knows before output leaves it.

## Sketch

The v2 shapes together. Names are illustrative.

```rust
enum Principal { Admin, Session(Arc<Session>) }

enum AdminRequest { Register(RegisterRequest), Reload(..), ListSessions, Revoke(..), Renew(..), Logs(..), Stop }
enum SessionRequest { Exec { tool, args, cwd }, Stdin { data }, StdinEof, List, Check }

struct RegisterRequest {
    root: PathBuf,
    layers: Vec<Layer>,                // kind, path, approved, hash
    config: RawConfig,                 // the TOML raw types; deny_unknown_fields
    secrets: Vec<(Label, Secret<String>)>,
    env_snapshot: Vec<(String, String)>,
    path: Vec<PathBuf>,
    name: String,
    sandbox: SandboxKind,
}

struct Session {
    id: SessionId,
    token: Secret<Token>,
    root: PathBuf,
    policy: ArcSwap<SessionPolicy>,    // compiled; Reload swaps it
    binding: ProcessTree,              // anchor pid and start time
    ends: Ends,                        // Lease | Ttl
    execs: AtomicU64,
}

enum ErrorKind { NoSession, SessionEnded, SessionExpired, OutsideProcessTree, DaemonUnreachable,
                 UnknownTool, BinaryUnusable, StaleSecret, OutsideRoot, Malformed }
```
