# Airlock v2 — developer questions

Questions a developer is likely to ask when they first meet Airlock v2.
They mix "how do I use this" with "why is it built this way". Answers
belong in the README, SKILL.md and the
[design](airlock-v2-design.md) and [UX](airlock-v2-ux.md) docs. This list
is for checking that those docs cover them.

## Getting started

1. What is the smallest setup that lets my agent run `gh` without ever
   seeing my GitHub token?
2. Do I need to start the daemon before `airlock run`, and how do I know
   whether one is running?
3. Where do my secrets come from: the environment, a command like `op read`,
   or somewhere else? Which should I choose?
4. Why does `airlock run` show me my own `airlock.toml` and ask me to trust
   it, when I just wrote the file myself?
5. How do I use Airlock in a repository whose team has not adopted it?

## Sessions

6. What exactly is a session, and how is it different from the daemon?
7. Why does every agent need its own session instead of just connecting to
   the daemon's socket?
8. How do I run two agents in the same project at the same time, and do they
   share secrets?
9. What happens to a running agent's session when I close the terminal,
   restart the daemon, or upgrade Airlock?
10. How do I give a session to an IDE extension that I cannot start through
    `airlock run`?
11. Why does a session end when the harness exits, and why does a
    `session start` session expire after 12 hours?

## Config layers and trust

12. What goes in `airlock.toml`, what goes in `airlock.local.toml`, and
    what goes in `~/.config/airlock/airlock.toml`?
13. Why can't my global 1Password binding for `GH_TOKEN` serve the repo's
    `GH_TOKEN` automatically, without a line in `airlock.local.toml`?
14. Why is a tool defined in two layers an error instead of the higher layer
    winning?
15. Why does approval cover the whole file byte for byte, so that even a
    comment change has to be approved again?
16. Why doesn't the global config file need approval when the repo and
    local files do?
17. My agent added a tool to `airlock.toml`. How does it get to use that
    tool without me restarting it and losing its context?
18. How do I approve config in CI or a setup script where nobody can answer
    a prompt?
19. How do I see the merged config, and which layer each setting came from?

## Sandboxing and security

20. Why does the agent get a different sandbox from the tools it runs?
21. Why do the socket, PID file and CA certificate live outside the project
    directory now?
22. What stops the agent from approving its own config change, or from
    pointing Airlock at a trust store it wrote itself?
23. I already run Claude Code with its own sandbox. What do I give up with
    `airlock run --no-sandbox`, and what does that sandbox have to deny?
24. Why does Airlock filter my `PATH` and refuse a tool binary that lives
    inside the project?
25. Since one daemon now holds every project's secrets, what keeps one
    project's session from reaching another project's secrets?
26. What does Airlock deliberately *not* protect against, such as git hooks
    or build scripts that the agent wrote and I later run?

## Agent integration and day-to-day use

27. How does my agent find out which tools it must run through
    `airlock exec`, if it never reads SKILL.md?
28. What does `airlock agent check` actually test, and why can't a passing
    result prove that the agent is contained?
29. Why does `airlock exec` exit with 125, 126 or 127 for some failures
    instead of 1?
30. Why are `airlock status`, `airlock trust` and `airlock session` missing
    from `airlock --help` when I run it inside the sandbox?
