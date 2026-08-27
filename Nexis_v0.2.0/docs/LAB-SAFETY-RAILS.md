# Nexis Lab Safety Rails

Nexis lab workflows are deliberately scope-bound.

## Policy

- Lab targets must be explicitly registered in the Nexis allowlist.
- IP targets are limited to private or loopback addresses for the built-in lab policy.
- Privileged lab authorization requires an administrator password configured locally.
- Authorization sessions expire automatically.
- Operator confirmation remains required for privileged actions.
- Concurrency is bounded to avoid runaway workloads.
- Nexis does not attempt to modify external operating-system, router, ISP, cloud, browser, or third-party logs.
- The guardrail module does not execute exploits, credential attacks, or post-exploitation actions itself; it only provides authorization state for future approved lab tooling.

## Commands planned for the operator console

`lab policy`

`lab targets`

`lab register <target> <label>`

`lab authorize <target>`

`lab session`

`lab revoke`

Privileged workflows should also include an explicit target confirmation before any intrusive action.
