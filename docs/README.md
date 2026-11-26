# Faramir documentation

For the broker's purpose, security boundary, and quick start, see the [project README](../README.md).

## Install and operate

- [Installation](installing.md) covers `init` flags, repeat installs, and configuration directory requirements.
- [Configuration](configuration.md) lists settings, their flags, and `--check` conditions.
- [Installed layout](layout.md) lists the paths Faramir creates, with their modes and owners.
- [Operations](operating.md) covers install checks, operator commands, and adding an age recipient. See also the [rules a command does not state](operating.md#rules-a-command-does-not-state).
- [Coding agents](coding-agents.md) explains enrollment, rule enforcement, and agent-specific behavior.
- [Integrations](integrations.md) covers linked credentials, SSH, Ansible, and other tool recipes.
- [Escalation](escalation.md) explains when and how an operator approves `sudo` for a brokered command.

## Design and reference

- [Design overview](design.md) explains the account boundaries and shell rewrite.
- [Output handling](design/output-handling/redaction-failures.md) describes the rule for redaction failures and where it is enforced.
- [Redaction](redaction.md) documents the matching pipeline and its coverage.
- [Protocol](protocol.md) specifies the broker socket messages.
