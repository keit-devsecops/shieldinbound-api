# Contributing to ShieldInbound

Thanks for your interest in contributing. This project is a portfolio
simulation of a zero-trust control plane, and contributions that improve
the security heuristics, documentation, or Azure deployment workflow are
welcome.

## Workflow

1. Fork the repository.
2. Create a feature branch off `dev`: `git checkout -b feature/your-feature dev`
3. Make your changes with clear, focused commits.
4. Push your branch and open a Pull Request **targeting the `dev` branch** (not `main`).
5. The PR will be reviewed before merging.

## Branch Structure

- `main` — stable, deployed code. Protected. No direct commits.
- `dev` — integration branch for upcoming changes. PRs target this.
- `feature/*` — short-lived branches for individual changes.

## Guidelines

- Keep guardrail pattern additions tested against both attack and clean inputs to avoid false positives.
- Match the existing code style.
- Update the README if you change behavior a user would notice.

## Reporting Issues

Open an issue describing the problem, expected behavior, and steps to reproduce.
For security pattern gaps, include the input string that was mis-classified.
