# Contributing

Thanks for helping improve LuCI-RedTeam.

## Before You Start

- Use this project only for lawful, authorized security assessment work.
- Keep changes focused. Small, reviewable pull requests are much easier to merge safely.
- For anything security-sensitive or behavior-changing, include tests with your patch.

## Development Setup

```bash
python -m pip install -e .[dev]
```

Run the test suite:

```bash
pytest
```

## Contribution Guidelines

- Open an issue before beginning large features or broad refactors.
- Match the existing code style and module layout where practical.
- Add or update tests when changing CLI behavior, check registration, scan orchestration, or output formats.
- Avoid unrelated cleanup in the same pull request.
- Keep documentation in sync with behavior and command-line options.

## Pull Requests

Please include:

- A clear summary of what changed
- Why the change is needed
- Notes about testing performed
- Any security or compatibility considerations reviewers should know about

## Security-Related Contributions

If your finding affects the safety of users, the correctness of vulnerability detection, or a potential vulnerability in the tool itself, please follow [SECURITY.md](SECURITY.md) instead of opening a detailed public issue first.

## Community Expectations

By participating in this project, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
