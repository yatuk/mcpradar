# Contributing to MCPRadar

Thanks for contributing! Here's how to get started.

## Quick Links

- [Adding a Detection Rule](docs/contributing.md)
- [Architecture Overview](docs/architecture.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

## Development Setup

```bash
git clone https://github.com/yatuk/mcpradar
cd mcpradar
uv sync
```

## Before Submitting

- [ ] `ruff check .` passes
- [ ] `ruff format --check .` passes
- [ ] `mypy src/` passes
- [ ] `pytest` passes
- [ ] New features include tests
- [ ] Documentation updated if needed

## Commit Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` — new feature or detection rule
- `fix:` — bug fix
- `docs:` — documentation
- `test:` — tests
- `refactor:` — code restructuring
- `chore:` — CI, dependencies, etc.

## Pull Request Process

1. Fork the repo
2. Create a feature branch
3. Make your changes
4. Run the quality gates
5. Submit a PR against `main`
6. CI must pass

## License

By contributing, you agree that your contributions will be licensed 
under the MIT License.
