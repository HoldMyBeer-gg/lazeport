# Contributing to Lazeport

Thank you for your interest in contributing to Lazeport! This document provides guidelines and instructions for contributing.

## Code of Conduct

Be respectful, constructive, and professional in all interactions. We're building this together.

## How to Contribute

### Reporting Issues

Before creating an issue:

- Search existing issues to avoid duplicates
- Check if the issue exists in the latest version
- Collect relevant information (OS, versions, error messages, logs)

When creating an issue:

- Use a clear, descriptive title
- Provide steps to reproduce (if applicable)
- Include expected vs. actual behavior
- Add screenshots or error logs if relevant
- Mention your environment (OS, Python version, browser)

### Suggesting Features

Feature requests are welcome! Please:

- Explain the use case and problem it solves
- Describe the proposed solution
- Consider alternatives you've thought about
- Be open to discussion and refinement

### Submitting Pull Requests

#### Before You Start

1. **Fork the repository** and create a branch from `main`
2. **Check existing issues/PRs** to avoid duplicate work
3. **Open an issue first** for significant changes to discuss the approach

#### Development Setup

```bash
# Clone your fork
git clone https://github.com/yourusername/lazeport.git
cd lazeport

# Install dependencies
pip install -r requirements.txt
cd frontend && pnpm install && cd ..

# Run development server
./run.sh  # or run.bat on Windows

# Run tests
./run_tests.sh  # or run_tests.bat on Windows
```

#### Code Quality Standards

**Python:**

- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Format with Black (line length: 100)
- Run tests with pytest
- Add docstrings for public functions/classes

**JavaScript/Vue:**

- Format with Prettier
- Follow Vue 3 composition API patterns
- Use TypeScript types where applicable
- Keep components focused and reusable

**General:**

- Write clear, self-documenting code
- Avoid unnecessary comments; explain "why" not "what"
- Keep functions small and focused
- Test your changes thoroughly

#### Testing Requirements

All PRs must:

- Pass existing tests
- Include tests for new functionality
- Include tests for bug fixes (regression tests)
- Not decrease overall test coverage

Run tests before submitting:

```bash
# Backend tests
pytest

# Frontend unit tests (if applicable)
cd frontend && npm test
```

#### Commit Message Conventions

Use clear, descriptive commit messages:

```
Add validation for CVSS vector string input

- Validate vector format before parsing
- Show error message for invalid vectors
- Add unit tests for edge cases

Fixes #123
```

Format:

- **First line:** Brief summary (50 chars max, imperative mood)
- **Body:** Detailed explanation of what and why (not how)
- **Footer:** Reference issues/PRs (`Fixes #123`, `Relates to #456`)

#### Pull Request Process

1. **Update your branch** with latest `main` before submitting
2. **Ensure all tests pass** locally
3. **Fill out the PR template** completely
4. **Keep PRs focused** - one feature/fix per PR
5. **Respond to feedback** constructively
6. **Be patient** - reviews take time

PR checklist:

- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Comments added for complex logic
- [ ] Documentation updated (if applicable)
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] No new warnings or errors
- [ ] Tested in relevant browsers/environments

## Development Workflow

### Branch Naming

- `feature/short-description` - New features
- `fix/issue-description` - Bug fixes
- `docs/what-changed` - Documentation only
- `refactor/what-changed` - Code refactoring

### Local Development

```bash
# Backend changes: edit Python files, server auto-reloads
# Frontend changes: run separate dev server for hot reload
cd frontend
pnpm run dev  # Runs on port 5173, proxies API to :8000
```

### Database Changes

If modifying the database schema:

1. Update SQLModel models in `app/db/models.py`
2. Create an Alembic migration (if using migrations)
3. Document the change in your PR description
4. Test with fresh database and existing data

### Adding Dependencies

**Python:**

```bash
pip install package-name
pip freeze > requirements.txt
```

**JavaScript:**

```bash
cd frontend
pnpm install --save package-name
```

Document why the dependency is needed in your PR.

## Project Structure

```
lazeport/
├── app/                    # Backend (FastAPI)
│   ├── api/               # API endpoints
│   ├── db/                # Database layer
│   │   ├── models.py      # Database models (SQLModel)
│   │   ├── adapter.py     # Storage adapter protocol
│   │   └── sql_adapter.py # SQL implementation
│   ├── services/          # Business logic
│   └── main.py            # App entry point
├── frontend/              # Frontend (Vue 3)
│   ├── src/
│   │   ├── components/    # Reusable Vue components
│   │   ├── views/         # Page-level components
│   │   ├── i18n/          # Internationalization
│   │   └── App.vue        # Root component
│   └── public/            # Static assets
├── tests/                 # Backend tests (pytest)
├── data/                  # Database and runtime data
└── docs/                  # Additional documentation
```

## Internationalization (i18n)

When adding UI text:

1. **Never hardcode strings** in components
2. Add keys to `frontend/src/i18n/locales/en.json`
3. Use `$t('key.name')` in templates
4. Translations to other locales appreciated but not required

## Security

**Report security vulnerabilities privately:**

- Email: [your-security-email]
- Do NOT open public issues for security bugs
- Allow reasonable time for fixes before disclosure

## Questions?

- **General questions:** Open a GitHub Discussion
- **Bug reports:** Open an issue with the bug template
- **Feature ideas:** Open an issue with the feature request template
- **Development help:** Check existing issues or ask in Discussions

## Recognition

Contributors will be recognized in:

- `CHANGELOG.md` for significant contributions
- GitHub's contributor graph
- Release notes for features/fixes

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make Lazeport better! 🚀
