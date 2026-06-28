<!-- PR TITLE: Use Conventional Commits: <type>(<scope>): <description>
     Types: feat, fix, docs, style, refactor, perf, test, build, ci, chore, revert
     Example: feat(cli): add --json flag to audit command
     See CONTRIBUTING.md for the full specification. -->

<!-- TARGET BRANCH: Feature, fix, and doc branches → `develop`. Hotfixes → `main`.
     See CONTRIBUTING.md for branching strategy. -->

## Summary

<!-- Provide a concise description of the changes in this PR. What problem does it solve? What does it add or change? -->

Closes #<!-- issue number -->

---

## Type of Change

<!-- Check all that apply -->

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] 🚀 New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to change)
- [ ] 🔒 Security fix
- [ ] ♻️ Refactor (no functional changes)
- [ ] 📖 Documentation update
- [ ] 🧪 Tests only
- [ ] 🏗️ Build / CI / dependency update
- [ ] ⚡ Performance improvement
- [ ] 🎨 Style (formatting, no logic change)
- [ ] 🧹 Chore (formatting, renaming, cleanup)

<!-- LABELS: After creating your PR, apply the appropriate GitHub labels.
     Type labels: bug, enhancement, documentation, security, performance, chore
     Area labels: area:cli, area:audit, area:cooldown-engine, area:threat-intelligence, etc.
     See .github/labels.yml for the full taxonomy. -->

---

## Motivation and Context

<!-- Why is this change needed? What problem does it solve?
     If it fixes a bug, describe the root cause. If it adds a feature, describe the use case. -->

---

## Implementation Notes

<!-- Any implementation details, design decisions, or trade-offs worth highlighting for reviewers. -->

---

## Testing

<!-- Describe how you tested your changes. -->

- [ ] I have added tests that cover the changes in this PR
- [ ] All existing tests pass locally (`pytest --cov-fail-under=90`)
- [ ] I have run the e2e gate test locally (`pytest tests/integration/test_smoke_e2e.py --tb=short -q`)
- [ ] I have tested this manually (describe what you did below)

**Manual testing performed:**
<!-- Describe manual test steps taken, commands run, output observed -->

---

## Checklist

- [ ] My code follows the project's style guidelines (passes `ruff check .` and `ruff format --check .`)
- [ ] My code passes type checking (`mypy .`)
- [ ] My changes maintain or improve code coverage (`pytest --cov-fail-under=90`)
- [ ] My CLI changes use the correct exit codes defined in `docs/reference/exit-codes.md`
- [ ] I have updated documentation as needed (README, docstrings, CHANGELOG)
- [ ] I have updated `CHANGELOG.md` with a brief entry under `[Unreleased]`
- [ ] My changes do not introduce new dependencies without discussion
- [ ] Any new dependencies are pinned appropriately in `pyproject.toml`
- [ ] I am aware that the dependency review workflow (`.github/workflows/dependency-review.yml`) runs automatically on PRs
- [ ] I have reviewed my own diff before requesting review

---

## Screenshots / Output

<!-- If this change affects the CLI output, UI, or terminal rendering, please include before/after screenshots or terminal recordings. -->

---

## Breaking Changes

<!-- If this is a breaking change, describe exactly what breaks and what users need to do to migrate.
     Leave this section blank if not applicable. -->

---

## Related Issues / PRs

<!-- Link any related issues, PRs, or external references. -->
