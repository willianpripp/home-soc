"""Enforces the contract: a rule without a test does not ship.

Checked in both directions. Every rules/*.sql needs a matching
tests/test_rule_<stem>.py, or a broken or untested rule could sit in the repo
looking exactly as trustworthy as the ones that are actually proven. And every
tests/test_rule_*.py needs a rule file it is still testing, or a test for a
rule that got deleted or renamed just sits there as dead weight, passing
against nothing.
"""
from __future__ import annotations

import pathlib

RULES_DIR = pathlib.Path(__file__).resolve().parent.parent / "rules"
TESTS_DIR = pathlib.Path(__file__).resolve().parent


def _rule_stems() -> set[str]:
    return {p.stem for p in RULES_DIR.glob("*.sql")}


def _tested_stems() -> set[str]:
    prefix = "test_rule_"
    return {p.stem[len(prefix):] for p in TESTS_DIR.glob(f"{prefix}*.py")}


def test_every_rule_has_a_matching_test_file():
    missing = []
    for stem in sorted(_rule_stems()):
        expected = TESTS_DIR / f"test_rule_{stem}.py"
        if not expected.exists():
            missing.append((stem, expected))

    if missing:
        lines = [
            f"  rules/{stem}.sql has no test at {path.relative_to(TESTS_DIR.parent)}"
            for stem, path in missing
        ]
        raise AssertionError(
            "a rule without a test does not ship. Add the missing test file(s):\n"
            + "\n".join(lines)
        )


def test_every_rule_test_points_at_an_existing_rule():
    dangling = []
    for stem in sorted(_tested_stems()):
        rule_path = RULES_DIR / f"{stem}.sql"
        if not rule_path.exists():
            dangling.append((stem, rule_path))

    if dangling:
        lines = [
            f"  tests/test_rule_{stem}.py has no matching {path.relative_to(TESTS_DIR.parent)}"
            for stem, path in dangling
        ]
        raise AssertionError(
            "a test for a deleted rule is dead weight. Remove or retarget the test file(s):\n"
            + "\n".join(lines)
        )
