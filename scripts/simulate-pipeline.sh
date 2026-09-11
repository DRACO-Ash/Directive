#!/bin/sh
# Run the platform's test stage against the built PACKAGE, not against the repository.
#
# The distinction is the whole point. The repository's loop installs both requirement
# files and runs from a tree where every file exists. The platform unzips the package
# into a fresh container, installs ONE file, and runs pytest from there. A green loop
# says nothing about that, which is how a package that has never been unzipped reaches
# an upload and fails in seconds with eight later stages skipped.
#
# Stage 5 of the platform pipeline is `pip install -r requirements.txt` then pytest.
# That is the command run below, verbatim, with no second requirements file, because
# adding one is what hides the failure this script exists to find.
set -eu

ROOT="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT"

# The package to test: the argument, or whatever the builder last wrote. Reading the
# builder's own record beats picking the newest file by modification time, which meant
# parsing `ls` output and could pick the wrong one of two packages built from different
# commits.
PKG="${1:-}"
FROM_POINTER=no
if [ -z "$PKG" ] && [ -f dist/latest ]; then
  PKG="$(cat dist/latest)"
  FROM_POINTER=yes
fi

# The pointer is unauthenticated input: it is a file in `dist/`, and anything that can write
# there can name a different archive. Matching only the filename accepted a package from any
# directory, so the builder records the artefact's SHA-256 beside the pointer and it is
# re-checked here. A mismatch means the bytes changed under the name.
if [ "$FROM_POINTER" = yes ]; then
  # A MISSING digest is a refusal, not a skip. Guarding on `[ -f dist/latest.sha256 ]` let
  # the same actor the check exists to stop remove the control with `rm`: repoint
  # `dist/latest` at a foreign archive, delete the digest, and the simulation unpacked it.
  if [ ! -f dist/latest.sha256 ]; then
    echo "FAIL: dist/latest.sha256 is missing, so the pointer cannot be trusted."
    echo "Run scripts/build-package.sh, or pass the package explicitly to test it anyway."
    exit 1
  fi
  if [ "$(sha256sum "$PKG" | cut -d' ' -f1)" != "$(cat dist/latest.sha256)" ]; then
    echo "FAIL: $PKG does not match the digest the builder recorded for it."
    echo "Rebuild, or pass the package explicitly to test it anyway."
    exit 1
  fi
fi
if [ -z "$PKG" ] || [ ! -f "$PKG" ]; then
  echo "FAIL: no package at '${PKG:-dist/latest}'. Run scripts/build-package.sh first."
  exit 1
fi

# A package built from a different tree tests the wrong thing and reports PASS for it,
# which is the one answer this script must never give. Checked only when the package came
# from the pointer: an explicit argument is a deliberate choice to test that file.
#
# The match is on the FILENAME the builder writes, not anywhere in the path. `*$HEAD_SHORT*`
# accepted `dist/3a0661f/comply-ops-2.2-20260101-deadbee.zip` because the commit appeared in
# a directory name, which is looser than the check reads.
#
# The commit stamp is NOT sufficient on its own, and saying otherwise was an over-claim
# this file made about itself. It matches the commit the package was BUILT at, and says
# nothing about what the tree holds NOW: build clean, edit a source file, run from the
# pointer, and the stale package sails through. Demonstrated with the register state
# vocabulary check disabled in the tree and SIMULATION: PASS returned anyway.
#
# So the tree is checked at simulation time as well, which is a superset of the stamp: any
# difference between the package and the tree under test, whenever it appeared, shows up as
# a dirty worktree here. The stamp stays because it marks the artefact itself, so a package
# file on disk declares its own provenance.
if [ "$FROM_POINTER" = yes ]; then
  HEAD_SHORT=nogit
  if command -v git >/dev/null 2>&1; then
    HEAD_SHORT="$(git rev-parse --short HEAD 2>/dev/null || echo nogit)"
  fi
  if [ "$HEAD_SHORT" = nogit ]; then
    # Either git is absent or this is not a repository. Both leave the package unchecked,
    # and a `nogit` stamp would otherwise match a `nogit` package from any tree at any time,
    # which is a tautology rather than a check.
    echo "SKIPPED: no commit is resolvable, so the package was NOT checked against the tree."
    echo "Compensating control: none here. Pass the package explicitly to be sure of it."
  else
    case "${PKG##*/}" in
      comply-ops-*-"$HEAD_SHORT".zip) ;;
      comply-ops-*-"$HEAD_SHORT"-dirty.zip)
        echo "FAIL: ${PKG##*/} was built from a dirty tree, so it may already be stale."
        echo "Commit, rebuild, or pass the package explicitly to test it anyway."
        exit 1
        ;;
      *)
        echo "FAIL: $PKG was not built from the current commit ($HEAD_SHORT)."
        echo "Run scripts/build-package.sh, or pass the package explicitly to test it anyway."
        exit 1
        ;;
    esac
    # A skip bit makes a modified file invisible to `git status`, so the guard below reads a
    # clean tree and the stale package sails through. `git ls-files -v` lower-cases the tag
    # for `assume-unchanged` and reports `S` for `skip-worktree`, so `^[a-z]` caught the
    # first and silently missed the second while the message claimed both. Demonstrated with
    # a security control gutted in the tree and SIMULATION: PASS returned anyway.
    if git ls-files -v | grep -qE '^[a-zS]'; then
      echo "FAIL: a tracked path carries an assume-unchanged or skip-worktree bit,"
      echo "      so the tree cannot be compared. Clear it with git update-index --no-assume-unchanged."
      exit 1
    fi
    if [ -n "$(git status --porcelain)" ]; then
      echo "FAIL: the working tree has changed, so $PKG no longer represents it."
      echo "Rebuild, or pass the package explicitly to test it anyway."
      exit 1
    fi
  fi
fi

# Every step from here to the `cd` is an EXPLICIT refusal rather than a reliance on
# `set -e`, and the reason is what the fall-through DOES rather than tidiness. If the work
# directory is never created, or never entered, the current directory is still the
# REPOSITORY: a tree where every file exists, the lockfile installs and the whole suite
# passes. The script would then print SIMULATION: PASS having tested the one thing it
# exists to avoid testing, and a package that cannot even unzip would read as green. The
# install and pytest legs are different: both are caught downstream by the STATUS guard
# whether `set -e` is present or not. So this is the only region where the option was ever
# load-bearing, and the guards below are what a test can delete to prove it.
# Armed BEFORE the directory exists, and on every signal a caller can send rather than on
# EXIT alone. In dash an EXIT trap runs for none of INT, TERM, HUP or PIPE, so piping this
# script into `head` left an unpacked copy of the package behind, unbounded in number. The
# identical defect was found in `scripts/build-package.sh` and fixed there; the sibling was
# not, which is what a duplicated control does when only one copy is held by a test.
WORK=""
trap 'rm -rf "${WORK:-}"' EXIT HUP INT TERM PIPE
WORK="$(mktemp -d)" || { echo "FAIL: no work directory could be created"; exit 1; }
echo "package:     $PKG"
echo "unpacked to: $WORK"
unzip -q "$PKG" -d "$WORK" || { echo "FAIL: $PKG did not unpack"; exit 1; }

cd "$WORK"
# The assertion every fall-through above defeats, stated POSITIVELY because that is what
# makes it reachable. `cd ""` returns zero in this shell and leaves the current directory
# in the repository, so a negative check on the `cd` alone proves nothing. Everything below
# runs in the current directory, and this is the line that decides what was tested: the
# repository is refused by name, and so is any directory that is not an unpacked package,
# which also catches a builder whose allowlist has dropped the lockfile.
if [ "$PWD" = "$ROOT" ] || [ ! -f requirements.txt ]; then
  echo "FAIL: this is not an unpacked package; refusing to report on it as if it were one"
  exit 1
fi

# BELOW the assertion above, deliberately. A host with no Python 3.12 must skip this leg,
# but a skip is a statement about the host and the refusal above is a statement about what
# would have been tested. Checking the interpreter first turned the second into the first
# on any such host, which is a control reported as an environment limitation.
PY312="${PYTHON312:-/usr/bin/python3.12}"
[ -x "$PY312" ] || { echo "SKIP: no interpreter at $PY312; this leg cannot run locally."; exit 1; }

"$PY312" -m venv .venv
echo "== stage 5, install: pip install -r requirements.txt =="
.venv/bin/python -m pip install -q -r requirements.txt

echo "== stage 5, test: pytest with coverage to the path the quality gate reads =="
set +e
.venv/bin/python -m pytest --cov --cov-report=xml -q
STATUS=$?
set -e
echo "PYTEST EXIT: $STATUS"
[ "$STATUS" -eq 0 ] || { echo "SIMULATION: FAIL at stage 5"; exit "$STATUS"; }

# Stage 6 reads this exact path. A suite that passes while writing the report somewhere
# else still fails the quality gate, so the artefact is asserted rather than assumed.
[ -f coverage.xml ] || { echo "SIMULATION: FAIL, coverage.xml was not written"; exit 1; }
echo "coverage.xml: $(wc -c < coverage.xml) bytes"
echo "SIMULATION: PASS"
