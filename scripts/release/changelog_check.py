#!/usr/bin/python3 -I
"""Flag commits that change user-visible files without touching CHANGELOG.md.

  changelog_check.py [BASE]     commits in BASE..HEAD (default: since the last
                                v* tag, or since CHANGELOG.md was added)

A commit can opt out with "[no changelog]" in its message (typos, tests,
invisible refactors). Exit 1 if any commit is flagged.
"""
import re
import subprocess
import sys

VISIBLE = ("netprobe.sh", "Test-Network.cmd", "examples/", "README.md", "LICENSE", "VERSION", "docs/")


def git(*args):
    return subprocess.run(["git"] + list(args), capture_output=True, text=True, check=True).stdout


def default_base():
    tags = git("tag", "--list", "v*", "--sort=-v:refname").split()
    if tags:
        return tags[0]
    added = git("log", "--diff-filter=A", "--format=%H", "--", "CHANGELOG.md").split()
    return added[-1] if added else None


def excluded():
    """Paths in private/public-exclude.txt never reach the public repo, so they are not visible changes."""
    try:
        with open("private/public-exclude.txt", encoding="utf-8") as f:
            return [l.strip().rstrip("/") for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def flagged(base):
    skip = excluded()
    rng = "%s..HEAD" % base if base else "HEAD"
    out = []
    for sha in git("rev-list", "--no-merges", rng).split():
        if sha in LISTED:
            continue
        msg = git("log", "-1", "--format=%B", sha)
        if "[no changelog]" in msg:
            continue
        files = git("diff-tree", "--no-commit-id", "--name-only", "-r", sha).split()
        if "CHANGELOG.md" in files:
            continue
        visible = [f for f in files if not f.startswith("private/") and
                   not any(f == s or f.startswith(s + "/") for s in skip) and
                   any(f == v or f.startswith(v) for v in VISIBLE)]
        if visible:
            out.append((sha[:10], msg.splitlines()[0] if msg else "", visible))
    return out


# Reviewed commits that went in without a CHANGELOG.md line or [no changelog]:
# private/changelog-skip.txt, one full 40-character SHA per line, then the reason.
# Lines that start with # are comments. The list never reaches the public copy.
SKIP_LIST = "private/changelog-skip.txt"
SKIP_LINE = re.compile(r"([0-9a-f]{40})[ \t]+([^#\s].*)")
LISTED = {}


class SkipListError(Exception):
    """The skip list can't be used. The check fails rather than guess."""


def in_history(sha):
    """True if SHA is a commit that HEAD's history contains."""
    found = subprocess.run(["git", "rev-parse", "--verify", "--quiet", sha + "^{commit}"],
                           capture_output=True, text=True)
    if found.returncode != 0 or found.stdout.strip() != sha:
        return False
    return subprocess.run(["git", "merge-base", "--is-ancestor", sha, "HEAD"],
                          capture_output=True).returncode == 0


def skip_list(path=SKIP_LIST):
    """{sha: reason} from the skip list ({} when there is none)."""
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeDecodeError) as error:
        raise SkipListError("%s can't be read (%s)" % (path, error.__class__.__name__)) from None
    listed = {}
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        where = "%s line %d" % (path, number)
        match = SKIP_LINE.fullmatch(line)
        if not match:
            raise SkipListError("%s: needs a full 40-character commit SHA in lower case, then a space "
                                "and the reason" % where)
        sha, reason = match.groups()
        if sha in listed:
            raise SkipListError("%s: lists commit %s a second time" % (where, sha[:10]))
        if not in_history(sha):
            raise SkipListError("%s: commit %s isn't in the history of HEAD" % (where, sha[:10]))
        listed[sha] = reason
    return listed


def main(argv):
    global LISTED
    try:
        LISTED = skip_list()
    except SkipListError as error:
        print("changelog check: %s" % error)
        return 2
    if LISTED:
        print("changelog check: %d reviewed commit(s) listed in %s are skipped" % (len(LISTED), SKIP_LIST))
    base = argv[1] if len(argv) > 1 else default_base()
    bad = flagged(base)
    for sha, subject, files in bad:
        print("%s %s\n    changes %s but not CHANGELOG.md (add a line, or put "
              "[no changelog] in the message)" % (sha, subject, ", ".join(files[:5])))
    print("changelog check: %s" % ("%d commit(s) need a changelog line" % len(bad) if bad else "OK"))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
