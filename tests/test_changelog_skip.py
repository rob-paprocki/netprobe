"""Tests of the private/changelog-skip.txt support in scripts/release/changelog_check.py,
run on small temporary git repositories."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(os.path.dirname(HERE), "scripts", "release", "changelog_check.py")
ENV = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
           GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
           GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


class ChangelogSkipListTests(unittest.TestCase):
    def setUp(self):
        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)
        self.git("init", "-q", "-b", "main")
        self.commit("Add the changelog", {"CHANGELOG.md": "# Changelog\n"})

    def git(self, *args):
        return subprocess.run(["git", "-C", self.repo] + list(args), capture_output=True, text=True,
                              check=True, env=ENV).stdout.strip()

    def commit(self, message, files):
        for path, text in files.items():
            full = os.path.join(self.repo, path)
            os.makedirs(os.path.dirname(full) or self.repo, exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(text)
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def skip(self, text):
        os.makedirs(os.path.join(self.repo, "private"), exist_ok=True)
        with open(os.path.join(self.repo, "private", "changelog-skip.txt"), "w", encoding="utf-8") as f:
            f.write(text)

    def run_check(self):
        r = subprocess.run([sys.executable, "-I", SCRIPT], cwd=self.repo, capture_output=True,
                           text=True, env=ENV)
        return r.returncode, r.stdout + r.stderr

    def test_an_unlisted_visible_change_still_fails(self):
        self.commit("Change the readme", {"README.md": "one\n"})
        self.assertEqual(self.run_check()[0], 1)

    def test_a_listed_commit_is_skipped(self):
        sha = self.commit("Reword the readme", {"README.md": "one\n"})
        self.skip("# reviewed\n%s  wording only\n" % sha)
        code, out = self.run_check()
        self.assertEqual(code, 0, out)
        self.assertIn("skipped", out)

    def test_only_listed_commits_are_skipped(self):
        listed = self.commit("Reword the readme", {"README.md": "one\n"})
        self.commit("Change the readme", {"README.md": "two\n"})
        self.skip("%s  wording only\n" % listed)
        self.assertEqual(self.run_check()[0], 1)

    def test_a_malformed_line_fails(self):
        sha = self.commit("Reword the readme", {"README.md": "one\n"})
        self.skip("%s\n" % sha[:10])
        code, out = self.run_check()
        self.assertEqual(code, 2)
        self.assertIn("line 1", out)

    def test_a_sha_outside_the_history_fails(self):
        self.commit("Reword the readme", {"README.md": "one\n"})
        self.skip("%s  not here\n" % ("0" * 40))
        self.assertEqual(self.run_check()[0], 2)

    def test_a_commit_listed_twice_fails(self):
        sha = self.commit("Reword the readme", {"README.md": "one\n"})
        self.skip("%s  once\n%s  twice\n" % (sha, sha))
        self.assertEqual(self.run_check()[0], 2)


if __name__ == "__main__":
    unittest.main()
