#!/usr/bin/env python3
"""Check .claude-plugin/marketplace.json for the jposluns plugin marketplace.

Python 3 standard library only. Run it from the repository root:

    python3 -I -B tools/check_marketplace.py               check the live file
    python3 -I -B tools/check_marketplace.py FILE          check a copy of the file
    python3 -I -B tools/check_marketplace.py --self-test   test the checker (no network)

What it checks:

  1. The file is valid JSON: UTF-8, no byte order mark, no duplicate keys.
  2. The required fields are present: name, owner.name and plugins at the top
     level; name and source in every entry. The marketplace name is "jposluns"
     and owner.name is "Jeff Posluns", both exactly.
  3. Names use lowercase letters, digits and single hyphens, and each entry
     name is used once.
  4. A source is one of github, git-subdir or archive, with only the fields
     listed for that source.
  5. A github or git-subdir source names a repository under jposluns.
  6. An archive source has an https url on an allow-listed host, a file name
     of the form <artifact>-<version>.zip, and a sha256 of 64 lowercase hex
     characters. The version is the last part after a "-" and starts with a
     digit: auditthis-plugin-2.14.0.zip gives auditthis-plugin and 2.14.0.
     https://posluns.dev/hashes.txt must hold exactly one release row for
     that artifact and version, and the row's sha256 must equal the entry's.
     One redirect is allowed, only to https://posluns.ca/hashes.txt.

What it does not check: it does not download a zip or clone a repository, so
it does not compare the entry name with the plugin's own plugin.json, and it
does not run "claude plugin validate".

Any failure to read the file or to fetch hashes.txt counts as a problem.
Exit status: 0 when clean, 1 when there are problems, 2 for a usage error.
"""

import argparse
import contextlib
import http.client
import io
import json
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

MARKETPLACE_NAME = "jposluns"
OWNER_NAME = "Jeff Posluns"
ARCHIVE_HOSTS = frozenset({
    "posluns.dev",
    "posluns.ca",
    "auditthis.ai",
    "secureconfig.ai",
    "cleanlanguage.ai",
    "aiqt.ai",
    "opfiles.ai",
})
HASHES_URL = "https://posluns.dev/hashes.txt"
HASHES_REDIRECT_URL = "https://posluns.ca/hashes.txt"
REDIRECT_STATUSES = (301, 302, 303, 307, 308)

MAX_MARKETPLACE_BYTES = 1024 * 1024
MAX_HASHES_BYTES = 4 * 1024 * 1024
TIMEOUT_SECONDS = 20

DEFAULT_PATH = Path(__file__).resolve().parent.parent / ".claude-plugin" / "marketplace.json"

SOURCE_FIELDS = {
    "github": frozenset({"source", "repo", "ref", "sha"}),
    "git-subdir": frozenset({"source", "url", "path", "ref", "sha"}),
    "archive": frozenset({"source", "url", "sha256"}),
}

NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+-]*")
REPO_RE = re.compile(r"jposluns/([A-Za-z0-9._-]+)")
REPO_URL_RE = re.compile(r"https://github\.com/jposluns/([A-Za-z0-9._-]+?)(?:\.git)?")
ZIP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip")
URL_CHARS_RE = re.compile(r"[!-$&-\[\]-~]+")  # printable ASCII without space, % and backslash
HASHES_DIGEST_RE = re.compile(r"sha256:([0-9a-f]{64})")
HASHES_RELEASE_KIND = "release"


class HashesError(Exception):
    """The hashes list could not be fetched, read or understood."""


# --------------------------------------------------------------------------
# hashes.txt
# --------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _https_get(url):
    """One GET that follows no redirect. Returns (status, location, body)."""
    opener = urllib.request.build_opener(_NoRedirect)
    request = urllib.request.Request(
        url, headers={"User-Agent": "jposluns-plugins-check", "Accept": "text/plain"})
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:
            return response.status, None, response.read(MAX_HASHES_BYTES + 1)
    except urllib.error.HTTPError as error:
        with error:
            location = error.headers.get("Location") if error.headers else None
            return error.code, location, b""
    except (OSError, ValueError, http.client.HTTPException) as error:
        raise HashesError("could not fetch {}: {}".format(url, error)) from None


def _decode_hashes(body, source):
    if len(body) > MAX_HASHES_BYTES:
        raise HashesError("{} is larger than {} bytes".format(source, MAX_HASHES_BYTES))
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        raise HashesError("{} is not UTF-8 text".format(source)) from None


def fetch_hashes(get=None):
    """Fetch the published hashes list. One redirect, only to the .ca address."""
    get = get or _https_get
    source = HASHES_URL
    status, location, body = get(source)
    if status in REDIRECT_STATUSES:
        if location != HASHES_REDIRECT_URL:
            raise HashesError("{} redirects to {!r}; the only redirect allowed is to {}".format(
                source, location, HASHES_REDIRECT_URL))
        source = HASHES_REDIRECT_URL
        status, location, body = get(source)
    if status != 200:
        raise HashesError("{} answered HTTP {} (expected 200; one redirect at most)".format(
            source, status))
    return _decode_hashes(body, source)


def read_hashes_file(path):
    """Read a local copy of the hashes list (for offline use and tests)."""
    try:
        with open(path, "rb") as handle:
            body = handle.read(MAX_HASHES_BYTES + 1)
    except OSError as error:
        raise HashesError("could not read {}: {}".format(path, error)) from None
    return _decode_hashes(body, str(path))


def split_archive_name(file_name):
    """Return (artifact, version) for <artifact>-<version>.zip, or None.

    The version is the last part after a "-" and must start with a digit, so
    auditthis-plugin-2.14.0.zip gives ("auditthis-plugin", "2.14.0").
    """
    parts = file_name[:-len(".zip")].split("-")
    if len(parts) < 2 or "" in parts or parts[-1][0] not in "0123456789":
        return None
    return "-".join(parts[:-1]), parts[-1]


def rows_for_release(text, artifact, version):
    """Return (release digests, other kinds) for the rows of artifact and version.

    A row holds six fields with whitespace between them:

        artifact  version  date  revision  kind  sha256:<64 lowercase hex>

    Blank lines and lines that start with "#" are ignored. The first list holds
    the sha256 of every row whose kind is "release", one item per row. The
    second list holds the kind of every other row for the same artifact and
    version (for example "pre-release"). A row for the artifact and version
    that is not in this form is an error.
    """
    digests, other_kinds = [], []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or fields[0].startswith("#") or fields[:2] != [artifact, version]:
            continue
        digest = HASHES_DIGEST_RE.fullmatch(fields[5]) if len(fields) == 6 else None
        if not digest:
            raise HashesError("hashes.txt line {} for {} {} is not in the form: artifact "
                              "version date revision kind sha256:<64 lowercase hex>".format(
                                  number, artifact, version))
        if fields[4] == HASHES_RELEASE_KIND:
            digests.append(digest.group(1))
        else:
            other_kinds.append(fields[4])
    return digests, other_kinds


class _Hashes:
    """Loads the hashes list once, on first use, and remembers a failure."""

    def __init__(self, load):
        self._load = load
        self._result = None

    def get(self):
        if self._result is None:
            try:
                self._result = (self._load(), None)
            except HashesError as error:
                self._result = (None, str(error))
        return self._result


# --------------------------------------------------------------------------
# marketplace.json
# --------------------------------------------------------------------------

def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key {!r}".format(key))
        result[key] = value
    return result


def _no_constants(token):
    raise ValueError("{} is not valid JSON".format(token))


def _parse_json(raw):
    """Return (document, None) or (None, problem)."""
    if len(raw) > MAX_MARKETPLACE_BYTES:
        return None, "file is larger than {} bytes".format(MAX_MARKETPLACE_BYTES)
    if raw.startswith(b"\xef\xbb\xbf"):
        return None, "file starts with a byte order mark"
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, "file is not UTF-8"
    try:
        return json.loads(text, object_pairs_hook=_no_duplicate_keys,
                          parse_constant=_no_constants), None
    except (ValueError, RecursionError) as error:
        return None, "invalid JSON: {}".format(error)


def _is_text(value):
    return isinstance(value, str) and value.strip() != ""


def _jposluns_repo_url(value):
    """True for jposluns/<repo> or https://github.com/jposluns/<repo>[.git]."""
    if not isinstance(value, str):
        return False
    match = REPO_RE.fullmatch(value) or REPO_URL_RE.fullmatch(value)
    return bool(match) and match.group(1) not in (".", "..")


def _check_subdir_path(value):
    """Return a problem text, or None when the path is a plain relative path."""
    if not _is_text(value):
        return '"path" is required and must be text'
    if "\\" in value or value.startswith("/"):
        return '"path" must be a relative path with forward slashes'
    if any(part in ("", ".", "..") for part in value.split("/")):
        return '"path" must not hold empty, "." or ".." parts'
    return None


def _check_pin(source, label, problems, notes):
    if "ref" in source:
        ref = source["ref"]
        if not isinstance(ref, str) or not REF_RE.fullmatch(ref):
            problems.append('{}: "ref" must be a branch or tag name'.format(label))
    if "sha" in source:
        sha = source["sha"]
        if not isinstance(sha, str) or not COMMIT_RE.fullmatch(sha):
            problems.append('{}: "sha" must be the full 40-character lowercase hex '
                            'revision id'.format(label))
    else:
        notes.append("{}: the source is not pinned to a sha".format(label))


def check_archive_url(url):
    """Return (file_name, None) or (None, problem) for an archive url."""
    if not isinstance(url, str) or not URL_CHARS_RE.fullmatch(url):
        return None, '"url" is required and must be a plain URL (no spaces, "%" or "\\")'
    if not url.startswith("https://"):
        return None, '"url" must start with https://'
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None, '"url" is not a valid URL'
    if parts.netloc not in ARCHIVE_HOSTS:
        return None, '"url" host {!r} is not on the allow-list ({})'.format(
            parts.netloc, ", ".join(sorted(ARCHIVE_HOSTS)))
    if "?" in url or "#" in url:
        return None, '"url" must not carry a query or a fragment'
    segments = parts.path.split("/")[1:]
    if not segments or any(part in ("", ".", "..") for part in segments[:-1]):
        return None, '"url" path must not hold empty, "." or ".." parts'
    file_name = segments[-1]
    if not ZIP_NAME_RE.fullmatch(file_name):
        return None, '"url" must end in a zip file name (letters, digits, ".", "_", "-")'
    return file_name, None


def _check_archive(source, label, problems, hashes):
    file_name, url_problem = check_archive_url(source.get("url"))
    named = None if url_problem else split_archive_name(file_name)
    if not url_problem and not named:
        url_problem = ('"url" file name {} is not of the form <artifact>-<version>.zip (the '
                       'version is the last part after a "-" and starts with a digit)'.format(
                           file_name))
    if url_problem:
        problems.append("{}: {}".format(label, url_problem))
    sha256 = source.get("sha256")
    sha_ok = isinstance(sha256, str) and bool(SHA256_RE.fullmatch(sha256))
    if not sha_ok:
        problems.append('{}: "sha256" is required and must be 64 lowercase hex '
                        'characters'.format(label))
    if url_problem or not sha_ok:
        return
    text, error = hashes.get()
    if error:
        problems.append("{}: could not check the sha256 against hashes.txt: {}".format(
            label, error))
        return
    artifact, version = named
    target = "{} {}".format(artifact, version)
    try:
        digests, other_kinds = rows_for_release(text, artifact, version)
    except HashesError as error:
        problems.append("{}: {}".format(label, error))
        return
    if len(digests) > 1:
        problems.append("{}: hashes.txt has {} release rows for {}; exactly one is "
                        "required".format(label, len(digests), target))
    elif not digests and other_kinds:
        problems.append("{}: hashes.txt has no release row for {} (it has only: {})".format(
            label, target, ", ".join(sorted(set(other_kinds)))))
    elif not digests:
        problems.append("{}: hashes.txt has no row for {} (artifact and version taken from "
                        "the file name {})".format(label, target, file_name))
    elif digests[0] != sha256:
        problems.append("{}: sha256 does not match the hashes.txt release row for {}".format(
            label, target))


def _check_source(source, label, problems, notes, hashes):
    if isinstance(source, str):
        problems.append("{}: a relative path source is not accepted; use github, git-subdir "
                        "or archive".format(label))
        return
    if not isinstance(source, dict):
        problems.append('{}: "source" must be an object'.format(label))
        return
    kind = source.get("source")
    if not isinstance(kind, str) or kind not in SOURCE_FIELDS:
        problems.append("{}: source type {!r} is not accepted; use github, git-subdir or "
                        "archive".format(label, kind))
        return
    extra = sorted(str(key) for key in set(source) - SOURCE_FIELDS[kind])
    if extra:
        problems.append("{}: {} source has unknown field(s): {}".format(
            label, kind, ", ".join(extra)))
    if kind == "github":
        if not _jposluns_repo_url(source.get("repo")) or "://" in source["repo"]:
            problems.append('{}: "repo" is required and must be jposluns/<repository>'.format(
                label))
        _check_pin(source, label, problems, notes)
    elif kind == "git-subdir":
        if not _jposluns_repo_url(source.get("url")):
            problems.append('{}: "url" is required and must be jposluns/<repository> or '
                            'https://github.com/jposluns/<repository>'.format(label))
        path_problem = _check_subdir_path(source.get("path"))
        if path_problem:
            problems.append("{}: {}".format(label, path_problem))
        _check_pin(source, label, problems, notes)
    else:
        _check_archive(source, label, problems, hashes)


def check_marketplace(raw, load_hashes):
    """Check the bytes of a marketplace.json. Returns (problems, notes, plugin count).

    load_hashes is called at most once, and only when an archive entry needs it.
    It returns the text of the hashes list or raises HashesError.
    """
    problems, notes = [], []
    document, problem = _parse_json(raw)
    if problem:
        return [problem], notes, 0
    if not isinstance(document, dict):
        return ["the top level must be a JSON object"], notes, 0

    if "name" not in document:
        problems.append('missing required field "name"')
    elif not isinstance(document["name"], str) or not NAME_RE.fullmatch(document["name"]):
        problems.append('"name" must use lowercase letters, digits and single hyphens')
    elif document["name"] != MARKETPLACE_NAME:
        problems.append('"name" must be "{}"'.format(MARKETPLACE_NAME))

    if "owner" not in document:
        problems.append('missing required field "owner"')
    elif not isinstance(document["owner"], dict) or not _is_text(document["owner"].get("name")):
        problems.append('"owner" must be an object with a non-empty "name"')
    else:
        if document["owner"]["name"] != OWNER_NAME:
            problems.append('"owner.name" must be exactly "{}"'.format(OWNER_NAME))
        for key in ("email", "url"):
            if key in document["owner"] and not isinstance(document["owner"][key], str):
                problems.append('"owner.{}" must be text'.format(key))

    if "description" in document and not isinstance(document["description"], str):
        problems.append('"description" must be text')

    if "plugins" not in document:
        problems.append('missing required field "plugins"')
        return problems, notes, 0
    plugins = document["plugins"]
    if not isinstance(plugins, list):
        problems.append('"plugins" must be an array')
        return problems, notes, 0
    if not plugins:
        notes.append('"plugins" is empty')

    hashes = _Hashes(load_hashes)
    seen = set()
    for index, entry in enumerate(plugins):
        label = "plugins[{}]".format(index)
        if not isinstance(entry, dict):
            problems.append("{}: an entry must be an object".format(label))
            continue
        name = entry.get("name")
        if "name" not in entry:
            problems.append('{}: missing required field "name"'.format(label))
        elif not isinstance(name, str) or not NAME_RE.fullmatch(name):
            problems.append('{}: "name" must use lowercase letters, digits and single '
                            'hyphens'.format(label))
        else:
            label = "{} ({})".format(label, name)
            if name in seen:
                problems.append('{}: the name "{}" is already used by another entry'.format(
                    label, name))
            seen.add(name)
        if "description" in entry and not isinstance(entry["description"], str):
            problems.append('{}: "description" must be text'.format(label))
        if "source" not in entry:
            problems.append('{}: missing required field "source"'.format(label))
        else:
            _check_source(entry["source"], label, problems, notes, hashes)
    return problems, notes, len(plugins)


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

def run_check(path, hashes_file=None, out=None):
    out = out or sys.stdout
    used = []

    def load_hashes():
        if hashes_file is None:
            used.append(HASHES_URL)
            return fetch_hashes()
        used.append("local file {} (not the published list)".format(hashes_file))
        return read_hashes_file(hashes_file)

    print("check_marketplace: {}".format(path), file=out)
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_MARKETPLACE_BYTES + 1)
    except OSError as error:
        problems, notes, count = ["could not read the file: {}".format(error)], [], 0
    else:
        problems, notes, count = check_marketplace(raw, load_hashes)
    for source in used:
        print("hashes source: {}".format(source), file=out)
    for note in notes:
        print("note: {}".format(note), file=out)
    for problem in problems:
        print("problem: {}".format(problem), file=out)
    if problems:
        print("check_marketplace: FAIL, {} problem(s)".format(len(problems)), file=out)
        return 1
    print("check_marketplace: OK, {} plugin(s) checked".format(count), file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check the jposluns plugin marketplace file.", allow_abbrev=False)
    parser.add_argument("path", nargs="?",
                        help="marketplace.json to check (default: the one in this repository)")
    parser.add_argument("--hashes-file", metavar="FILE",
                        help="read the hashes list from a local file instead of fetching it")
    parser.add_argument("--self-test", action="store_true",
                        help="test the checker itself; uses no network")
    args = parser.parse_args(argv)
    if args.self_test:
        if args.path or args.hashes_file:
            parser.error("--self-test takes no other argument")
        return self_test()
    return run_check(args.path or DEFAULT_PATH, args.hashes_file)


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

_SHA_A = "0123456789abcdef" * 4
_SHA_B = "fedcba9876543210" * 4
_COMMIT = "0123456789abcdef0123456789abcdef01234567"
_ZIP = "beta-plugin-1.0.0.zip"
_ZIP_URL = "https://posluns.dev/downloads/" + _ZIP
_GIT, _ARCHIVE, _GITHUB = 0, 1, 2
_DROP = object()


def _row(artifact, version, digest, kind="release"):
    """One made-up hashes.txt row."""
    return "{}  {}  2026-01-01  0000000  {}  sha256:{}\n".format(artifact, version, kind, digest)


_HASHES = ("# self-test fixture\n" + _row("beta-plugin", "1.0.0", _SHA_A)
           + _row("other-plugin", "1.0.0", _SHA_B))

# Lines copied unchanged from https://posluns.ca/hashes.txt as fetched on 2026-11-15.
_SAMPLE = """\
# fields:  project   version   date        commit    status        digest

# aiqt
aiqt              1.0.0     2026-09-17  058abd9  pre-release  sha256:435cb9659316125701b1479a35da4be74ac4a6b62c6530cfaff1c5bb31e229dc
aiqt              1.0.5     2026-09-18  c5d77b0  release      sha256:e96f4836bbdcda3815198454292f68bcb9c79b748ea20c9c4a5dbaddf4cec18c

# auditthis-plugin
auditthis-plugin  2.10.0    2026-11-13  2a9514e  release      sha256:da80fbccb389991259e509ca0b7512b1b2336ad7ce8a849c0e10f34a8c2124eb
auditthis-plugin  2.11.0    2026-11-13  10b7f5a  release      sha256:f3ec0f7cf31f0d5ea2146bd79f259e417f902176b93e0857f2c67e3067014e97
auditthis-plugin  2.11.1    2026-11-13  c69f1b5  release      sha256:6dd9711ad44d3bd29403086138ecc147bad6497248835e830d05bca6b111dfc7
auditthis-plugin  2.12.0    2026-11-14  76df64b  release      sha256:4dd26eef2146880d94261b5671f2743eb2063cb0adb2700366df67e7721bbc90
auditthis-plugin  2.13.0    2026-11-14  dfad1cb  release      sha256:78af137b72da1b7a4ef521d26aaeed42e5e53288463c660368f774a7d1f95880
auditthis-plugin  2.14.0    2026-11-15  3572753  release      sha256:2c6acb53d8cc293b0515cbfab61bb00699b9852ec52171652981b7d27f99bddc

# auditthis-skill
auditthis-skill   2.13.0    2026-11-14  dfad1cb  release      sha256:dce732c94c8f3d907e2064a9467b2e8c1f82fc0599b4610ba31555ae36e58ba1
auditthis-skill   2.14.0    2026-11-15  3572753  release      sha256:2d984a4041976c81cf0fc7999fe933a9851d67fb1a53f82d4b5000ae89d1f1de
"""
_SAMPLE_ROW = ("auditthis-plugin  2.14.0    2026-11-15  3572753  release      sha256:"
               "2c6acb53d8cc293b0515cbfab61bb00699b9852ec52171652981b7d27f99bddc")
_SAMPLE_URL = "https://auditthis.ai/downloads/auditthis-plugin-2.14.0.zip"
_SAMPLE_SHA = "2c6acb53d8cc293b0515cbfab61bb00699b9852ec52171652981b7d27f99bddc"
_SAMPLE_SHA_2_13_0 = "78af137b72da1b7a4ef521d26aaeed42e5e53288463c660368f774a7d1f95880"
_SAMPLE_SHA_SKILL = "2d984a4041976c81cf0fc7999fe933a9851d67fb1a53f82d4b5000ae89d1f1de"
_SAMPLE_PRE_URL = "https://aiqt.ai/downloads/aiqt-1.0.0.zip"
_SAMPLE_PRE_SHA = "435cb9659316125701b1479a35da4be74ac4a6b62c6530cfaff1c5bb31e229dc"


def _sample(url=_SAMPLE_URL, sha256=_SAMPLE_SHA):
    """The fixture with its archive entry replaced by the auditthis entry."""
    return _changed(("plugins", _ARCHIVE), {"name": "auditthis", "source": {
        "source": "archive", "url": url, "sha256": sha256}})


def _fixture():
    return {
        "name": "jposluns",
        "owner": {"name": "Jeff Posluns"},
        "description": "Self-test fixture.",
        "plugins": [
            {"name": "alpha", "description": "Fixture entry.",
             "source": {"source": "git-subdir", "url": "jposluns/alpha", "path": "plugin",
                        "ref": "main"}},
            {"name": "beta",
             "source": {"source": "archive", "url": _ZIP_URL, "sha256": _SHA_A}},
            {"name": "gamma",
             "source": {"source": "github", "repo": "jposluns/gamma", "ref": "v1.0.0",
                        "sha": _COMMIT}},
        ],
    }


def _changed(path, value=_DROP):
    """The fixture with one value replaced, or removed when no value is given."""
    document = _fixture()
    node = document
    for key in path[:-1]:
        node = node[key]
    if value is _DROP:
        del node[path[-1]]
    else:
        node[path[-1]] = value
    return document


def self_test():
    global _https_get
    results = []

    def record(name, passed, detail=""):
        results.append((name, bool(passed), detail))

    def run(document, hashes=_HASHES):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
        calls = []

        def load():
            calls.append(1)
            if isinstance(hashes, Exception):
                raise hashes
            return hashes

        problems, notes, _count = check_marketplace(raw, load)
        return problems, notes, len(calls)

    def clean(name, document, hashes=_HASHES, lookups=None, note=None):
        problems, notes, calls = run(document, hashes)
        passed = not problems
        if lookups is not None:
            passed = passed and calls == lookups
        if note is not None:
            passed = passed and any(note in text for text in notes)
        record("accepts " + name, passed,
               "problems={} notes={} lookups={}".format(problems, notes, calls))

    def refused(name, document, fragment, hashes=_HASHES):
        problems, _notes, _calls = run(document, hashes)
        record("refuses " + name, len(problems) == 1 and fragment in problems[0],
               "wanted one problem holding {!r}, got {}".format(fragment, problems))

    real_get = _https_get

    def no_network(url):
        raise HashesError("the self-test tried to use the network: {}".format(url))

    _https_get = no_network
    try:
        source = ("plugins", _ARCHIVE, "source")
        git = ("plugins", _GIT, "source")
        hub = ("plugins", _GITHUB, "source")

        # Files that pass.
        clean("the fixture", _fixture(), lookups=1, note="plugins[0] (alpha): the source is not")
        document = _fixture()
        del document["plugins"][_ARCHIVE]
        clean("a file with no archive entry, without a hashes lookup", document, lookups=0)
        document = _fixture()
        document["plugins"].append({"name": "delta", "source": {
            "source": "archive", "url": "https://aiqt.ai/other-plugin-1.0.0.zip",
            "sha256": _SHA_B}})
        clean("two archive entries with one hashes lookup", document, lookups=1)
        clean("an empty plugins array, with a note", _changed(("plugins",), []),
              lookups=0, note="empty")
        clean("a git-subdir https URL with a sha", _changed(git, {
            "source": "git-subdir", "url": "https://github.com/jposluns/alpha.git",
            "path": "plugins/alpha", "sha": _COMMIT}))
        clean("a github source with no ref or sha", _changed(hub, {
            "source": "github", "repo": "jposluns/gamma"}), note="plugins[2] (gamma)")
        for host in sorted(ARCHIVE_HOSTS):
            clean("an archive on " + host,
                  _changed(source + ("url",), "https://{}/{}".format(host, _ZIP)))
        clean("hashes.txt with a release row beside a pre-release row", _fixture(),
              hashes=_row("beta-plugin", "1.0.0", _SHA_B, "pre-release") + _HASHES)
        clean("hashes.txt with tabs, an indent, blank lines and comments", _fixture(),
              hashes="\n  # note\n#{0}\n \tbeta-plugin\t1.0.0\t2026-01-01\t0000000\trelease"
                     "\tsha256:{1}\n\n".format(_row("beta-plugin", "1.0.0", _SHA_B), _SHA_A))

        # JSON validity.
        good = json.dumps(_fixture()).encode("utf-8")
        refused("broken JSON", b"{", "invalid JSON")
        refused("a byte order mark", b"\xef\xbb\xbf" + good, "byte order mark")
        refused("bytes that are not UTF-8", b"\xff\xfe", "not UTF-8")
        refused("a duplicate key",
                b'{"name":"jposluns","name":"jposluns","owner":{"name":"x"},"plugins":[]}',
                "duplicate key")
        refused("NaN", b'{"name":"jposluns","owner":{"name":"x"},"plugins":[],"x":NaN}',
                "invalid JSON")
        refused("a top-level array", b"[]", "top level")
        refused("an oversized file", b" " * (MAX_MARKETPLACE_BYTES + 1), "larger than")

        # Required fields.
        refused("no marketplace name", _changed(("name",)), 'required field "name"')
        refused("another marketplace name", _changed(("name",), "other"), 'must be "jposluns"')
        refused("no owner", _changed(("owner",)), 'required field "owner"')
        refused("an owner without a name", _changed(("owner",), {}), '"owner" must be')
        refused("an owner that is text", _changed(("owner",), "Jeff Posluns"), '"owner" must be')
        refused("no plugins", _changed(("plugins",)), 'required field "plugins"')
        refused("plugins that is an object", _changed(("plugins",), {}), "must be an array")
        refused("an entry that is text", _changed(("plugins", _GIT), "alpha"),
                "must be an object")
        refused("an entry without a name", _changed(("plugins", _GIT, "name")),
                'plugins[0]: missing required field "name"')
        refused("an entry without a source", _changed(("plugins", _GIT, "source")),
                'missing required field "source"')

        # The owner name: "Jeff Posluns" exactly.
        clean("the owner name with a url beside it",
              _changed(("owner",), {"name": OWNER_NAME, "url": "https://posluns.dev"}))
        clean("the owner name written with a JSON escape for the same text",
              good.replace(b'"Jeff Posluns"', b'"Jeff\\u0020Posluns"'))
        for bad in ("Someone Else", "jeff posluns", "JEFF POSLUNS", "Jeff", "Posluns",
                    "Jeff Posluns ", " Jeff Posluns", "Jeff  Posluns", "Jeff\tPosluns",
                    "Jeff\N{NO-BREAK SPACE}Posluns", "JeffPosluns", "Jeff Posluns Jr",
                    "Jeff Posluns.", "Jeff Poslun\N{CYRILLIC SMALL LETTER DZE}",
                    "Jeff Posluns\N{ZERO WIDTH SPACE}", "Jeff Posluns\n", "Jeff Posluns\x00",
                    "jposluns"):
            refused("the owner name {!a}".format(bad), _changed(("owner", "name"), bad),
                    '"owner.name" must be exactly "Jeff Posluns"')
        for bad in ("", "   ", 7, None, True, ["Jeff Posluns"], {"name": "Jeff Posluns"}):
            refused("the owner name {!r}".format(bad), _changed(("owner", "name"), bad),
                    '"owner" must be')
        document = _changed(("owner", "name"), "Someone Else")
        document["owner"]["email"] = 7
        problems, _notes, _calls = run(document)
        record("reports a wrong owner name and a wrong owner email as two problems",
               len(problems) == 2 and "owner.name" in problems[0]
               and "owner.email" in problems[1], repr(problems))

        # Names.
        for bad in ("Alpha", "al pha", "alpha_1", "-alpha", "alpha-", "alpha--one", "alpha.one",
                    "", 7):
            refused("the entry name {!r}".format(bad), _changed(("plugins", _GIT, "name"), bad),
                    "lowercase letters, digits and single hyphens")
        refused("a name used twice", _changed(("plugins", _GITHUB, "name"), "alpha"),
                "already used")

        # Source types and fields.
        refused("a relative path source", _changed(git, "./plugins/alpha"), "relative path")
        for kind in ("npm", "url", "command", None, ["github"]):
            refused("the source type {!r}".format(kind), _changed(git, {"source": kind}),
                    "is not accepted")
        refused("an unknown source field", _changed(source + ("ref",), "main"),
                "unknown field(s): ref")

        # github and git-subdir sources.
        for bad in ("someone/gamma", "jposluns/", "jposluns/gamma/extra", "Jposluns/gamma",
                    "https://github.com/jposluns/gamma", "jposluns/..", None):
            refused("the github repo {!r}".format(bad), _changed(hub + ("repo",), bad),
                    '"repo" is required')
        for bad in ("someone/alpha", "https://github.com/someone/alpha",
                    "https://gitlab.com/jposluns/alpha", "http://github.com/jposluns/alpha",
                    "https://github.com.evil.example/jposluns/alpha",
                    "https://evil.example/github.com/jposluns/alpha",
                    "git@github.com:jposluns/alpha.git", None):
            refused("the git-subdir url {!r}".format(bad), _changed(git + ("url",), bad),
                    '"url" is required')
        for bad in ("../plugin", "/plugin", "plugin/../..", "plugin//x", "plugin\\x", "", None):
            refused("the git-subdir path {!r}".format(bad), _changed(git + ("path",), bad),
                    '"path"')
        refused("a git-subdir source without a path", _changed(git + ("path",)), '"path"')
        for bad in ("abc123", _COMMIT.upper(), _COMMIT + "0", 40):
            refused("the sha {!r}".format(bad), _changed(hub + ("sha",), bad), '"sha" must be')
        for bad in ("", "-x", "two words", None):
            refused("the ref {!r}".format(bad), _changed(hub + ("ref",), bad), '"ref" must be')

        # archive sources.
        for bad, fragment in (
                ("http://posluns.dev/downloads/" + _ZIP, "must start with https://"),
                ("HTTPS://posluns.dev/downloads/" + _ZIP, "must start with https://"),
                ("https://evil.example/downloads/" + _ZIP, "allow-list"),
                ("https://posluns.dev.evil.example/" + _ZIP, "allow-list"),
                ("https://posluns.dev@evil.example/" + _ZIP, "allow-list"),
                ("https://evil.example@posluns.dev/" + _ZIP, "allow-list"),
                ("https://posluns.dev:8443/" + _ZIP, "allow-list"),
                ("https://POSLUNS.DEV/" + _ZIP, "allow-list"),
                ("https://www.posluns.dev/" + _ZIP, "allow-list"),
                (_ZIP_URL + "?v=1", "query or a fragment"),
                (_ZIP_URL + "#top", "query or a fragment"),
                ("https://posluns.dev/downloads/../" + _ZIP, '"." or ".."'),
                ("https://posluns.dev//" + _ZIP, '"." or ".."'),
                ("https://posluns.dev/downloads/beta-plugin-1.0.0.tar.gz", "zip file name"),
                ("https://posluns.dev/", "zip file name"),
                ("https://posluns.dev", '"." or ".."'),
                ("https://posluns.dev/downloads/beta%2Dplugin-1.0.0.zip", "plain URL"),
                ("https://posluns.dev\\@evil.example/" + _ZIP, "plain URL"),
                ("https://posluns.dev/down loads/" + _ZIP, "plain URL"),
                ("https://posluns.dev/downloads/beta-plugin.zip", "<artifact>-<version>.zip"),
                ("https://posluns.dev/downloads/beta-plugin-v1.0.0.zip",
                 "<artifact>-<version>.zip"),
                ("https://posluns.dev/downloads/beta-plugin-1.0.0-rc1.zip",
                 "<artifact>-<version>.zip"),
                ("https://posluns.dev/downloads/1.0.0.zip", "<artifact>-<version>.zip"),
                (None, "plain URL")):
            refused("the archive url {!r}".format(bad), _changed(source + ("url",), bad),
                    fragment)
        for bad in (_SHA_A[:-1], _SHA_A + "0", _SHA_A.upper(), "g" * 64, 64, None):
            refused("the sha256 {!r}".format(bad), _changed(source + ("sha256",), bad),
                    '"sha256" is required')
        refused("an archive source without a sha256", _changed(source + ("sha256",)),
                '"sha256" is required')

        # The artifact and version taken from the zip file name.
        for name, wanted in (
                ("auditthis-plugin-2.14.0.zip", ("auditthis-plugin", "2.14.0")),
                ("cleanlanguage-1.0.15.zip", ("cleanlanguage", "1.0.15")),
                ("tool-2-1.0.zip", ("tool-2", "1.0")),
                ("auditthis-plugin.zip", None),
                ("auditthis-plugin-v2.14.0.zip", None),
                ("auditthis-plugin-2.14.0-beta.zip", None),
                ("auditthis-plugin-.zip", None),
                ("auditthis--2.14.0.zip", None),
                ("2.14.0.zip", None)):
            got = split_archive_name(name)
            record("file name {} gives {}".format(name, wanted), got == wanted, repr(got))

        # hashes.txt lookups, with rows copied from the published list.
        clean("the auditthis-plugin 2.14.0 entry with the published rows", _sample(),
              hashes=_SAMPLE, lookups=1)
        refused("a wrong sha256 (the 2.13.0 row's) with the published rows",
                _sample(sha256=_SAMPLE_SHA_2_13_0),
                "does not match the hashes.txt release row for auditthis-plugin 2.14.0",
                hashes=_SAMPLE)
        refused("a wrong sha256 (the auditthis-skill 2.14.0 row's) with the published rows",
                _sample(sha256=_SAMPLE_SHA_SKILL),
                "does not match the hashes.txt release row for auditthis-plugin 2.14.0",
                hashes=_SAMPLE)
        refused("a missing row: the published rows without auditthis-plugin 2.14.0",
                _sample(), "no row for auditthis-plugin 2.14.0",
                hashes=_SAMPLE.replace(_SAMPLE_ROW + "\n", ""))
        refused("a pre-release row only: the auditthis-plugin 2.14.0 row marked pre-release",
                _sample(), "no release row for auditthis-plugin 2.14.0",
                hashes=_SAMPLE.replace(
                    _SAMPLE_ROW, _SAMPLE_ROW.replace("  release      ", "  pre-release  ")))
        refused("a pre-release row only: the published aiqt 1.0.0 row",
                _sample(url=_SAMPLE_PRE_URL, sha256=_SAMPLE_PRE_SHA),
                "no release row for aiqt 1.0.0", hashes=_SAMPLE)
        refused("two matching rows: the auditthis-plugin 2.14.0 row twice",
                _sample(), "2 release rows for auditthis-plugin 2.14.0",
                hashes=_SAMPLE + _SAMPLE_ROW + "\n")
        refused("two matching rows with different sha256 values",
                _sample(), "2 release rows for auditthis-plugin 2.14.0",
                hashes=_SAMPLE + _SAMPLE_ROW.replace(_SAMPLE_SHA, _SAMPLE_SHA_2_13_0) + "\n")

        # hashes.txt lookups, with made-up rows.
        refused("a zip with no hashes.txt row", _fixture(), "no row for beta-plugin 1.0.0",
                hashes=_row("other-plugin", "1.0.0", _SHA_A))
        refused("an empty hashes.txt", _fixture(), "no row for beta-plugin 1.0.0", hashes="")
        refused("a sha256 that differs from the row", _fixture(), "does not match",
                hashes=_row("beta-plugin", "1.0.0", _SHA_B))
        refused("rows for another artifact or version", _fixture(),
                "no row for beta-plugin 1.0.0",
                hashes="".join(_row(artifact, version, _SHA_A) for artifact, version in (
                    ("old-beta-plugin", "1.0.0"), ("beta-plugin-x", "1.0.0"),
                    ("beta", "1.0.0"), ("Beta-Plugin", "1.0.0"), ("beta-plugin", "1.0"),
                    ("beta-plugin", "1.0.0.1"), ("beta-plugin", "11.0.0"),
                    ("beta-plugin-1.0.0", "1.0.0"), ("1.0.0", "beta-plugin"))))
        refused("a row that is commented out", _fixture(), "no row for beta-plugin 1.0.0",
                hashes="# {0}#{0}".format(_row("beta-plugin", "1.0.0", _SHA_A)))
        refused("a row in the old file-name form", _fixture(), "no row for beta-plugin 1.0.0",
                hashes="{}  {}\n".format(_SHA_A, _ZIP))
        good_row = _row("beta-plugin", "1.0.0", _SHA_A)
        for label, row in (
                ("with a field missing", good_row.replace("  0000000", "")),
                ("with a field added", good_row.replace("\n", "  extra\n")),
                ("with no sha256: before the hash", good_row.replace("sha256:", "")),
                ("with a 65-character hash", good_row.replace("\n", "0\n")),
                ("with an uppercase hash", good_row.replace(_SHA_A, _SHA_A.upper())),
                ("that is a pre-release row with a short hash",
                 _row("beta-plugin", "1.0.0", _SHA_A[:-1], "pre-release") + good_row)):
            refused("a row " + label, _fixture(), "is not in the form", hashes=row)
        refused("a failed hashes lookup", _fixture(), "could not check the sha256",
                hashes=HashesError("lookup failed"))

        # Fetching hashes.txt: status codes and the one allowed redirect.
        def fetch(replies):
            calls = []

            def get(url):
                calls.append(url)
                reply = replies[len(calls) - 1]
                if isinstance(reply, Exception):
                    raise reply
                return reply

            try:
                return fetch_hashes(get), calls
            except HashesError as error:
                return error, calls

        body = _HASHES.encode("utf-8")
        result, calls = fetch([(200, None, body)])
        record("fetch accepts a direct 200", result == _HASHES and calls == [HASHES_URL],
               repr((result, calls)))
        for status in REDIRECT_STATUSES:
            result, calls = fetch([(status, HASHES_REDIRECT_URL, b""), (200, None, body)])
            record("fetch accepts a {} redirect to posluns.ca".format(status),
                   result == _HASHES and calls == [HASHES_URL, HASHES_REDIRECT_URL],
                   repr((result, calls)))
        for label, location in (
                ("to another host", "https://evil.example/hashes.txt"),
                ("to http", "http://posluns.ca/hashes.txt"),
                ("to another path", "https://posluns.ca/other.txt"),
                ("to a look-alike host", "https://posluns.ca.evil.example/hashes.txt"),
                ("with a query", HASHES_REDIRECT_URL + "?x=1"),
                ("with a relative target", "/hashes.txt"),
                ("with no target", None)):
            result, calls = fetch([(302, location, b""), (200, None, body)])
            record("fetch refuses a redirect " + label,
                   isinstance(result, HashesError) and calls == [HASHES_URL],
                   repr((result, calls)))
        result, calls = fetch([(301, HASHES_REDIRECT_URL, b""),
                               (301, HASHES_URL, b""), (200, None, body)])
        record("fetch refuses a second redirect",
               isinstance(result, HashesError) and len(calls) == 2, repr((result, calls)))
        for status in (204, 304, 403, 404, 500):
            result, calls = fetch([(status, None, b"")])
            record("fetch refuses HTTP {}".format(status),
                   isinstance(result, HashesError) and len(calls) == 1, repr((result, calls)))
        result, calls = fetch([(200, None, b"x" * (MAX_HASHES_BYTES + 1))])
        record("fetch refuses an oversized list", isinstance(result, HashesError), repr(result))
        result, calls = fetch([(200, None, b"\xff\xfe")])
        record("fetch refuses a list that is not UTF-8", isinstance(result, HashesError),
               repr(result))
        result, calls = fetch([HashesError("connection failed")])
        record("fetch reports a connection failure", isinstance(result, HashesError),
               repr(result))
        try:
            fetch_hashes()
            record("the self-test has no network access", False, "fetch_hashes returned")
        except HashesError as error:
            record("the self-test has no network access", "tried to use the network" in str(error),
                   str(error))

        # The command line, with a local fixture for the hashes lookup.
        with tempfile.TemporaryDirectory() as folder:
            market = Path(folder) / "marketplace.json"
            hashes_path = Path(folder) / "hashes.txt"
            hashes_path.write_text(_HASHES, encoding="utf-8")

            def command(document, hashes_file=hashes_path):
                market.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    status = main([str(market), "--hashes-file", str(hashes_file)])
                return status, out.getvalue()

            status, text = command(_fixture())
            record("command line passes the fixture",
                   status == 0 and "OK, 3 plugin(s) checked" in text
                   and "not the published list" in text, repr((status, text)))
            status, text = command(_changed(source + ("sha256",), _SHA_B))
            record("command line fails a wrong sha256",
                   status == 1 and "FAIL, 1 problem(s)" in text, repr((status, text)))
            status, text = command(_changed(("owner", "name"), "Someone Else"))
            record("command line fails a wrong owner name",
                   status == 1 and "FAIL, 1 problem(s)" in text
                   and '"owner.name" must be exactly "Jeff Posluns"' in text,
                   repr((status, text)))
            status, text = command(_fixture(), Path(folder) / "absent.txt")
            record("command line fails a missing hashes file",
                   status == 1 and "could not read" in text, repr((status, text)))
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                status = run_check(Path(folder) / "absent.json", hashes_path)
            record("command line fails a missing marketplace file",
                   status == 1 and "could not read the file" in out.getvalue(),
                   repr((status, out.getvalue())))
    finally:
        _https_get = real_get

    failed = [item for item in results if not item[1]]
    for name, passed, detail in results:
        print("{}  {}{}".format("ok  " if passed else "FAIL", name,
                                "" if passed else ": " + detail))
    print("self-test: {} passed, {} failed".format(len(results) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
