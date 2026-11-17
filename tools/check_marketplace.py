#!/usr/bin/env python3
"""Check .claude-plugin/marketplace.json for the jposluns plugin marketplace.

Python 3 standard library only. Run it from the repository root:

    python3 -I -B tools/check_marketplace.py               check the live file, with the
                                                           repository's README.md and SHA256SUMS
    python3 -I -B tools/check_marketplace.py FILE          check a copy of the file
    python3 -I -B tools/check_marketplace.py --self-test   test the checker (no network)

Options for a check: --hashes-file FILE reads the hashes list from a local
file. --readme FILE, --readme-base FILE and --sums-file FILE check the
checksums of rule 8 in those files. --print-checksums prints the checksums of
a file that passes, to paste into README.md and SHA256SUMS; the checker never
writes a file. --base FILE names the base branch's marketplace.json and turns
on rule 12; the pull request job passes it.

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
  7. Every entry is an archive source (owner ruling D-164). A github or
     git-subdir source is refused, pinned or not, after rules 4 and 5 have
     been applied to it. The one exception is an entry that equals a value
     of HELD_ENTRIES field for field (owner decision D-165): it passes with
     a note. HELD_ENTRIES is part of this file, so only a reviewed change to
     the checker can add to it.
  8. The checksums (owner ruling D-164). README.md holds one checksums block,
     from the line <!-- checksums:begin --> to the line <!-- checksums:end -->,
     equal to the block made from the file: the sha256 of the file itself,
     then the zip file name and sha256 of each entry. A held entry is listed
     as not pinned. With --readme-base, the README outside the block equals
     the base README outside its block. SHA256SUMS is the one line
     "<sha256>  .claude-plugin/marketplace.json".
  9. An entry holds only the fields name, description and source. Any other
     field is refused, so that an entry cannot carry plugin parts of its own
     (for example hooks or servers) that the sha256 of the zip does not cover.
 10. The top level holds only the fields name, owner, description, metadata
     and plugins. owner holds only name, email and url. metadata is an object
     that holds only description and version, both text. Any other field is
     refused, so that a pull request cannot add a field that no rule here
     judges.
 11. An archive entry is tied to its project by its name: the artifact in the
     zip file name is the entry name followed by "-plugin". The entry
     auditthis takes auditthis-plugin-<version>.zip, and no other project's
     zip.
 12. With --base FILE, the file is compared with the base branch's file.
     Every entry name of the base file is still in the file, so an entry is
     not removed or renamed. For an archive entry that is also an archive
     entry in the base file, the url host equals the base entry's host, and
     the version is not lower than the base entry's version. Two versions
     that differ must both be numbers with "." between them; 1.0 equals
     1.0.0. A new entry may use any allow-listed host. Without --base none of
     this is checked: the check of main after a merge has no base file.

What it does not check: it does not download a zip or clone a repository, so
it does not compare the entry name with the plugin's own plugin.json, and it
does not run "claude plugin validate". It does not check that the file has
its own row in hashes.txt; that row is added after the change is merged. It
finds a zip's row by the artifact and version in the file name alone; rule 11
ties the artifact to the entry name. It does not know what a project's digest
covers (the head of hashes.txt says), so it does not refuse a row whose
digest covers another file than the zip; the sha256 must still equal the
row's. Rule 12 compares the host of a url with the base file, not its path.

Any failure to read a file or to fetch hashes.txt counts as a problem.
Exit status: 0 when clean, 1 when there are problems, 2 for a usage error.
"""

import argparse
import contextlib
import hashlib
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
DEFAULT_README = DEFAULT_PATH.parent.parent / "README.md"
DEFAULT_SUMS = DEFAULT_PATH.parent.parent / "SHA256SUMS"

SOURCE_FIELDS = {
    "github": frozenset({"source", "repo", "ref", "sha"}),
    "git-subdir": frozenset({"source", "url", "path", "ref", "sha"}),
    "archive": frozenset({"source", "url", "sha256"}),
}
# Owner ruling D-164: every entry is an archive source pinned by sha256. The
# other source types stay in SOURCE_FIELDS so that rules 4 and 5 still report
# what is wrong with them; rule 7 then refuses them.
PINNED_SOURCE = "archive"
D164_PROBLEM = "every entry must be an archive source pinned by sha256"
# Owner decision D-165: the entries that rule 7 lets pass, by entry name. An
# entry is held only when it equals the value here field for field; any other
# entry of that name is judged by rule 7. The values hold text only, so "=="
# is exact. A held entry is reported in a note, and in the checksums block as
# not pinned. Empty means that no entry is held. A hold ends in one owner pull
# request: it replaces the entry in the list with its archive entry, removes
# the entry from this table and updates the README and SHA256SUMS.
HELD_ENTRIES = {
    "secureconfig": {
        "name": "secureconfig",
        "description": "The secureconfig plugin, from the plugin folder of the "
                       "jposluns/secureconfig repository.",
        "source": {"source": "git-subdir", "url": "jposluns/secureconfig", "path": "plugin",
                   "ref": "main"},
    },
}
HELD_NOTE = "held under owner decision D-165"
# Rule 9: the fields an entry may hold. Without this limit an entry could carry
# plugin parts of its own, which the sha256 of the zip does not cover.
ENTRY_FIELDS = frozenset({"name", "description", "source"})
ENTRY_FIELDS_PROBLEM = "an entry holds only name, description and source"
# Rule 10: the fields the top level may hold, and the fields of "metadata".
# "description" is here because the list holds it today; "$schema" is not,
# because the list does not hold it. Without this limit a pull request that
# changes only the list could add a top-level field that no rule here judges.
TOP_FIELDS = frozenset({"name", "owner", "description", "metadata", "plugins"})
TOP_FIELDS_PROBLEM = "the top level holds only name, owner, description, metadata and plugins"
METADATA_FIELDS = frozenset({"description", "version"})
METADATA_FIELDS_PROBLEM = '"metadata" holds only description and version'
OWNER_FIELDS = frozenset({"name", "email", "url"})
OWNER_FIELDS_PROBLEM = '"owner" holds only name, email and url'
# Rule 11: the artifact of an entry's zip is the entry name followed by this
# text, so that an entry cannot point at another project's zip.
ARTIFACT_SUFFIX = "-plugin"
# Rule 12: the comparison with the base branch's file (--base). The base file
# is not judged here; it must still be a list that can be compared with.
BASE_PROBLEM = ("base: the base branch's marketplace file is not a list whose entries each "
                "have a name of their own, so the file could not be compared with it")
BASE_REMOVED_PROBLEM = ("base: the entry {!r} of the base branch is not in the file; an entry "
                        "is not removed or renamed without the owner's review")

# Owner ruling D-164: the checksums that README.md and SHA256SUMS list.
CATALOGUE_NAME = ".claude-plugin/marketplace.json"
CHECKSUMS_BEGIN = "<!-- checksums:begin -->"
CHECKSUMS_END = "<!-- checksums:end -->"
MAX_TEXT_BYTES = 1024 * 1024

NAME_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/+-]*")
REPO_RE = re.compile(r"jposluns/([A-Za-z0-9._-]+)")
REPO_URL_RE = re.compile(r"https://github\.com/jposluns/([A-Za-z0-9._-]+?)(?:\.git)?")
ZIP_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.zip")
VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*")  # a version that rule 12 can put in order
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


def _version_key(version):
    """Return a key that puts versions in order, or None for a version with no order.

    A version has an order when it is numbers with "." between them. Each
    number counts as a number, whatever its length: 2.9.0 is lower than
    2.10.0. Zeros at the end do not count: 1.0 equals 1.0.0.
    """
    if not VERSION_RE.fullmatch(version):
        return None
    key = [(len(part.lstrip("0")), part.lstrip("0")) for part in version.split(".")]
    while key and key[-1] == (0, ""):
        key.pop()
    return key


def _base_entries(base_raw):
    """Return ({entry name: entry}, None) or (None, problem) for the base branch's file.

    Every entry must be an object with a text name that no other entry uses,
    or nothing can be compared with the file (rule 12).
    """
    document, problem = _parse_json(base_raw)
    plugins = None if problem or not isinstance(document, dict) else document.get("plugins")
    if not isinstance(plugins, list):
        return None, BASE_PROBLEM
    entries = {}
    for entry in plugins:
        name = entry.get("name") if isinstance(entry, dict) else None
        if not isinstance(name, str) or name in entries:
            return None, BASE_PROBLEM
        entries[name] = entry
    return entries, None


def _compare_with_base(url, version, base):
    """Return the rule 12 problems of an archive url and its version against a base entry.

    base is the base branch's entry of the same name, or None. An entry that
    is new, or that was not an archive entry in the base file, has nothing to
    be compared with: rule 6 holds its host to the allow-list.
    """
    base_source = base.get("source") if isinstance(base, dict) else None
    if not isinstance(base_source, dict) or base_source.get("source") != PINNED_SOURCE:
        return []
    file_name, url_problem = check_archive_url(base_source.get("url"))
    named = None if url_problem else split_archive_name(file_name)
    if not named:
        return ["the base branch's entry of this name has an archive url that cannot be read, "
                "so the host and the version could not be compared with it"]
    problems = []
    host = urllib.parse.urlsplit(url).netloc
    base_host = urllib.parse.urlsplit(base_source["url"]).netloc
    if host != base_host:
        problems.append('"url" host {!r} is not the host of this entry on the base branch, '
                        '{!r}; an entry stays on its host'.format(host, base_host))
    key, base_key = _version_key(version), _version_key(named[1])
    if version == named[1]:
        pass
    elif key is None or base_key is None:
        problems.append("version {} cannot be compared with the base branch's version {}: "
                        'both must be numbers with "." between them'.format(version, named[1]))
    elif key < base_key:
        problems.append("version {} is lower than the base branch's version {}; an entry does "
                        "not go back to an earlier version".format(version, named[1]))
    return problems


def _check_archive(source, label, problems, hashes, name=None, base=None):
    """Check an archive source.

    name is the entry name when it is in the accepted form, else None (rule
    11). base is the base branch's entry of that name, or None (rule 12).
    """
    file_name, url_problem = check_archive_url(source.get("url"))
    named = None if url_problem else split_archive_name(file_name)
    if not url_problem and not named:
        url_problem = ('"url" file name {} is not of the form <artifact>-<version>.zip (the '
                       'version is the last part after a "-" and starts with a digit)'.format(
                           file_name))
    if not url_problem and name is not None and named[0] != name + ARTIFACT_SUFFIX:
        url_problem = ('"url" file name {0} must be {1}{2}-<version>.zip: the artifact is the '
                       'entry name followed by "{2}"'.format(file_name, name, ARTIFACT_SUFFIX))
    if url_problem:
        problems.append("{}: {}".format(label, url_problem))
    else:
        problems.extend("{}: {}".format(label, text)
                        for text in _compare_with_base(source["url"], named[1], base))
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


def _is_held(entry):
    """True when an entry equals its HELD_ENTRIES value field for field (rule 7)."""
    name = entry.get("name")
    return isinstance(name, str) and name in HELD_ENTRIES and entry == HELD_ENTRIES[name]


def _check_source(source, label, problems, notes, hashes, held=False, name=None, base=None):
    if isinstance(source, str):
        problems.append("{}: a relative path source is not accepted; use an archive "
                        "source".format(label))
        return
    if not isinstance(source, dict):
        problems.append('{}: "source" must be an object'.format(label))
        return
    kind = source.get("source")
    if not isinstance(kind, str) or kind not in SOURCE_FIELDS:
        problems.append("{}: source type {!r} is not accepted; use an archive "
                        "source".format(label, kind))
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
        _check_archive(source, label, problems, hashes, name, base)
    if kind != PINNED_SOURCE and held:
        notes.append("{}: {}: a {} source, not pinned by sha256".format(label, HELD_NOTE, kind))
    elif kind != PINNED_SOURCE:
        problems.append("{}: a {} source is not accepted: {} that has a release row in "
                        "hashes.txt (owner ruling D-164)".format(label, kind, D164_PROBLEM))


def check_marketplace(raw, load_hashes, base_raw=None):
    """Check the bytes of a marketplace.json. Returns (problems, notes, plugin count).

    load_hashes is called at most once, and only when an archive entry needs it.
    It returns the text of the hashes list or raises HashesError. base_raw is
    the bytes of the base branch's marketplace.json, or None to leave rule 12
    out.
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
        extra = sorted(str(key) for key in set(document["owner"]) - OWNER_FIELDS)
        if extra:
            problems.append("{}; field(s) not accepted: {}".format(
                OWNER_FIELDS_PROBLEM, ", ".join(extra)))

    if "description" in document and not isinstance(document["description"], str):
        problems.append('"description" must be text')

    extra = sorted(str(key) for key in set(document) - TOP_FIELDS)
    if extra:
        problems.append("{}; field(s) not accepted: {}".format(
            TOP_FIELDS_PROBLEM, ", ".join(extra)))
    if "metadata" in document:
        metadata = document["metadata"]
        if not isinstance(metadata, dict):
            problems.append('"metadata" must be an object')
        else:
            extra = sorted(str(key) for key in set(metadata) - METADATA_FIELDS)
            if extra:
                problems.append("{}; field(s) not accepted: {}".format(
                    METADATA_FIELDS_PROBLEM, ", ".join(extra)))
            for key in sorted(METADATA_FIELDS):
                if key in metadata and not isinstance(metadata[key], str):
                    problems.append('"metadata.{}" must be text'.format(key))

    if "plugins" not in document:
        problems.append('missing required field "plugins"')
        return problems, notes, 0
    plugins = document["plugins"]
    if not isinstance(plugins, list):
        problems.append('"plugins" must be an array')
        return problems, notes, 0
    if not plugins:
        notes.append('"plugins" is empty')

    base_entries = {}
    if base_raw is not None:
        base_entries, problem = _base_entries(base_raw)
        if problem:
            base_entries = {}
            problems.append(problem)

    hashes = _Hashes(load_hashes)
    seen = set()
    for index, entry in enumerate(plugins):
        label = "plugins[{}]".format(index)
        if not isinstance(entry, dict):
            problems.append("{}: an entry must be an object".format(label))
            continue
        name = entry.get("name")
        tied = None
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
            tied = name
        extra = sorted(str(key) for key in set(entry) - ENTRY_FIELDS)
        if extra:
            problems.append("{}: {}; field(s) not accepted: {}".format(
                label, ENTRY_FIELDS_PROBLEM, ", ".join(extra)))
        if "description" in entry and not isinstance(entry["description"], str):
            problems.append('{}: "description" must be text'.format(label))
        if "source" not in entry:
            problems.append('{}: missing required field "source"'.format(label))
        else:
            _check_source(entry["source"], label, problems, notes, hashes, _is_held(entry),
                          tied, base_entries.get(tied))
    problems.extend(BASE_REMOVED_PROBLEM.format(name) for name in base_entries
                    if name not in seen)
    return problems, notes, len(plugins)


# --------------------------------------------------------------------------
# checksums (owner ruling D-164)
# --------------------------------------------------------------------------

def checksum_block(raw):
    """Return the README checksums block for the bytes of a marketplace.json.

    The block is a list of lines: the begin line, a table with the sha256 of
    the file itself and then the zip file name and sha256 of each entry in the
    file's order, and the end line. A held entry (HELD_ENTRIES) has no zip, so
    its line says that it is not pinned. Returns None when the block cannot be
    made: the file is not valid, or an entry that is not held lacks a name, an
    archive url or a sha256 in the accepted form. check_marketplace reports a
    problem for every such file.
    """
    document, problem = _parse_json(raw)
    if problem or not isinstance(document, dict):
        return None
    plugins = document.get("plugins")
    if not isinstance(plugins, list):
        return None
    rows = []
    for entry in plugins:
        if isinstance(entry, dict) and _is_held(entry):
            rows.append("| none | the `{}` plugin, {} | not pinned |".format(
                entry["name"], HELD_NOTE))
            continue
        source = entry.get("source") if isinstance(entry, dict) else None
        if not isinstance(source, dict) or source.get("source") != PINNED_SOURCE:
            return None
        name, sha256 = entry.get("name"), source.get("sha256")
        file_name, url_problem = check_archive_url(source.get("url"))
        if (url_problem or not isinstance(name, str) or not NAME_RE.fullmatch(name)
                or not isinstance(sha256, str) or not SHA256_RE.fullmatch(sha256)):
            return None
        rows.append("| `{}` | the `{}` plugin | `{}` |".format(file_name, name, sha256))
    first = "| `{}` | the marketplace file | `{}` |".format(
        CATALOGUE_NAME, hashlib.sha256(raw).hexdigest())
    return ([CHECKSUMS_BEGIN, "| File | What it is | SHA-256 |", "|---|---|---|", first]
            + rows + [CHECKSUMS_END])


def sums_line(raw):
    """Return the one line of SHA256SUMS for the bytes of a marketplace.json."""
    return "{}  {}\n".format(hashlib.sha256(raw).hexdigest(), CATALOGUE_NAME)


def _split_readme(text):
    """Return (lines before, block lines, lines after) for a README text.

    Returns None unless the text holds the begin line once and the end line
    once, as whole lines, with the begin line first.
    """
    lines = text.split("\n")
    if lines.count(CHECKSUMS_BEGIN) != 1 or lines.count(CHECKSUMS_END) != 1:
        return None
    begin, end = lines.index(CHECKSUMS_BEGIN), lines.index(CHECKSUMS_END)
    if begin > end:
        return None
    return lines[:begin], lines[begin:end + 1], lines[end + 1:]


def check_readme(text, block, base_text=None):
    """Return the problems of a README text against a checksums block.

    With base_text, the README must also equal the base README outside the
    block, so that a pull request can change the block and nothing else.
    """
    parts = _split_readme(text)
    if parts is None:
        return ['README: must hold one checksums block: the line "{}" once and, after it, '
                'the line "{}" once'.format(CHECKSUMS_BEGIN, CHECKSUMS_END)]
    problems = []
    if parts[1] != block:
        problems.append("README: the checksums block does not match the marketplace file; "
                        "replace it with the block that --print-checksums prints")
    if base_text is not None:
        base = _split_readme(base_text)
        if base is None:
            problems.append("README: the base README holds no single checksums block to "
                            "compare with")
        elif (parts[0], parts[2]) != (base[0], base[2]):
            problems.append("README: the text outside the checksums block differs from the "
                            "base README; that change needs the owner's review")
    return problems


def check_sums(body, raw):
    """Return the problems of the bytes of SHA256SUMS for a marketplace.json."""
    if body != sums_line(raw).encode("ascii"):
        return ['SHA256SUMS: must be the one line "<sha256>  {}" for the marketplace file; '
                "replace it with the line that --print-checksums prints".format(CATALOGUE_NAME)]
    return []


def _read_small(path, what):
    """Return (bytes, None) or (None, problem) for a small file."""
    try:
        with open(path, "rb") as handle:
            body = handle.read(MAX_TEXT_BYTES + 1)
    except OSError as error:
        return None, "{}: could not read {}: {}".format(what, path, error)
    if len(body) > MAX_TEXT_BYTES:
        return None, "{}: {} is larger than {} bytes".format(what, path, MAX_TEXT_BYTES)
    return body, None


def _read_text(path, what):
    """Return (text, None) or (None, problem) for a small UTF-8 file."""
    body, problem = _read_small(path, what)
    if problem:
        return None, problem
    try:
        return body.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "{}: {} is not UTF-8".format(what, path)


def check_checksums(raw, readme=None, readme_base=None, sums_file=None):
    """Check README.md and SHA256SUMS against the bytes of a marketplace.json.

    Each argument after raw is a path, or None to leave that check out.
    Returns the problems. A README is never passed unchecked: when the block
    cannot be made from the file, that is a problem here too.
    """
    problems = []
    if readme is not None:
        block = checksum_block(raw)
        text, problem = _read_text(readme, "README")
        base_text, base_problem = None, None
        if readme_base is not None:
            base_text, base_problem = _read_text(readme_base, "base README")
        if block is None:
            problems.append("README: the checksums block was not checked, because the "
                            "marketplace file has problems")
        elif problem or base_problem:
            problems.extend(text for text in (problem, base_problem) if text)
        else:
            problems.extend(check_readme(text, block, base_text))
    if sums_file is not None:
        body, problem = _read_small(sums_file, "SHA256SUMS")
        problems.extend([problem] if problem else check_sums(body, raw))
    return problems


# --------------------------------------------------------------------------
# command line
# --------------------------------------------------------------------------

def run_check(path, hashes_file=None, out=None, readme=None, readme_base=None,
              sums_file=None, print_checksums=False, base=None):
    out = out or sys.stdout
    used = []

    def load_hashes():
        if hashes_file is None:
            used.append(HASHES_URL)
            return fetch_hashes()
        used.append("local file {} (not the published list)".format(hashes_file))
        return read_hashes_file(hashes_file)

    print("check_marketplace: {}".format(path), file=out)
    compared = ()
    try:
        with open(path, "rb") as handle:
            raw = handle.read(MAX_MARKETPLACE_BYTES + 1)
    except OSError as error:
        problems, notes, count = ["could not read the file: {}".format(error)], [], 0
    else:
        base_raw, base_problem = (None, None) if base is None else _read_small(base, "base")
        problems, notes, count = check_marketplace(raw, load_hashes, base_raw)
        problems.extend([base_problem] if base_problem else [])
        problems.extend(check_checksums(raw, readme, readme_base, sums_file))
        compared = (("base list", base), ("readme", readme), ("base readme", readme_base),
                    ("sums file", sums_file))
        if print_checksums and not problems and checksum_block(raw) is None:
            problems.append("the checksums could not be made from the file")
    for source in used:
        print("hashes source: {}".format(source), file=out)
    for what, checked in compared:
        if checked is not None:
            print("{}: {}".format(what, checked), file=out)
    for note in notes:
        print("note: {}".format(note), file=out)
    for problem in problems:
        print("problem: {}".format(problem), file=out)
    if problems:
        print("check_marketplace: FAIL, {} problem(s)".format(len(problems)), file=out)
        return 1
    print("check_marketplace: OK, {} plugin(s) checked".format(count), file=out)
    if print_checksums:
        print("checksums block for README.md:", file=out)
        for line in checksum_block(raw):
            print(line, file=out)
        print("line for SHA256SUMS:", file=out)
        print(sums_line(raw), end="", file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check the jposluns plugin marketplace file.", allow_abbrev=False)
    parser.add_argument("path", nargs="?",
                        help="marketplace.json to check (default: the one in this repository)")
    parser.add_argument("--hashes-file", metavar="FILE",
                        help="read the hashes list from a local file instead of fetching it")
    parser.add_argument("--base", metavar="FILE",
                        help="the base branch's marketplace.json: refuse a removed or renamed "
                             "entry, another host for an entry and a lower version (rule 12)")
    parser.add_argument("--readme", metavar="FILE",
                        help="check the checksums block of this README against the file")
    parser.add_argument("--readme-base", metavar="FILE",
                        help="with --readme: the README must equal this base README outside "
                             "the checksums block")
    parser.add_argument("--sums-file", metavar="FILE",
                        help="check this SHA256SUMS against the file")
    parser.add_argument("--print-checksums", action="store_true",
                        help="print the README checksums block and the SHA256SUMS line of a "
                             "file that passes; README.md and SHA256SUMS are not checked")
    parser.add_argument("--self-test", action="store_true",
                        help="test the checker itself; uses no network")
    args = parser.parse_args(argv)
    checked = args.readme or args.readme_base or args.sums_file
    if args.self_test:
        if args.path or args.hashes_file or checked or args.print_checksums or args.base:
            parser.error("--self-test takes no other argument")
        return self_test()
    if args.readme_base and not args.readme:
        parser.error("--readme-base needs --readme")
    if args.print_checksums and checked:
        parser.error("--print-checksums takes no --readme, --readme-base or --sums-file")
    readme, sums_file = args.readme, args.sums_file
    if args.path is None and not args.print_checksums:
        # The live file is checked with the repository's own README.md and SHA256SUMS.
        readme, sums_file = readme or DEFAULT_README, sums_file or DEFAULT_SUMS
    return run_check(args.path or DEFAULT_PATH, args.hashes_file, readme=readme,
                     readme_base=args.readme_base, sums_file=sums_file,
                     print_checksums=args.print_checksums, base=args.base)


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

_SHA_A = "0123456789abcdef" * 4
_SHA_B = "fedcba9876543210" * 4
_COMMIT = "0123456789abcdef0123456789abcdef01234567"
_ZIP = "beta-plugin-1.0.0.zip"
_ZIP_URL = "https://posluns.dev/downloads/" + _ZIP
_ENTRY = 0
_DROP = object()
_OTHER_URL = "https://aiqt.ai/other-plugin-1.0.0.zip"
# Sources that owner ruling D-164 refuses. Rules 4 and 5 still apply to them.
_GIT_SOURCE = {"source": "git-subdir", "url": "jposluns/alpha", "path": "plugin", "ref": "main"}
_GITHUB_SOURCE = {"source": "github", "repo": "jposluns/gamma", "ref": "v1.0.0", "sha": _COMMIT}
# The secureconfig entry of the list before owner ruling D-164.
_OLD_SECURECONFIG = {
    "name": "secureconfig",
    "description": "The secureconfig plugin, from the plugin folder of the "
                   "jposluns/secureconfig repository.",
    "source": {"source": "git-subdir", "url": "jposluns/secureconfig", "path": "plugin",
               "ref": "main"}}


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
_SAMPLE_URL_2_13_0 = "https://auditthis.ai/downloads/auditthis-plugin-2.13.0.zip"
_SAMPLE_SKILL_URL = "https://auditthis.ai/downloads/auditthis-skill-2.14.0.zip"


def _sample(url=_SAMPLE_URL, sha256=_SAMPLE_SHA, name="auditthis"):
    """The fixture with its entry replaced by the auditthis entry, or one of another name."""
    return _changed(("plugins", _ENTRY), {"name": name, "source": {
        "source": "archive", "url": url, "sha256": sha256}})


def _fixture():
    """A file that passes: one archive entry, with its row in _HASHES."""
    return {
        "name": "jposluns",
        "owner": {"name": "Jeff Posluns"},
        "description": "Self-test fixture.",
        "plugins": [
            {"name": "beta", "description": "Fixture entry.",
             "source": {"source": "archive", "url": _ZIP_URL, "sha256": _SHA_A}},
        ],
    }


def _second(name="other", url=_OTHER_URL, sha256=_SHA_B):
    """The fixture with a second archive entry, which also has its row in _HASHES."""
    document = _fixture()
    document["plugins"].append({"name": name, "source": {
        "source": "archive", "url": url, "sha256": sha256}})
    return document


def _with(source, fields):
    """A copy of a source with fields replaced, or removed when the value is _DROP."""
    source = dict(source)
    for key, value in fields.items():
        if value is _DROP:
            del source[key]
        else:
            source[key] = value
    return source


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
    global _https_get, DEFAULT_PATH, DEFAULT_README, DEFAULT_SUMS, HELD_ENTRIES
    results = []

    def record(name, passed, detail=""):
        results.append((name, bool(passed), detail))

    def run(document, hashes=_HASHES, base=None):
        raw = document if isinstance(document, bytes) else json.dumps(document).encode("utf-8")
        if base is not None and not isinstance(base, bytes):
            base = json.dumps(base).encode("utf-8")
        calls = []

        def load():
            calls.append(1)
            if isinstance(hashes, Exception):
                raise hashes
            return hashes

        problems, notes, _count = check_marketplace(raw, load, base)
        return problems, notes, len(calls)

    def clean(name, document, hashes=_HASHES, lookups=None, note=None, base=None):
        problems, notes, calls = run(document, hashes, base)
        passed = not problems
        if lookups is not None:
            passed = passed and calls == lookups
        if note is not None:
            passed = passed and any(note in text for text in notes)
        record("accepts " + name, passed,
               "problems={} notes={} lookups={}".format(problems, notes, calls))

    def refused(name, document, fragment, hashes=_HASHES, d164=0, base=None):
        """One problem that holds the fragment, and d164 problems of owner ruling D-164."""
        problems, _notes, _calls = run(document, hashes, base)
        ruled = [text for text in problems if D164_PROBLEM in text]
        other = [text for text in problems if D164_PROBLEM not in text]
        record("refuses " + name,
               len(other) == 1 and fragment in other[0] and len(ruled) == d164,
               "wanted one problem holding {!r} and {} D-164 problem(s), got {}".format(
                   fragment, d164, problems))

    def ruled_out(name, document, labels, hashes=_HASHES, lookups=None, note=None):
        """Only D-164 problems: one for each label, in the order of the entries."""
        problems, notes, calls = run(document, hashes)
        passed = len(problems) == len(labels) and all(
            text.startswith(label + ": a ") and D164_PROBLEM in text and "D-164" in text
            for text, label in zip(problems, labels))
        if lookups is not None:
            passed = passed and calls == lookups
        if note is not None:
            passed = passed and any(note in text for text in notes)
        record("refuses " + name, passed,
               "wanted one D-164 problem for each of {}, got problems={} notes={} "
               "lookups={}".format(labels, problems, notes, calls))

    real_get = _https_get
    real_paths = DEFAULT_PATH, DEFAULT_README, DEFAULT_SUMS
    real_held = HELD_ENTRIES

    def no_network(url):
        raise HashesError("the self-test tried to use the network: {}".format(url))

    _https_get = no_network
    try:
        # No entry is held, whatever HELD_ENTRIES ships with, except in the
        # cases for owner decision D-165, which set their own.
        HELD_ENTRIES = {}
        entry = ("plugins", _ENTRY)
        source = entry + ("source",)
        where = "plugins[0] (beta)"

        def git(**fields):
            """The fixture with a git-subdir source in place of its archive source."""
            return _changed(source, _with(_GIT_SOURCE, fields))

        def hub(**fields):
            """The fixture with a github source in place of its archive source."""
            return _changed(source, _with(_GITHUB_SOURCE, fields))

        # Files that pass.
        clean("the fixture", _fixture(), lookups=1)
        clean("two archive entries with one hashes lookup", _second(), lookups=1)
        clean("an empty plugins array, with a note", _changed(("plugins",), []),
              lookups=0, note="empty")
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
        refused("an entry that is text", _changed(entry, "beta"), "must be an object")
        refused("an entry without a name", _changed(entry + ("name",)),
                'plugins[0]: missing required field "name"')
        refused("an entry without a source", _changed(source),
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

        # Rule 10: owner holds only name, email and url.
        record("the accepted owner fields are name, email and url",
               OWNER_FIELDS == {"name", "email", "url"}, repr(sorted(OWNER_FIELDS)))
        clean("an owner with a name, an email and a url", _changed(("owner",), {
            "name": OWNER_NAME, "email": "owner@example.test", "url": "https://posluns.dev"}))
        for field, value in (("hooks", {}), ("Name", OWNER_NAME), ("plugins", []),
                             ("homepage", "https://posluns.dev"), ("x", None)):
            refused("the owner field {!r}".format(field), _changed(("owner", field), value),
                    '"owner" holds only name, email and url; field(s) not accepted: ' + field)
        refused("two owner fields that are not accepted, as one problem that names both",
                _changed(("owner",), {"name": OWNER_NAME, "x": 1, "hooks": {}}),
                "field(s) not accepted: hooks, x")
        document = _changed(("owner", "x"), 1)
        document["x"] = 1
        problems, _notes, _calls = run(document)
        record("reports the same field in the owner and at the top level as two problems",
               len(problems) == 2 and problems[0].startswith('"owner" holds only')
               and problems[1].startswith("the top level holds only"), repr(problems))

        # Names.
        for bad in ("Alpha", "al pha", "alpha_1", "-alpha", "alpha-", "alpha--one", "alpha.one",
                    "", 7):
            refused("the entry name {!r}".format(bad), _changed(entry + ("name",), bad),
                    "lowercase letters, digits and single hyphens")
        refused("a name used twice", _second("beta", _ZIP_URL, _SHA_A), "already used")

        # Source types and fields.
        refused("a relative path source", _changed(source, "./plugins/alpha"), "relative path")
        for kind in ("npm", "url", "command", None, ["github"]):
            refused("the source type {!r}".format(kind), _changed(source, {"source": kind}),
                    "is not accepted")
        refused("an unknown source field", _changed(source + ("ref",), "main"),
                "unknown field(s): ref")

        # Rule 9: an entry holds only name, description and source.
        for field, value in (
                ("hooks", {"PreToolUse": []}), ("mcpServers", {"x": {"command": "x"}}),
                ("lspServers", {}), ("commands", ["./commands"]), ("agents", "./agents"),
                ("skills", "./skills"), ("strict", False), ("version", "1.0.0"),
                ("author", {"name": "x"}), ("homepage", "https://posluns.dev"),
                ("category", "x"), ("Name", "beta"), ("sha256", _SHA_A), ("x", None)):
            refused("the entry field {!r}".format(field), _changed(entry + (field,), value),
                    where + ": an entry holds only name, description and source; field(s) "
                    "not accepted: " + field)
        document = _changed(entry + ("hooks",), {})
        document["plugins"][_ENTRY]["agents"] = []
        refused("two entry fields that are not accepted, as one problem that names both",
                document, "field(s) not accepted: agents, hooks")
        document = _second()
        document["plugins"][1]["strict"] = False
        refused("an entry field that is not accepted in the second entry", document,
                "plugins[1] (other): an entry holds only")
        document = git()
        document["plugins"][_ENTRY]["hooks"] = {}
        refused("an entry field that is not accepted in a git-subdir entry, as two problems",
                document, "field(s) not accepted: hooks", d164=1)

        # Rule 10: the top level holds only name, owner, description, metadata and
        # plugins, and metadata holds only description and version.
        record("the accepted top-level fields are name, owner, description, metadata and "
               "plugins", TOP_FIELDS == {"name", "owner", "description", "metadata", "plugins"},
               repr(sorted(TOP_FIELDS)))
        record("the accepted metadata fields are description and version",
               METADATA_FIELDS == {"description", "version"}, repr(sorted(METADATA_FIELDS)))
        for field, value in (
                ("$schema", "https://example.test/marketplace.schema.json"),
                ("version", "1.0.0"), ("hooks", {"PreToolUse": []}),
                ("mcpServers", {"x": {"command": "x"}}), ("pluginRoot", "./plugins"),
                ("strict", False), ("Name", "jposluns"), ("Plugins", []), ("x", None)):
            refused("the top-level field {!r}".format(field), _changed((field,), value),
                    "the top level holds only name, owner, description, metadata and plugins; "
                    "field(s) not accepted: " + field)
        document = _changed(("hooks",), {})
        document["version"] = "1.0.0"
        refused("two top-level fields that are not accepted, as one problem that names both",
                document, "field(s) not accepted: hooks, version")
        document = _changed(("plugins",))
        document["hooks"] = {}
        problems, _notes, _calls = run(document)
        record("reports a top-level field that is not accepted and no plugins as two problems",
               len(problems) == 2 and "field(s) not accepted: hooks" in problems[0]
               and 'required field "plugins"' in problems[1], repr(problems))
        document = _changed(entry + ("hooks",), {})
        document["hooks"] = {}
        problems, _notes, _calls = run(document)
        record("reports the same field at the top level and in an entry as two problems",
               len(problems) == 2 and problems[0].startswith("the top level holds only")
               and problems[1].startswith(where + ": an entry holds only"), repr(problems))
        refused("a top-level description that is not text", _changed(("description",), 7),
                '"description" must be text')
        clean("a file with no top-level description", _changed(("description",)), lookups=1)
        for name, value in (
                ("an empty metadata", {}),
                ("a metadata description", {"description": "Self-test fixture."}),
                ("a metadata version", {"version": "2"}),
                ("a metadata description and version",
                 {"description": "Self-test fixture.", "version": "1.0.0"})):
            clean(name, _changed(("metadata",), value), lookups=1)
        for bad in ("1.0.0", 7, None, True, ["version"]):
            refused("the metadata {!r}".format(bad), _changed(("metadata",), bad),
                    '"metadata" must be an object')
        for field, value in (("pluginRoot", "./plugins"), ("hooks", {}), ("Version", "1"),
                             ("plugins", [])):
            refused("the metadata field {!r}".format(field),
                    _changed(("metadata",), {field: value}),
                    '"metadata" holds only description and version; field(s) not accepted: '
                    + field)
        refused("two metadata fields that are not accepted, as one problem that names both",
                _changed(("metadata",), {"pluginRoot": ".", "hooks": {}, "version": "1"}),
                "field(s) not accepted: hooks, pluginRoot")
        for key in ("description", "version"):
            for bad in (7, None, ["x"], {"x": "y"}):
                refused("the metadata {} {!r}".format(key, bad),
                        _changed(("metadata",), {key: bad}),
                        '"metadata.{}" must be text'.format(key))

        # Owner ruling D-164: every entry is an archive source pinned by sha256.
        ruled_out("a git-subdir source on a branch, with no hashes lookup and a note that "
                  "it is not pinned", git(), [where], lookups=0,
                  note=where + ": the source is not pinned")
        ruled_out("a git-subdir source pinned to a sha", git(sha=_COMMIT), [where], lookups=0)
        ruled_out("a git-subdir https URL with a sha and no ref", _changed(source, {
            "source": "git-subdir", "url": "https://github.com/jposluns/alpha.git",
            "path": "plugins/alpha", "sha": _COMMIT}), [where])
        ruled_out("a github source pinned to a tag and a sha", hub(), [where], lookups=0)
        ruled_out("a github source with no ref or sha, with a note", _changed(source, {
            "source": "github", "repo": "jposluns/gamma"}), [where], note=where)
        document = _second()
        document["plugins"].insert(1, {"name": "alpha", "source": dict(_GIT_SOURCE)})
        document["plugins"].append({"name": "gamma", "source": dict(_GITHUB_SOURCE)})
        ruled_out("a git-subdir entry and a github entry among archive entries, which are "
                  "still looked up", document,
                  ["plugins[1] (alpha)", "plugins[3] (gamma)"], lookups=1)
        document = _sample()
        document["plugins"].insert(0, dict(_OLD_SECURECONFIG))
        ruled_out("the secureconfig entry of the list before D-164 (git-subdir, branch main, "
                  "no sha), beside the auditthis entry", document,
                  ["plugins[0] (secureconfig)"], hashes=_SAMPLE, lookups=1,
                  note="plugins[0] (secureconfig): the source is not pinned")
        refused("an archive source with a wrong sha256 beside a git-subdir entry, as two "
                "problems", document, "does not match the hashes.txt release row",
                hashes=_SAMPLE.replace(_SAMPLE_SHA, _SAMPLE_SHA_2_13_0), d164=1)

        # Owner decision D-165: an entry that equals a HELD_ENTRIES value field for
        # field passes rule 7 with a note. Any other entry of that name does not.
        held = {"name": "beta", "description": "Fixture entry.", "source": dict(_GIT_SOURCE)}
        held_note = where + ": held under owner decision D-165: a git-subdir source"
        HELD_ENTRIES = {"beta": held}
        clean("a held git-subdir entry, with a note and no hashes lookup", git(), lookups=0,
              note=held_note)
        clean("an archive entry under a held name", _fixture(), lookups=1)
        document = _second()
        document["plugins"][_ENTRY] = dict(held)
        clean("a held entry beside an archive entry, which is still looked up", document,
              lookups=1, note=held_note)
        document = git()
        document["plugins"].append(dict(held))
        refused("a held entry twice", document, "already used")
        for name, document in (
                ("another ref", git(ref="dev")),
                ("a sha beside the ref", git(sha=_COMMIT)),
                ("no ref", git(ref=_DROP)),
                ("another path", git(path="plugins/beta")),
                ("the https form of the same repository",
                 git(url="https://github.com/jposluns/alpha")),
                ("a github source", hub())):
            ruled_out("an entry of a held name with " + name, document, [where])
        document = git()
        document["plugins"][_ENTRY]["description"] = "Another text."
        ruled_out("an entry of a held name with another description", document, [where])
        document = git()
        del document["plugins"][_ENTRY]["description"]
        ruled_out("an entry of a held name without its description", document, [where])
        document = git()
        document["plugins"][_ENTRY]["name"] = "alpha"
        ruled_out("a held entry under another name", document, ["plugins[0] (alpha)"])
        document = git()
        document["plugins"][_ENTRY]["hooks"] = {}
        refused("a held entry with one more field, as two problems", document,
                "field(s) not accepted: hooks", d164=1)
        HELD_ENTRIES = {"secureconfig": dict(_OLD_SECURECONFIG)}
        document = _sample()
        document["plugins"].insert(0, dict(_OLD_SECURECONFIG))
        clean("the secureconfig entry of the list before D-164 when it is held, beside the "
              "auditthis entry", document, hashes=_SAMPLE, lookups=1,
              note="plugins[0] (secureconfig): held under owner decision D-165")
        HELD_ENTRIES = real_held
        shipped = []
        for name, item in sorted(real_held.items()):
            problems, notes, _calls = run(_changed(("plugins",), [item]))
            shipped.append((name, problems, item.get("name") == name and not problems
                            and any(HELD_NOTE in text for text in notes)))
        record("each entry that HELD_ENTRIES ships with ({}) is held under its own name and "
               "has no problem".format(", ".join(sorted(real_held)) or "none"),
               all(passed for _name, _problems, passed in shipped), repr(shipped))
        HELD_ENTRIES = {}

        # github and git-subdir sources: rules 4 and 5 still report what is wrong
        # with them, and owner ruling D-164 refuses each of them as well.
        for bad in ("someone/gamma", "jposluns/", "jposluns/gamma/extra", "Jposluns/gamma",
                    "https://github.com/jposluns/gamma", "jposluns/..", None):
            refused("the github repo {!r}".format(bad), hub(repo=bad), '"repo" is required',
                    d164=1)
        for bad in ("someone/alpha", "https://github.com/someone/alpha",
                    "https://gitlab.com/jposluns/alpha", "http://github.com/jposluns/alpha",
                    "https://github.com.evil.example/jposluns/alpha",
                    "https://evil.example/github.com/jposluns/alpha",
                    "git@github.com:jposluns/alpha.git", None):
            refused("the git-subdir url {!r}".format(bad), git(url=bad), '"url" is required',
                    d164=1)
        for bad in ("../plugin", "/plugin", "plugin/../..", "plugin//x", "plugin\\x", "", None):
            refused("the git-subdir path {!r}".format(bad), git(path=bad), '"path"', d164=1)
        refused("a git-subdir source without a path", git(path=_DROP), '"path"', d164=1)
        for bad in ("abc123", _COMMIT.upper(), _COMMIT + "0", 40):
            refused("the sha {!r}".format(bad), hub(sha=bad), '"sha" must be', d164=1)
        for bad in ("", "-x", "two words", None):
            refused("the ref {!r}".format(bad), hub(ref=bad), '"ref" must be', d164=1)
        refused("an unknown field in a github source", hub(path="plugin"),
                "unknown field(s): path", d164=1)

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

        # Rule 11: the artifact in the zip file name is the entry name and "-plugin".
        record('the artifact of an entry is its name followed by "-plugin"',
               ARTIFACT_SUFFIX == "-plugin", repr(ARTIFACT_SUFFIX))
        tied = "must be beta-plugin-<version>.zip"
        for name in ("gamma-plugin-1.0.0.zip", "beta-1.0.0.zip", "beta-skill-1.0.0.zip",
                     "beta-plugin-x-1.0.0.zip", "xbeta-plugin-1.0.0.zip",
                     "Beta-plugin-1.0.0.zip", "beta_plugin-1.0.0.zip", "plugin-1.0.0.zip"):
            refused("the zip {} under the entry name beta, even with a row of its own that "
                    "holds the entry's sha256".format(name),
                    _changed(source + ("url",), "https://posluns.dev/downloads/" + name), tied,
                    hashes=_HASHES + _row(split_archive_name(name)[0], "1.0.0", _SHA_A))
        problems, _notes, calls = run(_changed(source, {
            "source": "archive", "url": _OTHER_URL, "sha256": _SHA_B}))
        record("refuses the zip and sha256 of another entry under the entry name beta, with no "
               "hashes lookup", len(problems) == 1 and tied in problems[0] and calls == 0,
               repr((problems, calls)))
        clean("an entry name with a hyphen and a digit, with the zip of that name",
              _changed(entry, {"name": "tool-2", "source": {
                  "source": "archive", "url": "https://posluns.dev/tool-2-plugin-1.0.zip",
                  "sha256": _SHA_A}}),
              hashes=_row("tool-2-plugin", "1.0", _SHA_A), lookups=1)
        refused("the entry name beta-plugin with the zip of beta",
                _changed(entry + ("name",), "beta-plugin"),
                "must be beta-plugin-plugin-<version>.zip")
        refused("the published auditthis-skill 2.14.0 zip and sha256 under the entry name "
                "auditthis", _sample(url=_SAMPLE_SKILL_URL, sha256=_SAMPLE_SHA_SKILL),
                "must be auditthis-plugin-<version>.zip", hashes=_SAMPLE)
        refused("the published aiqt 1.0.0 zip and sha256 under the entry name auditthis",
                _sample(url=_SAMPLE_PRE_URL, sha256=_SAMPLE_PRE_SHA),
                "must be auditthis-plugin-<version>.zip", hashes=_SAMPLE)
        refused("the published aiqt 1.0.0 zip under the entry name aiqt: the artifact is not "
                "aiqt-plugin", _sample(url=_SAMPLE_PRE_URL, sha256=_SAMPLE_PRE_SHA, name="aiqt"),
                "must be aiqt-plugin-<version>.zip", hashes=_SAMPLE)

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
        got = rows_for_release(_SAMPLE, "aiqt", "1.0.0")
        record("a pre-release row only: the published aiqt 1.0.0 row gives no release digest",
               got == ([], ["pre-release"]), repr(got))
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

        # Rule 12: the comparison with the base branch's file, with the published rows.
        lower = "is lower than the base branch's version"
        clean("a file that equals its base file", _sample(), hashes=_SAMPLE, lookups=1,
              base=_sample())
        clean("a later version than the base file's", _sample(), hashes=_SAMPLE,
              base=_sample(_SAMPLE_URL_2_13_0, _SAMPLE_SHA_2_13_0))
        refused("an earlier version than the base file's, with the sha256 of its own row",
                _sample(_SAMPLE_URL_2_13_0, _SAMPLE_SHA_2_13_0),
                "version 2.13.0 " + lower + " 2.14.0", hashes=_SAMPLE, base=_sample())
        clean("that earlier version when no base file is given",
              _sample(_SAMPLE_URL_2_13_0, _SAMPLE_SHA_2_13_0), hashes=_SAMPLE)

        # Rule 12: the order of versions.
        for low, high in (("2.9.0", "2.10.0"), ("2.14.0", "2.14.1"), ("2.14.9", "3"),
                          ("1.0.15", "1.1"), ("0.9", "1.0"), ("1.0", "1.0.1"), ("1", "1.0.0.1"),
                          ("09", "10")):
            keys = _version_key(low), _version_key(high)
            record("version {} is lower than {}".format(low, high),
                   None not in keys and keys[0] < keys[1] and not keys[1] < keys[0], repr(keys))
        keys = _version_key("9" * 5000), _version_key("1" + "0" * 5000)
        record("a version number of 5000 digits is lower than one of 5001 digits",
               None not in keys and keys[0] < keys[1], "the keys are not in that order")
        for one, other in (("1.0", "1.0.0"), ("1.01", "1.1"), ("0", "0.0"), ("2.14.0", "2.14.0")):
            keys = _version_key(one), _version_key(other)
            record("version {} equals {}".format(one, other),
                   None not in keys and keys[0] == keys[1], repr(keys))
        for bad in ("1.0.0b", "1.0rc1", "1..0", "1.", ".1", "1_0", "1.x", "v1", ""):
            record("version {!r} has no order".format(bad), _version_key(bad) is None,
                   repr(_version_key(bad)))

        # Rule 12: the comparison with the base branch's file, with made-up rows.
        def beta(version, host="posluns.dev"):
            """The fixture with another version or host for its zip."""
            return _changed(source + ("url",), "https://{}/downloads/beta-plugin-{}.zip".format(
                host, version))

        rows = _HASHES + "".join(_row("beta-plugin", version, _SHA_A)
                                 for version in ("0.9.0", "1.0", "1.0.0b", "2.0.0"))
        another_host = "is not the host of this entry on the base branch"
        no_order = "cannot be compared with the base branch's version"
        clean("version 2.0.0 after the base file's 1.0.0", beta("2.0.0"), hashes=rows,
              base=_fixture())
        clean("version 1.0 after the base file's 1.0.0, which it equals", beta("1.0"),
              hashes=rows, base=_fixture())
        refused("version 0.9.0 after the base file's 1.0.0", beta("0.9.0"),
                "version 0.9.0 " + lower + " 1.0.0", hashes=rows, base=_fixture())
        refused("version 1.0.0 after the base file's 2.0.0", _fixture(),
                "version 1.0.0 " + lower + " 2.0.0", base=beta("2.0.0"))
        refused("a version with no order after the base file's 1.0.0", beta("1.0.0b"),
                "version 1.0.0b " + no_order + " 1.0.0", hashes=rows, base=_fixture())
        refused("version 2.0.0 after a base file's version with no order", beta("2.0.0"),
                "version 2.0.0 " + no_order + " 1.0.0b", hashes=rows, base=beta("1.0.0b"))
        clean("a version with no order that the base file also names", beta("1.0.0b"),
              hashes=rows, base=beta("1.0.0b"))
        for host in sorted(ARCHIVE_HOSTS - {"posluns.dev"}):
            refused("a move of an entry from posluns.dev to " + host, beta("1.0.0", host),
                    another_host, base=_fixture())
        refused("a move of an entry from auditthis.ai to posluns.dev", _fixture(), another_host,
                base=beta("1.0.0", "auditthis.ai"))
        problems, _notes, _calls = run(beta("0.9.0", "posluns.ca"), rows, _fixture())
        record("reports another host and a lower version as two problems",
               len(problems) == 2 and another_host in problems[0] and lower in problems[1]
               and all(text.startswith(where + ": ") for text in problems), repr(problems))
        problems, _notes, _calls = run(_changed(source + ("sha256",), _SHA_B), rows,
                                       beta("2.0.0"))
        record("reports a lower version and a wrong sha256 as two problems",
               len(problems) == 2 and lower in problems[0] and "does not match" in problems[1],
               repr(problems))

        # Rule 12: new, removed and renamed entries.
        removed = "of the base branch is not in the file"
        clean("a new entry on an allow-listed host beside the base file's entry", _second(),
              lookups=1, base=_fixture())
        refused("a new entry on a host that is not allow-listed",
                _second(url="https://evil.example/other-plugin-1.0.0.zip"), "allow-list",
                base=_fixture())
        clean("any entry when the base file has no entry", _fixture(),
              base=_changed(("plugins",), []))
        refused("a file without an entry of the base file", _fixture(),
                "base: the entry 'other' " + removed, base=_second())
        refused("a renamed entry, with the zip of its new name",
                _changed(entry, {"name": "gamma", "source": {
                    "source": "archive", "url": "https://posluns.dev/gamma-plugin-1.0.0.zip",
                    "sha256": _SHA_A}}),
                "base: the entry 'beta' " + removed,
                hashes=_row("gamma-plugin", "1.0.0", _SHA_A), base=_fixture())
        problems, _notes, _calls = run(_changed(("plugins",), []), base=_second())
        record("reports each entry of the base file that an empty list lacks, in the base "
               "file's order", len(problems) == 2 and "'beta' " + removed in problems[0]
               and "'other' " + removed in problems[1], repr(problems))
        problems, _notes, _calls = run(_changed(entry + ("name",), "Beta"), base=_fixture())
        record("reports an entry name in another case as a name problem and a removed entry",
               len(problems) == 2 and "lowercase letters" in problems[0]
               and "'beta' " + removed in problems[1], repr(problems))
        document = _second()
        document["plugins"].reverse()
        clean("the base file's entries in another order", document, lookups=1, base=_second())
        only_other = _changed(("plugins",), _second()["plugins"][1:])
        HELD_ENTRIES = {"beta": held}
        clean("a held entry that the base file also holds", git(), lookups=0, note=held_note,
              base=git())
        clean("an archive entry in place of the base file's held entry", _fixture(), lookups=1,
              base=git())
        refused("a file without the base file's held entry", only_other,
                "base: the entry 'beta' " + removed, base=git())
        HELD_ENTRIES = {}
        clean("an archive entry in place of a git-subdir entry of the base file that is not "
              "held", _fixture(), lookups=1, base=git())

        # Rule 12: a base file that cannot be compared with.
        for name, base in (
                ("that is broken JSON", b"{"),
                ("that is a top-level array", b"[]"),
                ("that starts with a byte order mark", b"\xef\xbb\xbf" + good),
                ("with no plugins", _changed(("plugins",))),
                ("with plugins that is an object", _changed(("plugins",), {})),
                ("with an entry that is text", _changed(entry, "beta")),
                ("with an entry without a name", _changed(entry + ("name",))),
                ("with an entry name that is a number", _changed(entry + ("name",), 7)),
                ("with a name used twice", _second("beta", _ZIP_URL, _SHA_A))):
            refused("a base file " + name, _fixture(),
                    "base: the base branch's marketplace file is not a list", base=base)
        for name, value in (
                ("on a host that is not allow-listed", "https://evil.example/" + _ZIP),
                ("with no version in its file name", "https://posluns.dev/beta-plugin.zip"),
                ("that is not text", None)):
            refused("a base entry with an archive url " + name, _fixture(),
                    where + ": the base branch's entry of this name has an archive url that "
                    "cannot be read", base=_changed(source + ("url",), value))

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

        # The checksums (owner ruling D-164): the block made from the file.
        raw = (json.dumps(_second(), indent=2) + "\n").encode("utf-8")
        digest = hashlib.sha256(raw).hexdigest()
        block = checksum_block(raw)
        record("the checksums block lists the file, then each entry in the file's order",
               block == [
                   "<!-- checksums:begin -->",
                   "| File | What it is | SHA-256 |",
                   "|---|---|---|",
                   "| `.claude-plugin/marketplace.json` | the marketplace file | `{}` |".format(
                       digest),
                   "| `beta-plugin-1.0.0.zip` | the `beta` plugin | `{}` |".format(_SHA_A),
                   "| `other-plugin-1.0.0.zip` | the `other` plugin | `{}` |".format(_SHA_B),
                   "<!-- checksums:end -->"], repr(block))
        longer = checksum_block(raw + b"\n")
        record("one more byte in the file changes the block's line for the file, and no other",
               longer is not None and longer[3] != block[3]
               and longer[:3] + longer[4:] == block[:3] + block[4:], repr(longer))
        record("the SHA256SUMS line names the file after its sha256",
               sums_line(raw) == digest + "  .claude-plugin/marketplace.json\n",
               repr(sums_line(raw)))
        document = _second()
        document["plugins"][_ENTRY] = dict(held)
        held_raw = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        HELD_ENTRIES = {"beta": held}
        held_block = checksum_block(held_raw)
        HELD_ENTRIES = {}
        record("the checksums block lists a held entry as not pinned",
               held_block == block[:3] + [
                   "| `.claude-plugin/marketplace.json` | the marketplace file | `{}` |".format(
                       hashlib.sha256(held_raw).hexdigest()),
                   "| none | the `beta` plugin, held under owner decision D-165 | not pinned |",
                   block[5], block[6]], repr(held_block))
        record("no checksums block for the same file when no entry is held",
               checksum_block(held_raw) is None)
        for name, document in (
                ("a git-subdir entry", git()),
                ("a github entry", hub()),
                ("a relative path source", _changed(source, "./plugins/alpha")),
                ("an entry without a sha256", _changed(source + ("sha256",))),
                ("an entry with an uppercase sha256",
                 _changed(source + ("sha256",), _SHA_A.upper())),
                ("an archive url on another host",
                 _changed(source + ("url",), "https://evil.example/" + _ZIP)),
                ("an entry without a name", _changed(entry + ("name",))),
                ("an entry name with a backtick", _changed(entry + ("name",), "be`ta")),
                ("an entry that is text", _changed(entry, "beta")),
                ("plugins that is an object", _changed(("plugins",), {})),
                ("no plugins", _changed(("plugins",)))):
            made = checksum_block(json.dumps(document).encode("utf-8"))
            problems, _notes, _calls = run(document)
            record("no checksums block for {}, which the check also refuses".format(name),
                   made is None and bool(problems), repr((made, problems)))
        for name, body in (("broken JSON", b"{"), ("a top-level array", b"[]"),
                           ("a byte order mark", b"\xef\xbb\xbf" + raw)):
            record("no checksums block for " + name, checksum_block(body) is None)

        # The checksums: the README block.
        readme = "# Title\n\nSome text.\n\n" + "\n".join(block) + "\n\nMore text.\n"
        older = readme.replace(digest, "0" * 64)
        one_block = "must hold one checksums block"
        stale = "does not match the marketplace file"
        outside = "outside the checksums block"
        for name, text, base, wanted in (
                ("accepts the block", readme, None, []),
                ("accepts the block when the base README has an older block and the same text "
                 "outside it", readme, older, []),
                ("refuses an older sha256 for the file", older, None, [stale]),
                ("refuses another sha256 for a zip", readme.replace(_SHA_B, _SHA_A), None,
                 [stale]),
                ("refuses a block with a row missing", readme.replace(block[5] + "\n", ""), None,
                 [stale]),
                ("refuses a block with a row added",
                 readme.replace(block[5], block[5] + "\n" + block[4]), None, [stale]),
                ("refuses a block with its rows in another order",
                 readme.replace(block[4] + "\n" + block[5], block[5] + "\n" + block[4]), None,
                 [stale]),
                ("refuses a block with a blank line in it",
                 readme.replace(block[4], block[4] + "\n"), None, [stale]),
                ("refuses a block with text after a row",
                 readme.replace(block[5], block[5] + " x"), None, [stale]),
                ("refuses a README with no block", "# Title\n", None, [one_block]),
                ("refuses a README with two blocks", readme + "\n".join(block) + "\n", None,
                 [one_block]),
                ("refuses a README with no end line", readme.replace(CHECKSUMS_END, ""), None,
                 [one_block]),
                ("refuses a README with the end line before the begin line",
                 "\n".join([CHECKSUMS_END] + block[1:-1] + [CHECKSUMS_BEGIN]) + "\n", None,
                 [one_block]),
                ("refuses a begin line with a space after it",
                 readme.replace(CHECKSUMS_BEGIN, CHECKSUMS_BEGIN + " "), None, [one_block]),
                ("refuses an indented end line",
                 readme.replace(CHECKSUMS_END, "  " + CHECKSUMS_END), None, [one_block]),
                ("refuses CRLF line ends", readme.replace("\n", "\r\n"), None, [one_block]),
                ("refuses changed text after the block, with a base README",
                 readme.replace("More text.", "Other text."), readme, [outside]),
                ("refuses changed text before the block, with a base README",
                 readme.replace("Some text.", "Other text."), older, [outside]),
                ("refuses a line added after the block, with a base README",
                 readme + "One more line.\n", readme, [outside]),
                ("does not compare the text outside the block without a base README",
                 readme.replace("More text.", "Other text."), None, []),
                ("refuses a base README with no block", readme, "# Title\n",
                 ["base README holds no single checksums block"]),
                ("reports an older block and changed text outside it as two problems",
                 older.replace("More text.", "Other text."), readme, [stale, outside])):
            problems = check_readme(text, block, base)
            record("README: " + name,
                   len(problems) == len(wanted) and all(
                       fragment in problem for fragment, problem in zip(wanted, problems)),
                   "wanted {}, got {}".format(wanted, problems))

        # The checksums: SHA256SUMS.
        good_sums = sums_line(raw).encode("ascii")
        record("SHA256SUMS: accepts the one line", check_sums(good_sums, raw) == [],
               repr(check_sums(good_sums, raw)))
        for name, body in (
                ("without its final newline", good_sums[:-1]),
                ("with a CRLF line end", good_sums[:-1] + b"\r\n"),
                ("twice", good_sums + good_sums),
                ("with a blank line after it", good_sums + b"\n"),
                ("in binary mode", good_sums.replace(b"  .", b" *.")),
                ("with one space", good_sums.replace(b"  .", b" .")),
                ("with another file name", good_sums.replace(b".claude-plugin/", b"")),
                ("with another sha256", (_SHA_A + "  " + CATALOGUE_NAME + "\n").encode("ascii")),
                ("with an uppercase sha256",
                 (digest.upper() + "  " + CATALOGUE_NAME + "\n").encode("ascii")),
                ("replaced by an empty file", b"")):
            problems = check_sums(body, raw)
            record("SHA256SUMS: refuses the line " + name,
                   len(problems) == 1 and "must be the one line" in problems[0], repr(problems))

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
                   status == 0 and "OK, 1 plugin(s) checked" in text
                   and "not the published list" in text and "readme" not in text
                   and "sums file" not in text, repr((status, text)))
            status, text = command(git())
            record("command line fails a git-subdir entry",
                   status == 1 and "FAIL, 1 problem(s)" in text and D164_PROBLEM in text
                   and "owner ruling D-164" in text and "hashes source" not in text,
                   repr((status, text)))
            status, text = command(_changed(entry + ("hooks",), {}))
            record("command line fails an entry field that is not accepted",
                   status == 1 and "FAIL, 1 problem(s)" in text
                   and "field(s) not accepted: hooks" in text, repr((status, text)))
            status, text = command(_changed(("hooks",), {}))
            record("command line fails a top-level field that is not accepted",
                   status == 1 and "FAIL, 1 problem(s)" in text
                   and "problem: the top level holds only" in text
                   and "field(s) not accepted: hooks" in text, repr((status, text)))
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

            # The command line and the checksums (owner ruling D-164).
            readme_path = Path(folder) / "README.md"
            base_path = Path(folder) / "README-base.md"
            sums_path = Path(folder) / "SHA256SUMS"
            absent = str(Path(folder) / "absent")
            with_readme = ["--readme", str(readme_path)]
            with_base = with_readme + ["--readme-base", str(base_path)]
            with_sums = ["--sums-file", str(sums_path)]

            def write(document):
                """Write the file with a README, a base README and a SHA256SUMS that match."""
                market.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
                body = market.read_bytes()
                made = checksum_block(body) or [CHECKSUMS_BEGIN, CHECKSUMS_END]
                text = "# Title\n\n" + "\n".join(made) + "\n\nMore text.\n"
                readme_path.write_text(text, encoding="utf-8")
                base_path.write_text(text.replace(hashlib.sha256(body).hexdigest(), "0" * 64),
                                     encoding="utf-8")
                sums_path.write_bytes(sums_line(body).encode("ascii"))
                return text

            def call(arguments):
                """Run the command line. A usage error gives the text "usage error 2"."""
                out = io.StringIO()
                try:
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                        status = main(arguments)
                except SystemExit as error:
                    status = "usage error {}".format(error.code)
                return status, out.getvalue()

            def checked(*options):
                return call([str(market), "--hashes-file", str(hashes_path)] + list(options))

            def case(name, options, status, *fragments, without=()):
                got, text = checked(*options)
                record("command line " + name,
                       got == status and all(fragment in text for fragment in fragments)
                       and not any(fragment in text for fragment in without),
                       repr((got, text)))

            good_text = write(_fixture())
            case("passes a README, a base README and a SHA256SUMS that match",
                 with_base + with_sums, 0, "OK, 1 plugin(s) checked", "readme: ",
                 "base readme: ", "sums file: ")
            readme_path.write_text(good_text.replace(_SHA_A, _SHA_B), encoding="utf-8")
            case("fails a README with another sha256 for a zip", with_base + with_sums, 1,
                 "FAIL, 1 problem(s)", "README: the checksums block does not match")
            readme_path.write_text(good_text.replace("More text.", "Other text."),
                                   encoding="utf-8")
            case("fails a README changed outside the block, with a base README", with_base, 1,
                 "FAIL, 1 problem(s)", "outside the checksums block")
            case("passes that README without a base README", with_readme, 0,
                 "OK, 1 plugin(s) checked")
            readme_path.write_bytes(b"\xff\xfe")
            case("fails a README that is not UTF-8", with_readme, 1, "FAIL, 1 problem(s)",
                 "README: ", "is not UTF-8")
            readme_path.write_bytes(b" " * (MAX_TEXT_BYTES + 1))
            case("fails an oversized README", with_readme, 1, "FAIL, 1 problem(s)",
                 "README: ", "is larger than")
            write(_fixture())
            sums_path.write_bytes(b"")
            case("fails an empty SHA256SUMS", with_base + with_sums, 1, "FAIL, 1 problem(s)",
                 "SHA256SUMS: must be the one line")
            write(_fixture())
            case("fails a missing README", ["--readme", absent], 1, "FAIL, 1 problem(s)",
                 "README: could not read")
            case("fails a missing base README", with_readme + ["--readme-base", absent], 1,
                 "FAIL, 1 problem(s)", "base README: could not read")
            case("fails a missing SHA256SUMS", ["--sums-file", absent], 1, "FAIL, 1 problem(s)",
                 "SHA256SUMS: could not read")
            write(_changed(source + ("sha256",), _SHA_B))
            case("fails a wrong sha256 even when the README and SHA256SUMS list it",
                 with_base + with_sums, 1, "FAIL, 1 problem(s)", "does not match the hashes.txt")
            write(_changed(("hooks",), {}))
            case("fails a top-level field that is not accepted even when the README and "
                 "SHA256SUMS list the file", with_base + with_sums, 1, "FAIL, 1 problem(s)",
                 "problem: the top level holds only", "field(s) not accepted: hooks")
            case("prints no checksums for a file with a top-level field that is not accepted",
                 ["--print-checksums"], 1, "FAIL, 1 problem(s)",
                 without=(CHECKSUMS_BEGIN, "line for SHA256SUMS"))
            write(git())
            case("reports a README as not checked when the file has a git-subdir entry",
                 with_readme + with_sums, 1, "FAIL, 2 problem(s)", D164_PROBLEM,
                 "README: the checksums block was not checked")
            HELD_ENTRIES = {"beta": held}
            write(git())
            case("passes a held entry whose README lists it as not pinned",
                 with_base + with_sums, 0, "OK, 1 plugin(s) checked", "note: " + held_note,
                 "readme: ")
            case("prints the checksums of a file with a held entry", ["--print-checksums"], 0,
                 "| none | the `beta` plugin, held under owner decision D-165 | not pinned |")
            HELD_ENTRIES = {}
            case("fails the same files when no entry is held", with_base + with_sums, 1,
                 "FAIL, 2 problem(s)", D164_PROBLEM,
                 "README: the checksums block was not checked")
            write(_fixture())
            body = market.read_bytes()
            printed = ("checksums block for README.md:\n" + "\n".join(checksum_block(body))
                       + "\nline for SHA256SUMS:\n" + sums_line(body))
            got, text = checked("--print-checksums")
            record("command line prints the checksums of a file that passes",
                   got == 0 and text.endswith(printed) and "OK, 1 plugin(s) checked" in text,
                   repr((got, text)))
            write(_changed(source + ("sha256",), _SHA_B))
            case("prints no checksums for a file with a wrong sha256", ["--print-checksums"], 1,
                 "FAIL, 1 problem(s)", without=(CHECKSUMS_BEGIN, "line for SHA256SUMS"))
            write(git())
            case("prints no checksums for a file with a git-subdir entry", ["--print-checksums"],
                 1, "FAIL, 1 problem(s)", without=(CHECKSUMS_BEGIN, "line for SHA256SUMS"))
            write(_fixture())
            got, text = call([absent, "--hashes-file", str(hashes_path)] + with_base + with_sums)
            record("command line fails a missing marketplace file without naming a README or "
                   "SHA256SUMS that it did not compare",
                   got == 1 and "FAIL, 1 problem(s)" in text and "could not read the file" in text
                   and "readme" not in text and "sums file" not in text, repr((got, text)))

            # The command line and the base file (rule 12).
            base_market = Path(folder) / "marketplace-base.json"
            with_list = ["--base", str(base_market)]
            base_market.write_bytes(market.read_bytes())
            case("passes a file that equals its base file, with the README and SHA256SUMS",
                 with_list + with_base + with_sums, 0, "OK, 1 plugin(s) checked",
                 "base list: {}".format(base_market))
            case("names no base file when none is given", with_base + with_sums, 0,
                 "OK, 1 plugin(s) checked", without=("base list",))
            base_market.write_text(json.dumps(_second()), encoding="utf-8")
            case("fails a file without an entry of its base file",
                 with_list + with_base + with_sums, 1, "FAIL, 1 problem(s)",
                 "problem: base: the entry 'other' " + removed)
            base_market.write_text(json.dumps(beta("2.0.0")), encoding="utf-8")
            case("fails an earlier version than the base file's", with_list, 1,
                 "FAIL, 1 problem(s)", "version 1.0.0 " + lower + " 2.0.0")
            case("passes that file with no base file", [], 0, "OK, 1 plugin(s) checked")
            base_market.write_text(json.dumps(beta("1.0.0", "posluns.ca")), encoding="utf-8")
            case("fails another host than the base file's", with_list, 1, "FAIL, 1 problem(s)",
                 another_host)
            base_market.write_bytes(b"{")
            case("fails a base file that is broken JSON", with_list, 1, "FAIL, 1 problem(s)",
                 "problem: base: the base branch's marketplace file is not a list")
            case("fails a missing base file", ["--base", absent], 1, "FAIL, 1 problem(s)",
                 "problem: base: could not read")
            base_market.write_bytes(b" " * (MAX_TEXT_BYTES + 1))
            case("fails an oversized base file", with_list, 1, "FAIL, 1 problem(s)",
                 "problem: base: ", "is larger than")
            base_market.write_bytes(market.read_bytes())
            case("prints the checksums of a file that equals its base file",
                 with_list + ["--print-checksums"], 0, "base list: ", CHECKSUMS_BEGIN)
            for name, arguments in (
                    ("--readme-base without --readme", ["--readme-base", str(base_path)]),
                    ("--print-checksums with --readme", ["--print-checksums"] + with_readme),
                    ("--print-checksums with --sums-file", ["--print-checksums"] + with_sums)):
                case("refuses " + name, arguments, "usage error 2")
            for option in (["--print-checksums"], with_readme, with_sums,
                           ["--readme-base", str(base_path)], with_list):
                got, text = call(["--self-test"] + option)
                record("command line refuses --self-test with " + option[0],
                       got == "usage error 2", repr((got, text)))

            # With no FILE, the repository's own README.md and SHA256SUMS are checked.
            DEFAULT_PATH, DEFAULT_README, DEFAULT_SUMS = market, readme_path, sums_path
            local = ["--hashes-file", str(hashes_path)]
            got, text = call(local)
            record("command line with no FILE checks the README.md and SHA256SUMS beside it",
                   got == 0 and "readme: {}".format(readme_path) in text
                   and "sums file: {}".format(sums_path) in text, repr((got, text)))
            readme_path.write_text("# Title\n", encoding="utf-8")
            got, text = call(local)
            record("command line with no FILE fails a README with no block",
                   got == 1 and "FAIL, 1 problem(s)" in text and one_block in text,
                   repr((got, text)))
            got, text = call(local + ["--print-checksums"])
            record("command line with no FILE prints the checksums without checking that README",
                   got == 0 and text.endswith(printed) and "readme" not in text,
                   repr((got, text)))
            write(_fixture())
            sums_path.unlink()
            got, text = call(local)
            record("command line with no FILE fails a missing SHA256SUMS",
                   got == 1 and "FAIL, 1 problem(s)" in text
                   and "SHA256SUMS: could not read" in text, repr((got, text)))
    finally:
        _https_get = real_get
        DEFAULT_PATH, DEFAULT_README, DEFAULT_SUMS = real_paths
        HELD_ENTRIES = real_held

    failed = [item for item in results if not item[1]]
    for name, passed, detail in results:
        print("{}  {}{}".format("ok  " if passed else "FAIL", name,
                                "" if passed else ": " + detail))
    print("self-test: {} passed, {} failed".format(len(results) - len(failed), len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
