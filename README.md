# jposluns plugins

This repository is the plugin marketplace for the jposluns projects. It holds one
list, `.claude-plugin/marketplace.json`. Each plugin lives in its own project's
public repository or release zip.

## Install

In Claude Code, add the marketplace once:

    /plugin marketplace add jposluns/plugins

Then install a plugin by name:

    /plugin install <project>@jposluns

## Plugins

The checksums table under "Checksums" below names every plugin in the list.
The `marketplace-check` job keeps that table equal to the list, so this README
holds no other table of plugins. The name of a plugin in that table is the
`<project>` of the install line above.

Every entry must be a release zip whose SHA-256 has a row at
https://posluns.dev/hashes.txt (owner ruling D-164). Since owner ruling D-171
every entry is one, and no entry is held.

## What is checked

Every pull request runs the `marketplace-check` job. The job takes its workflow
and `tools/check_marketplace.py` from the base branch, never from the pull
request. It reads the pull request's `.claude-plugin/marketplace.json`,
`README.md` and `SHA256SUMS` as data and runs no file from the pull request.
The checker checks that:

- the list is valid, the marketplace name is `jposluns`, the owner name is
  `Jeff Posluns`, and each plugin name is used once;
- the top level of the list holds only `name`, `owner`, `description`,
  `metadata` and `plugins`, `owner` holds only `name`, `email` and `url`, and
  `metadata` holds only `description` and `version`, so that a pull request
  cannot add a field that no check judges;
- an entry holds only `name`, `description` and `source`, so that it cannot
  carry plugin parts of its own, which no SHA-256 here would cover;
- every entry is a zip source; a repository source is refused, pinned or not
  (owner ruling D-164). The one exception is an entry that the checker's
  `HELD_ENTRIES` table names field for field (owner decision D-165); the
  checksums table below lists every held entry as not pinned. In a pull
  request an entry is held only when `main` holds the same entry, field for
  field: a held entry is not added, and an entry that `main` holds as a zip
  does not become held again;
- a zip source is an https URL on a known host, its file name is
  `<entry name>-plugin-<version>.zip`, and its SHA-256 matches the one
  `release` row for that artifact and version at
  https://posluns.dev/hashes.txt. The file name ties an entry to its project:
  the `auditthis` entry cannot point at the zip of another project;
- compared with the list on `main`, no entry is removed or renamed, the zip of
  an entry stays on the host that it has on `main`, and its version is not
  lower than the version on `main`. A new entry may use any known host;
- compared with the list on `main`, every field outside `plugins` is the same:
  the marketplace `name` and `description`, each field of `owner` and each
  field of `metadata`. None is added, removed or changed;
- the checksums table in this README and the `SHA256SUMS` file match the list.

The job passes only when the pull request changes
`.claude-plugin/marketplace.json`, the checksums table in this README and
`SHA256SUMS`, and nothing else. Any other change needs the owner's review: the
job fails for it. `.github/CODEOWNERS` names the owner as the code owner of
`.github/` and `tools/`, and so of the `CODEOWNERS` file itself. That file
alone does not make the owner's review a condition of a merge: the "Require
review from Code Owners" setting of `main` does (see the administrator's
settings below).

Removing or renaming an entry, moving an entry to another host, going back to
an earlier version, making an entry held and changing a field outside
`plugins` need the owner's review too: the job fails for each of them. The
`main-check` job has no earlier list to compare with, so it does not apply
these rules.

The job judges a pull request against `main` as it was when the job started,
and nothing starts it again when `main` changes. So a pull request is merged
only when its branch holds the last commit of `main` and the job is green for
the last commit of that branch. Updating the branch starts a new run. Branch
protection enforces this when `main` requires the `marketplace-check` job
together with "Require branches to be up to date before merging"; without that
setting it is a step for whoever merges. The `main-check` job runs the same
checker on `main` after each push to it, and fails when `main` holds a list,
a checksums table or a `SHA256SUMS` that the checker refuses.

The job takes its workflow and checker from the base branch of the pull
request. A branch other than `main` can hold an older check, so a pull request
against such a branch can pass a check that `main` would fail. Nothing in this
repository can stop that, and no file in this repository turns on a branch
protection setting. The repository administrator must:

- keep `main` the only branch whose `marketplace-check` result is accepted.
  The simple way is to delete every other branch and to allow no new one;
- require the `marketplace-check` job on `main`;
- turn on "Require a pull request before merging" for `main`, and under it
  "Require review from Code Owners".

GitHub's documentation says this of "Require review from Code Owners": a pull
request that changes a file with a code owner is merged only after a code
owner of that file has approved it. Here the files with a code owner are the
ones under `.github/` and `tools/`. The setting adds nothing for the list, this
README and `SHA256SUMS`, which have no code owner; the `marketplace-check` job
judges those. Without the setting, `CODEOWNERS` only makes GitHub ask the owner
for a review, and a pull request can be merged without that review. The
setting has not been tested on this repository, and this repository does not
record which settings `main` has.

The workflow also runs when a pull request is edited, so that a pull request
whose base branch is changed to `main` is checked again, by the check of
`main`. The next three statements are inferences about GitHub's behaviour.
They have not been tested on this repository:

- GitHub records a job result for the last commit of a pull request, so a
  result from a run against another branch could count for `main`;
- changing the base branch of a pull request starts the `edited` run;
- the result of that run replaces the earlier result for the same commit.

The workflow names the two actions that it uses, `actions/checkout` and
`actions/setup-python`, by version tag and not by commit. This is left as it
is for now: the owner will pin both to commit SHAs (TODO 61). Until then,
whoever can move those tags can change what the job runs. The job's token can
read the repository's contents and nothing more, and the job uses no secret.

The hashes list holds one digest for each release. What the digest covers
depends on the project. For some projects it is the SHA-256 of the release zip.
For some it is the SHA-256 of the release's `SHA256SUMS` file, which lists the
hash of every release file. The head of the list says what each project's
digest covers. To check a download yourself, compare as the project's install
page says.

## Checksums

The table gives the SHA-256 of the marketplace file and of each plugin zip, as
they are at this commit. A held entry has no zip, and the table lists it as not
pinned.

<!-- checksums:begin -->
| File | What it is | SHA-256 |
|---|---|---|
| `.claude-plugin/marketplace.json` | the marketplace file | `402980b09a1e8430d36461b2bbdf092f03905a9a0e56de62db789c5163d71069` |
| `secureconfig-plugin-1.0.1351.zip` | the `secureconfig` plugin | `677b3836d8fc69100424b352520d3f53c04667705a4c65e440cc942431d52c1a` |
| `auditthis-plugin-2.21.2.zip` | the `auditthis` plugin | `39f76793f0e1f04e9bea1d8bec965997dbd46458518d99a7d80262efd76c3b65` |
<!-- checksums:end -->

The table and `SHA256SUMS` are in this repository, beside the list. They show
that a copy of the list is whole. They are not a second channel: one change to
this repository can change the list, the table and `SHA256SUMS` together.

The separate channel is https://posluns.dev/hashes.txt, which is published
apart from this repository:

- A plugin zip has a `release` row there under its artifact name and version.
  The `marketplace-check` job fails for an entry whose zip has no such row.
- The marketplace file has rows there under `jposluns-plugins`, each with the
  commit of this repository that it is for. The owner adds a row by hand after
  a change is merged here, and no check enforces it, so the newest marketplace
  file can be without a row.
- A change that brings back an earlier marketplace file, byte for byte, gets no
  row of its own, because the tool that makes the rows refuses a digest that
  is already on another row. The earlier row stays, and a dated comment line
  below the row it follows, which is the highest version at that time, records
  the return. A later row goes directly after the previous row, so it is above
  that comment line.

A marketplace file whose SHA-256 is on a `jposluns-plugins` row is the file
that the owner recorded for the commit shown. A file whose SHA-256 is on no row
is not confirmed by that list.

To check the marketplace file in a checkout, run `sha256sum --check SHA256SUMS`
from the repository root. Then look for a `jposluns-plugins` row with the same
digest.

Whoever changes the list updates the table and `SHA256SUMS` in the same pull
request. `python3 -I -B tools/check_marketplace.py --print-checksums` prints
both, and the `marketplace-check` job fails when either does not match the list.

## Problems

Open an issue in this repository.

## Licence

Apache License 2.0. See `LICENSE`.
