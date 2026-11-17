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

| Plugin | Install line | Source |
|---|---|---|
| secureconfig | `/plugin install secureconfig@jposluns` | `plugin` folder of `jposluns/secureconfig`, branch `main` |
| auditthis | `/plugin install auditthis@jposluns` | versioned zip from auditthis.ai |

secureconfig is held in the list under owner decision D-165. It installs from
the `main` branch of its repository, so it is the one entry that is not pinned
by SHA-256, and no checksum here covers it. The checker reports that entry in a
note and does not refuse it. Every other entry, and any change to this one,
must be a release zip whose SHA-256 has a row at https://posluns.dev/hashes.txt
(owner ruling D-164).

The hold ends when secureconfig has a plugin zip with a row there. It ends in
one pull request that the owner reviews: it replaces the entry with the zip
entry, empties the checker's `HELD_ENTRIES` table, and updates this section,
the checksums table and `SHA256SUMS`.

## What is checked

Every pull request runs the `marketplace-check` job. The job takes its workflow
and `tools/check_marketplace.py` from the base branch, never from the pull
request. It reads the pull request's `.claude-plugin/marketplace.json`,
`README.md` and `SHA256SUMS` as data and runs no file from the pull request.
The checker checks that:

- the list is valid, the marketplace name is `jposluns`, the owner name is
  `Jeff Posluns`, and each plugin name is used once;
- the top level of the list holds only `name`, `owner`, `description`,
  `metadata` and `plugins`, and `metadata` holds only `description` and
  `version`, so that a pull request cannot add a field that no check judges;
- an entry holds only `name`, `description` and `source`, so that it cannot
  carry plugin parts of its own, which no SHA-256 here would cover;
- every entry is a zip source; a repository source is refused, pinned or not
  (owner ruling D-164). The one exception is an entry that the checker's
  `HELD_ENTRIES` table names field for field (owner decision D-165); the
  Plugins section above names every held entry;
- a zip source is an https URL on a known host, its file name is
  `<artifact>-<version>.zip`, and its SHA-256 matches the one `release` row for
  that artifact and version at https://posluns.dev/hashes.txt;
- the checksums table in this README and the `SHA256SUMS` file match the list.

The job passes only when the pull request changes
`.claude-plugin/marketplace.json`, the checksums table in this README and
`SHA256SUMS`, and nothing else. Any other change needs the owner's review: the
job fails for it, and
`.github/CODEOWNERS` names the owner as the required reviewer for `.github/`,
`tools/` and the `CODEOWNERS` file itself.

The job judges a pull request against `main` as it was when the job started,
and nothing starts it again when `main` changes. So a pull request is merged
only when its branch holds the last commit of `main` and the job is green for
the last commit of that branch. Updating the branch starts a new run. Branch
protection enforces this when `main` requires the `marketplace-check` job
together with "Require branches to be up to date before merging"; without that
setting it is a step for whoever merges. The `main-check` job runs the same
checker on `main` after each push to it, and fails when `main` holds a list,
a checksums table or a `SHA256SUMS` that the checker refuses.

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
| `.claude-plugin/marketplace.json` | the marketplace file | `1830a40bebfd11a76b139282a659b5fb05ec19a674a26f668132e4d40eacf8bc` |
| none | the `secureconfig` plugin, held under owner decision D-165 | not pinned |
| `auditthis-plugin-2.17.0.zip` | the `auditthis` plugin | `0a1dacb9752aafca859141746c33983d545930fdba064f4e56e33edd0e899e86` |
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
