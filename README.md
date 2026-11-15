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

secureconfig installs from the `main` branch until its first public release.
After that release, the entry is pinned to one commit.

## What is checked

Every pull request runs the `marketplace-check` job. The job takes its workflow
and `tools/check_marketplace.py` from the base branch, never from the pull
request. It reads the pull request's `.claude-plugin/marketplace.json` as data
and runs no file from the pull request. The checker checks that:

- the list is valid, the marketplace name is `jposluns`, the owner name is
  `Jeff Posluns`, and each plugin name is used once;
- a repository source is a repository under `jposluns`;
- a zip source is an https URL on a known host, its file name is
  `<artifact>-<version>.zip`, and its SHA-256 matches the one `release` row for
  that artifact and version at https://posluns.dev/hashes.txt.

The job passes only when the pull request changes
`.claude-plugin/marketplace.json` and no other file. A change outside the
catalogue needs the owner's review: the job fails for it, and
`.github/CODEOWNERS` names the owner as the required reviewer for `.github/`,
`tools/` and the `CODEOWNERS` file itself.

The hashes list holds one digest for each release. What the digest covers
depends on the project. For some projects it is the SHA-256 of the release zip.
For some it is the SHA-256 of the release's `SHA256SUMS` file, which lists the
hash of every release file. The head of the list says what each project's
digest covers. To check a download yourself, compare as the project's install
page says.

## Problems

Open an issue in this repository.

## Licence

Apache License 2.0. See `LICENSE`.
