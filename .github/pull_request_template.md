## What this pull request does

- [ ] Adds an entry
- [ ] Updates an entry (new version or pin)
- [ ] Something else (needs owner review)

Plugin name:
Source (repository, ref and commit; or zip URL):
Release link:

## Entry-only checklist

- [ ] Only `.claude-plugin/marketplace.json` changed.
- [ ] The change is inside `plugins`. No entry is removed or renamed. The
      marketplace `name` and `owner` are unchanged.
- [ ] The entry name equals `name` in the plugin's `.claude-plugin/plugin.json`.
- [ ] A github or git-subdir source names a public repository under `jposluns`.
- [ ] An archive source is an https URL on an allow-listed host. Its file name
      is `<artifact>-<version>.zip`, and its `sha256` equals the one `release`
      row for that artifact and version in https://posluns.dev/hashes.txt.
- [ ] `claude plugin validate .` passes, run from the repository root. The
      output and the CLI version are pasted below.
- [ ] The `marketplace-check` job is green.

If a box cannot be ticked, this is not an entry-only pull request. Say why and
wait for owner review.

## Output of claude plugin validate

```
(paste the command, its output and the CLI version here)
```
