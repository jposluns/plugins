## What this pull request does

- [ ] Adds an entry
- [ ] Updates an entry (new version)
- [ ] Something else (needs owner review)

Plugin name:
Source (zip URL):
Release link:

## Entry-only checklist

- [ ] Only `.claude-plugin/marketplace.json`, the checksums table in
      `README.md` and `SHA256SUMS` changed. The table and the `SHA256SUMS` line
      are the output of
      `python3 -I -B tools/check_marketplace.py --print-checksums`.
- [ ] The change is inside `plugins`. No entry is removed or renamed; the
      `marketplace-check` job fails for either. The marketplace `name` and
      `owner` are unchanged.
- [ ] The entry name equals `name` in the plugin's `.claude-plugin/plugin.json`.
- [ ] The entry holds only `name`, `description` and `source`, and the source
      is an archive source (owner ruling D-164).
- [ ] The archive source is an https URL on an allow-listed host. Its file name
      is `<entry name>-plugin-<version>.zip`, and its `sha256` equals the one
      `release` row for that artifact and version in
      https://posluns.dev/hashes.txt.
- [ ] For an entry that `main` already holds as a zip: the host of the URL is
      the one on `main`, and the version is not lower than the one on `main`.
- [ ] `claude plugin validate .` passes, run from the repository root. The
      output and the CLI version are pasted below.
- [ ] This branch holds the last commit of `main`, and the `marketplace-check`
      job is green for the last commit of this branch.

If a box cannot be ticked, this is not an entry-only pull request. Say why and
wait for owner review.

After the merge, the owner adds the `jposluns-plugins` row for the merged
marketplace file to https://posluns.dev/hashes.txt (see "Checksums" in the
README). That row is not part of this pull request.

## Output of claude plugin validate

```
(paste the command, its output and the CLI version here)
```
