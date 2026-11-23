# Accidion developer guide

## Run the starter kit

Open Git Bash on Windows or Bash on macOS or Linux from the Java application directory. Use the copy-paste command issued for the reviewed release. It includes the commit SHA and the SHA-256 digests of the launcher and archive. Use an approved GitHub user token supplied as GH_TOKEN, an authenticated GitHub CLI session, or a cached Git credential-manager entry. The launcher verifies both downloads before it executes the kit. See the [README](README.md#run-from-the-public-github-repository) for prerequisites and the command template.

Append --dry-run to verify authentication, download integrity, and application discovery. A dry run does not install tools, run scanners, or write scan reports. Normal runs write local JSON under $HOME/.accidion/reports/<application-name>/scan-<UTC-date-time>-<id>/ unless you set a different report location.

## Windows temporary-directory cleanup

The published commit 6dbbfa55a7669f2102d5ca59f5f049757dc4b277 can return status 1 after a successful dry run. The failure was reproduced after authentication, archive verification, and discovery. Windows reported a sharing violation (WinError 32) for the extracted kit directory, and Git Bash's rm reported that it was busy. The old EXIT trap allowed that cleanup error to replace the launcher status. An accessible-handle inspection did not identify the process holding the lock. Its identity remains unverified.

The cleanup fix covers the public copy-paste command and the extracted bootstrap. Each saves the status it received, makes up to five bounded attempts to remove its own temporary directory, and returns the saved status. If the directory remains locked, the command prints a warning with its path and the saved exit status. A successful launcher can therefore complete with a cleanup warning, while a scanner or bootstrap failure retains its nonzero status.

Use the new pinned command from the release handover to pick up the fix. Commands pinned to 6dbbfa55a7669f2102d5ca59f5f049757dc4b277 still use the original cleanup behavior. For a live run, inspect the scanner statuses in security-summary.json before deciding whether to retry. If the launcher reports a retained temporary directory, wait for the Windows handle to be released before removing that directory.

## Validation and limits

| Check | Result |
|---|---|
| Published Windows Git Bash dry run | The cleanup lock was reproduced after successful authenticated discovery. |
| Revised Windows Git Bash bootstrap | Six authenticated dry runs against the pinned public archive used fresh temporary directories. All exited 0, discovered six applicable stages, and cleaned up without warnings. |
| Ubuntu WSL | The published and revised authenticated dry runs both exited 0, removed their temporary directories, and produced identical discovery JSON. |
| Mocked cleanup regression | Both launcher layers retry a transient failure and warn on a persistent lock. The original statuses 0, 1, and 7 are preserved across the tested cases. Authentication and digest rejection tests also passed. |

Prepublication checks used the revised local bootstrap against the previous public archive and exercised the updated outer command with mocked cleanup failures. See the release handover for verification of the published pin. Native macOS and standalone Linux testing remain pending. No live security scanners were run for this change.
