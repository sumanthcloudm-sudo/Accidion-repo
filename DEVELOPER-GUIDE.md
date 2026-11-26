# Developer Guide

Put [security-scan.sh](https://raw.githubusercontent.com/sumanthcloudm-sudo/Accidion-repo/main/security-scan.sh)
in the application root. On Ubuntu, open a Bash terminal in that directory and run:

```bash
bash security-scan.sh
```

The launcher selects all six scanners by default and runs the stages that apply
to the project. It can install missing tools and resolve Maven or Gradle
dependencies. Tool downloads and vulnerability database updates require
network access. The application still needs the JDK and build settings it
normally uses.

Open `reports/security-summary.json` and the scanner JSON files alongside it.
Each scan refreshes those application reports and keeps private per-run JSON
and logs under `~/.accidion/reports/` by default. The launcher creates
`security-scan.properties` on the first regular run if needed. Edit it to
change the defaults for subsequent scans.

To preview discovery and scanner selection without installing tools or writing
reports, run `bash security-scan.sh --dry-run`.

## Maintain the standalone script

Edit the Python sources, scanner configuration, or
`scripts/security-scan.template.sh`, then rebuild the distribution from the
repository root. Commit the generated script with its sources.

```bash
python3 scripts/build_standalone.py
python3 scripts/build_standalone.py --check
bash -n security-scan.sh
python3 -m unittest discover -s tests
```
