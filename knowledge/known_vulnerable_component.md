# Known Vulnerable Component

## Description
Occurs when the application depends, directly or transitively, on a
library or package version with a publicly known vulnerability (identified
by a CVE). Risk depends on whether the vulnerable code path is actually
reachable from the application.

## Remediation
- Upgrade the affected package to the first version that contains the fix,
  per the CVE's advisory. Check the changelog for breaking changes before
  upgrading a major version.
- If no fixed version exists yet, evaluate whether the vulnerable
  functionality is actually used (reachability) and consider a workaround
  (config change, disabling the feature, or a temporary patch/override) —
  do not ship a temporary bypass as the final fix without also tracking
  the upgrade.
- Pin dependency versions and regenerate the lockfile after upgrading so
  the fix is reproducible in CI.
- Re-run the SCA scan after upgrading to confirm the CVE no longer appears.

## Verification
Confirm the installed version in the lockfile now matches or exceeds the
fixed version referenced in the CVE advisory, and re-scan.
