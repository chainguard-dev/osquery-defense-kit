# osquery-defense-kit

Real-world queries for using osquery as part of a detection & response pipeline.

![osquery-defense-kit](images/logo-small.png?raw=true "osquery-defense-kit logo")

Primarily focused on threat detection on POSIX platforms (Linux, macOS), the osquery-defense-kit (ODK) differs from
existing published query sets in that they are designed to be used in an alert pipeline. Most queries (particularly those in `detection` and `policy`) should return 0 results
unless an exceptional behavior is detected.

## Organization

* `detection/` - Threat detection queries tuned for alert generation.
* `response/` - Data collection to assist in responding to possible threats. Tuned for periodic evidence collection.
* `policy/` - Security policy queries tuned for alert generation.

The detection queries are further divided up by [MITRE ATT&CK](https://attack.mitre.org/) tactics categories.

Periodically, queries published in [osquery query pack](https://osquery.readthedocs.io/en/stable/deployment/configuration/#query-packs) format. See `Local Pack Generation` for information on how to generate your own.

## Detection on Linux Case Study: Shikitega (September 2022)

<https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux>

Here is a partial list of what queries would have fired an alert based on these queries:

* *Initial Dropper Execution*, detected by:
  * `execution/tiny-executable-events.sql`
  * `execution/tiny-executable.sql`
* *Next Stage Dropper Execution*, detected by:
  * `execution/tiny-executable-events.sql`
  * `execution/tiny-executable.sql`
  * `execution/unexpected-shell-parents.sql`
* *Escalation Prep*, detected by:
  * `execution/sketchy-fetchers.sql`
  * `execution/sketchy-fetcher-events.sql`
  * `c2/unexpected-talkers-linux.sql`
  * `c2/exotic-command-events.sql`
  * `c2/exotic-cmdline.sql`
* *Escalation Tool Execution* detected by:
  * `execution/unexpected-executable-permissions.sql`
  * `execution/unexpected-executable-directory-linux.sql`
  * `execution/unexpected-tmp-executables.sql`
  * `c2/exotic-command-events.sql`
  * `c2/exotic-cmdline.sql`
  * `initial_access/unexpected-shell-parents.sql`
  * `evasion/missing-from-disk-linux.sql`
* *Privilege Escalation* detected by:
  * `privesc/unexpected-setxid-process.sql`
  * `privesc/unexpected-privilege-escalation.sql`
  * `privesc/events/unexpected-privilege-escalation-events.sql`
  * `evasion/name_path_mismatch.sql`
* *Persistence* detected by:
  * `persistence/unexpected-cron-entries.sql`
  * `execution/unexpected-executable-directory-linux.sql`

## Detection on macOS Case Study: CloudMensis (April 2022)

<https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/>

Here is a partial list of what stages would have been detected by particular queries:

* *Initial Dropper Execution*, detected by:
  * `c2/unexpected-talkers-macos.sql`

* *Second Stage Execution*, detected by:
  * `execution/unexpected-executable-directory-macos.sql`
  * `persistence/unexpected-launch-daemon-macos.sql`
  * `execution/unexpected-mounts.sql`

* *TCC Bypass*, detected by:
  * `evasion/unexpected-env-values.sql`

* *Spy Agent Execution*, detected by:
  * `c2/unexpected-talkers-macos.sql`
  * `execution/exotic-command-events.sql`
  * `execution/unexpected-executable-directory-macos.sql`

## Local pack generation

Run `make packs`

For more control, you can invoke [osqtool](https://github.com/chainguard-dev/osqtool) directly, to override default intervals or exclude checks.

## Policies

### Contributions

Help is wanted! We support any new queries so long as they can be easily updated to address false positives.

Users may submit false positive exceptions for popular well-known software packages, so long as evidence is provided for the behavior.

### Platform Support

While originally focused on Linux and macOS, we support the addition of queries on any platform supported by osquery.

### False Positives

We endeavor to exclude real-world false positives from our `detection` queries.

Managing false positives is easier said than done - pull requests are welcome!

### CPU Overhead

In aggregate, queries should not consume more than 2% of the wall clock time across a day on a deployed system.

### Intervals

Deployed intervals are automatically determined based on the tags supported by the [osqtool](https://github.com/chainguard-dev/osqtool), which we use for pack assembly.
