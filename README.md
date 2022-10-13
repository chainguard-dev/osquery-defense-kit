# osquery-defense-kit

Real-world queries for using osquery as part of your detection & response pipeline.

![osquery-defense-kit](images/logo-small.png?raw=true "osquery-defense-kit logo")

## Organization

* `detection/` - Threat detection queries tuned for alert generation.
* `response/` - Data collection to assist in responding to possible threats. Tuned for periodic evidence collection.
* `policy/` - Security policy queries tuned for alert generation.

Where suitable, queries are further divided up by [MITRE ATT&CK](https://attack.mitre.org/) tactics categories. Queries are periodically released in [osquery query pack](https://osquery.readthedocs.io/en/stable/deployment/configuration/#query-packs) format. See `Local Pack Generation` for more information.

## Linux Case Study: Shikitega (September 2022)

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

## macOS Case Study: CloudMensis (April 2022)

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

## False Positive Policy

We endeavor to exclude real-world false positives from our `detection` queries.

Managing false positives is easier said than done - pull requests are welcome!

## Tags Policy

Value:

* critical: queries are run 3x as often
* high: queries are run twice as often
* medium: queries are run at a regular pace (default)
* low: queries are run half as often
* very-low: queries are run 1/3rd as often

Interval Type:

* ephemeral: 60s (1 minute) base
* periodic: 1200s (20 minute) base (default)
* postmortem: 14400s (4 hour) base

Status:

* experimental: Run only half as often as normal

## Local pack generation

Run `make packs`
