# osquery-defense-kit

Real-world queries for using osquery as part of your detection & response pipeline.

![osquery-defense-kit](images/logo-small.png?raw=true "osquery-defense-kit logo")

## Organization

* `detection/` - Threat detection queries suitable for alerting.
* `response/` - Data collection to assist in responding to possible threats. Designed to collect data for future analysis or in response to an event.
* `policy/` - Policy issues that are suitable for alerting.

Where suitable, these are further divided up by [MITRE ATT&CK](https://attack.mitre.org/) tactics categories.

## Linux Case Study: Shikitega (September 2022)

<https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux>

Here is a partial list of what stages would have been detected by particular queries:

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

## Local pack generation

Run `make packs`
