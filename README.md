# osquery-packs

osquery packs, mostly geared toward threat hunting.

## Linux Case Study: Shikitega (September 2022)

<https://cybersecurity.att.com/blogs/labs-research/shikitega-new-stealthy-malware-targeting-linux>

Here is a partial list of what stages would have been detected by particular queries:

* *Initial Dropper Execution*, detected by:
  * `process_events/tiny-executable-events.sql`
  * `process/tiny-executable.sql`
* *Next Stage Dropper Execution*, detected by:
  * `process_events/tiny-executable-events.sql`
  * `process/tiny-executable.sql`
  * `process/unexpected-shell-parents.sql`
* *Escalation Prep*, detected by:
  * `process/sketchy-fetchers.sql`
  * `process-events/sketchy-fetcher-events.sql`
  * `net/unexpected-talkers-linux.sql`
  * `net/exotic-command-events.sql`
  * `net/exotic-cmdline.sql`
* *Escalation Tool Execution* detected by:
  * `process/unexpected-executable-permissions.sql`
  * `process/unexpected-executable-directory-linux.sql`
  * `process/unexpected-tmp-executables.sql`
  * `net/exotic-command-events.sql`
  * `net/exotic-cmdline.sql`
  * `process/unexpected-shell-parents.sql`
  * `process/missing-from-disk-linux.sql`
* *Privilege Escalation* detected by:
  * `process/unexpected-setxid-process.sql`
  * `process/unexpected-privilege-escalation.sql`
  * `process/events/unexpected-privilege-escalation-events.sql`
  * `process/name_path_mismatch.sql`
* *Persistence* detected by:
  * `startup/unexpected-cron-entries.sql`
  * `process/unexpected-executable-directory-linux.sql`

## macOS Case Study: CloudMensis (April 2022)

<https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/>

Here is a partial list of what stages would have been detected by particular queries:

* *Initial Dropper Execution*, detected by:
  * `net/unexpected-talkers-macos.sql`

* *Second Stage Execution*, detected by:
  * `process/unexpected-executable-directory-macos.sql`
  * `startup/unexpected-launch-daemon-macos.sql`
  * `mounts/unexpected-mounts.sql`

* *TCC Bypass*, detected by:
  * `env/unexpected-env-values.sql`

* *Spy Agent Execution*, detected by:
  * `net/unexpected-talkers-macos.sql`
  * `process_events/exotic-command-events.sql`
  * `process/unexpected-executable-directory-macos.sql`
