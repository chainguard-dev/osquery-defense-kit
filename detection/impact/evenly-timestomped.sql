-- Files where the timestamp falls along 12-hour boundaries - probably caused by 'touch <date>0000'
--
-- false positives:
--   * 1 in 43200 chance per binary
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Indicator Removal on Host: Timestomp)
--
-- tags: persistent seldom filesystem
-- platform: linux
SELECT
  file.path,
  DATETIME(file.mtime, 'unixepoch', 'localtime') AS mod_time,
  DATETIME(file.atime, 'unixepoch', 'localtime') AS access_time,
  file.inode,
  file.type,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path LIKE "/bin/%%"
    OR file.path LIKE "/etc/%%"
    OR file.path LIKE "/sbin/%%"
    OR file.path LIKE "/lib/%%"
  )
  -- This timestamp is in UTC
  AND file.mtime > (strftime('%s', 'now') - (86400 * 720))
  AND file.mtime % 3600 = 0
  AND file.type = 'regular'
  -- Narrow down to specific offsets in the users local timezone (there should be a better way!)
  AND (
    mod_time LIKE "% 12:00:00"
    OR mod_time LIKE "% 00:00:00"
  )
  -- false positives
  AND filename NOT IN (
    'master.passwd',
    'COPYING',
    'debian_version',
    'NEWS',
    '_libinput',
    'printcap',
    'strace-log-merge',
    'installer-info.json'
  )
  AND file.path NOT LIKE '%/lynis%'
  AND file.path NOT LIKE '%/yelp-xsl%'
  AND file.path NOT LIKE '/etc/cups/%'
