-- Unexpected /etc/hosts entries
--
-- false positives:
--   * developers adding entries for their own use
--
-- references:
--   * https://attack.mitre.org/techniques/T1565/001/ (Data Manipulation: Stored Data Manipulation)
--
-- tags: persistent seldom filesystem net
SELECT
  *
FROM
  etc_hosts
WHERE
  hostnames NOT IN (
    'localhost',
    'localhost ip6-localhost ip6-loopback',
    'localhost localhost.localdomain localhost4 localhost4.localdomain4',
    'ip6-allnodes',
    'ip6-allrouters',
    'kubernetes'
  )
  AND address NOT IN (
    '::1',
    'ff02::1',
    'ff02::2',
    '255.255.255.255',
    'fe00::0',
    'ff00::0'
  )
  AND address NOT LIKE '127.%'
  AND hostnames NOT LIKE 'localhost.%'
  AND hostnames NOT LIKE '%.svc'
  AND hostnames NOT LIKE '%.%-%.%.dev'
  AND hostnames NOT LIKE '%.wtf'
  AND hostnames NOT LIKE '%.test'
  AND hostnames NOT LIKE '%.internal'
  AND hostnames NOT LIKE '%.local'
  AND hostnames NOT LIKE 'ip6-%'
