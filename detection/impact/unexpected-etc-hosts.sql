SELECT
  *
FROM
  etc_hosts
WHERE
  hostnames NOT IN (
    'localhost',
    'localhost ip6-localhost ip6-loopback',
    'ip6-allnodes',
    'ip6-allrouters',
    'kubernetes'
  )
  AND address NOT IN (
    '127.0.1.1',
    '::1',
    'ff02::1',
    'ff02::2',
    '255.255.255.255',
    'fe00::0',
    'ff00::0'
  )
  AND hostnames NOT LIKE 'localhost.%'
  AND hostnames NOT LIKE '%.svc'
  AND hostnames NOT LIKE '%.%-%.%.dev'
  AND hostnames NOT LIKE '%.test'
  AND hostnames NOT LIKE '%.internal'
  AND hostnames NOT LIKE '%.local'
  AND hostnames NOT LIKE 'ip6-%'
