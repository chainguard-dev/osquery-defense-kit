-- Catch DNS traffic going to machines other than the host-configured DNS server
-- NOTE: This only supports IPv4 traffic due to an osquery bug with 'dns_resolvers'

-- The non-event version is unexpected-dns-traffic.sql
SELECT s.family,
  protocol,
  s.local_port,
  s.remote_port,
  s.local_address,
  s.remote_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  s.pid,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  hash.sha256,
  GROUP_CONCAT(
    (
      SELECT address
      FROM dns_resolvers
      WHERE type = 'nameserver' AND address != ''
      GROUP BY address
    ),
    ","
  ) AS sys_resolvers,
  CONCAT(
    p.name,
    ',',
    remote_address,
    ',',
    remote_port,
    ',',
    protocol
  ) AS exception_key
FROM socket_events s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE s.time > (strftime('%s', 'now') -120)
  AND remote_port IN (53, 5353)
  AND remote_address NOT LIKE "%:%"
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '127.%'
  AND remote_address NOT IN (
    SELECT DISTINCT address
    FROM dns_resolvers
    WHERE type = 'nameserver'
      and address != ''
  )

  -- systemd-resolve sometimes shows up this way
  -- If we could narrow this down using "sys_resolvers" I would, but it is misuse of GROUP_CONCAT
  AND NOT (s.pid = -1 AND s.remote_port=53 and p.parent='')

  -- Local DNS servers and custom clients go here
  AND p.path NOT IN ('/usr/lib/systemd/systemd-resolved')

  -- Other exceptions
  AND exception_key NOT IN (
    'Brave Browser Helper,8.8.8.8,53,',
    'chrome,8.8.8.8,53,0',
    'Google Chrome Helper,208.67.222.222,53,', -- OpenDNS FamilyShield
    'Google Chrome Helper,8.8.8.8,53,',
    'nessusd,50.16.123.71,53,',
    'Slack Helper,1.1.1.1,53,',
    'Slack Helper,8.8.8.8,53,',
    'plugin-container,8.8.8.8,53,'
  )

-- Workaround for the GROUP_CONCAT subselect adding a blank ent
GROUP BY s.remote_address,
  s.remote_port
HAVING remote_address != ""