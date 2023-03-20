-- Catch DNS traffic going to machines other than the host-configured DNS server (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/004/ (C2: Application Layer Protocol: DNS)
--
-- interval: 120
-- tags: persistent events net
--
-- NOTE: The interval above must match WHERE clause to avoid missing events
--
-- This only supports IPv4 traffic due to an osquery bug with 'dns_resolvers'
-- The non-event version is unexpected-dns-traffic.sql
SELECT
  protocol,
  s.remote_port,
  s.remote_address,
  s.local_port,
  s.local_address,
  s.action,
  s.status,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  s.pid,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  hash.sha256,
  CONCAT (p.name, ',', remote_address, ',', remote_port) AS exception_key
FROM
  socket_events s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  s.time > (strftime('%s', 'now') -120)
  AND remote_port IN (53, 5353)
  AND remote_address NOT LIKE '%:%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '127.%'
  AND remote_address NOT IN (
    SELECT DISTINCT
      address
    FROM
      dns_resolvers
    WHERE
      type = 'nameserver'
      and address != ''
  )
  -- systemd-resolve sometimes shows up this way
  -- If we could narrow this down using 'sys_resolvers' I would, but it is misuse of GROUP_CONCAT
  AND NOT (
    s.pid = -1
    AND s.remote_port = 53
    and p.parent = ''
  )
  -- Some applications hard-code a safe DNS resolver, or allow the user to configure one
  AND s.remote_address NOT IN (
    '100.100.100.100', -- Tailscale Magic DNS
    '1.1.1.1', -- Cloudflare
    '1.1.1.2', -- Cloudflare
    '8.8.8.8', -- Google
    '8.8.4.4', -- Google (backup)
    '4.2.2.1', -- Level 3
    '4.2.2.2', -- Level 3
    '4.2.2.3', -- Level 3
    '4.2.2.4', -- Level 3
    '4.2.2.5', -- Level 3
    '4.2.2.6', -- Level 3
    '208.67.220.220', -- OpenDNS
    '208.67.222.222', -- OpenDNS
    '208.67.222.123', -- OpenDNS
    '208.67.220.123', -- OpenDNS FamilyShield
    '75.75.75.75', -- Comcast
    '75.75.76.76', -- Comcast
    '68.105.28.13', -- Cox
    '80.248.7.1' -- 21st Century (NG)
  )
  -- Exceptions that specifically talk to one server
  AND exception_key NOT IN (
    'coredns,0.0.0.0,53',
    'syncthing,46.162.192.181,53',
    'Code Helper,208.67.222.123,53',
    'Opera Helper,77.111.247.77,53',
    'chrome,74.125.250.47,53',
    'Jabra Direct Helper,208.67.222.123,53'
  )
  AND exception_key NOT LIKE 'Opera Helper,77.111.247.%,53'
  AND p.name != 'nessusd'
  -- Local DNS servers and custom clients go here
  -- Electron apps
  AND p.path NOT LIKE '/private/var/folders/%/T/AppTranslocation/%/%.app/Contents/MacOS/% Helper'
  AND p.path NOT LIKE '/Applications/%.app/Contents/MacOS/% Helper'
  AND p.path NOT LIKE '/Volumes/Google Chrome/%.app/Contents/MacOS/% Helper'
  AND p.path NOT IN (
    '/Library/Nessus/run/sbin/nessusd',
    '/opt/google/chrome/chrome',
    '/usr/bin/apko',
    '/sbin/apk',
    '/System/Volumes/Preboot/Cryptexes/Incoming/OS/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking',
    '/usr/lib/systemd/systemd-resolved'
  )
  -- Chromium apps can send stray DNS packets
  AND p.path NOT LIKE '/Applications/Google Chrome.app/Contents/Frameworks/Google Chrome Framework.framework/Versions/%/Helpers/Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper'
  AND p.path NOT LIKE '/Applications/Brave Browser.app/Contents/Frameworks/Brave Browser Framework.framework/Versions/%/Helpers/Brave Browser Helper.app/Contents/MacOS/Brave Browser Helper'
  AND p.path NOT LIKE '/Applications/Opera.app/Contents/Frameworks/Opera Framework.framework/Versions/%/Helpers/Opera Helper.app/Contents/MacOS/Opera Helper'
  -- Workaround for the GROUP_CONCAT subselect adding a blank ent
GROUP BY
  s.remote_address,
  s.remote_port
HAVING
  remote_address != ''
