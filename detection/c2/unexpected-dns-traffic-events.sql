-- Catch DNS traffic going to machines other than the host-configured DNS server (event-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/004/ (C2: Application Layer Protocol: DNS)
--
-- interval: 300
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
  COALESCE(REGEX_MATCH (p.path, '.*/(.*)', 1), p.path) AS basename,
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
  s.time > (strftime('%s', 'now') -300)
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
    '1.1.1.1', -- Cloudflare
    '100.100.100.100', -- Tailscale Magic DNS
    '208.67.220.123', -- OpenDNS FamilyShield
    '75.75.75.75', -- Comcast
    '75.75.76.76', -- Comcast
    '68.105.28.13', -- Cox
    '80.248.7.1', -- 21st Century (NG)
    '34.160.111.32', -- wolfi.dev
    '185.125.190.31', -- Canonical
    '185.125.190.77' -- Canonical
  )
  -- Exceptions that specifically talk to one server
  AND exception_key NOT IN (
    'adguard_dns,1.0.0.1,53',
    'AssetCacheLocatorService,0.0.0.0,53',
    'brave,8.8.8.8,53',
    'CapCut,8.8.8.8,53',
    'cg,108.177.98.95,53',
    'ChatGPT,8.8.8.8,53',
    'com.docker.backend,8.8.8.8,53',
    'com.docker.vpnkit,8.8.8.8,53',
    'coredns,0.0.0.0,53',
    'coredns,8.8.8.8,53',
    'Creative Cloud Content Manager.node,8.8.4.4,53',
    'Creative Cloud Content Manager.node,8.8.8.8,53',
    'distnoted,8.8.4.4,53',
    'distnoted,8.8.8.8,53',
    'dockerd,162.159.140.238,53',
    'EpicWebHelper,8.8.4.4,53',
    'EpicWebHelper,8.8.8.8,53',
    'gvproxy,170.247.170.2,53',
    'helm,185.199.108.133,53',
    'limactl,8.8.8.8,53',
    'Meeting Center,8.8.8.8,53',
    'msedge,8.8.4.4,53',
    'msedge,8.8.8.8,53',
    'node,149.22.90.225,5353',
    'nuclei,1.0.0.1,53',
    'Pieces OS,8.8.4.4,53',
    'Pieces OS,208.67.222.222,53',
    'plugin-container,8.8.8.8,53',
    'ServiceExtension,8.8.8.8,53',
    'signal-desktop,8.8.8.8,53',
    'Signal Helper (Renderer),8.8.8.8,53',
    'slack,8.8.8.8,53',
    'snapd,185.125.188.54,53',
    'snapd,185.125.188.55,53',
    'snapd,185.125.188.58,53',
    'snapd,185.125.188.59,53',
    'Socket Process,8.8.8.8,53',
    'syncthing,46.162.192.181,53',
    'Telegram,8.8.8.8,53',
    'WebexHelper,8.8.8.8,53',
    'WhatsApp,1.1.1.1,53',
    'yum,208.67.222.222,53',
    'ZaloCall,8.8.8.8,53',
    'zed,8.8.8.8,53',
    'ZoomPhone,200.48.225.130,53',
    'ZoomPhone,200.48.225.146,53',
    'ZoomPhone,8.8.8.8,53'
  )
  -- Local DNS servers and custom clients go here
  AND basename NOT IN (
    'adguard_dns',
    'apk',
    'agentbeat',
    'apko',
    'canonical-livep',
    'chrome',
    'com.apple.WebKit.Networking',
    'com.docker.backend',
    'go',
    'wolfictl',
    'gvproxy',
    'grype',
    'incusd',
    'helm',
    'terraform-provi',
    'IPNExtension',
    'Jabra Direct Helper',
    'limactl',
    'mDNSResponder',
    'melange',
    'syncthing',
    'nessusd',
    'nuclei',
    'systemd-resolved',
    'WhatsApp'
  )
  AND p.name NOT IN ('Jabra Direct Helper', 'terraform-provi')
  -- Chromium/Electron apps seem to send stray packets out like nobodies business
  AND p.path NOT LIKE '%/%.app/Contents/MacOS/% Helper'
  AND p.path NOT LIKE '/snap/%'
  -- Workaround for the GROUP_CONCAT subselect adding a blank ent
GROUP BY
  s.remote_address,
  s.remote_port
HAVING
  remote_address != ''
