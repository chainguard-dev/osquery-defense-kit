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
  hash.sha256
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
    '0.0.0.0',
    '100.100.100.100', -- Tailscale Magic DNS
    '1.0.0.1', -- Cloudflare
    '1.1.1.1', -- Cloudflare
    '1.1.1.2', -- Cloudflare
    '185.125.190.31', -- Canonical
    '185.125.190.77', -- Canonical
    '208.67.220.123', -- OpenDNS FamilyShield
    '208.67.222.222', -- OpenDNS
    '34.160.111.32', -- wolfi.dev
    '68.105.28.13', -- Cox
    '75.75.75.75', -- Comcast
    '75.75.76.76', -- Comcast
    '80.248.7.1', -- 21st Century (NG)
    '185.199.108.154' -- GitHub
  )
  -- Local DNS servers and custom clients go here
  AND basename NOT IN (
    'adguard_dns',
    'agentbeat',
    'apk',
    'apko',
    'AssetCacheLocatorService',
    'Beeper Desktop',
    'brave',
    'buildkitd',
    'canonical-livep',
    'CapCut',
    'cg',
    'chainctl',
    'ChatGPT',
    'chrome',
    'chromium',
    'cloudcode_cli',
    'git-lfs',
    'Code Helper (Plugin)',
    'com.apple.WebKit.Networking',
    'com.docker.backend',
    'com.docker.buil',
    'com.docker.build',
    'com.docker.vpnkit',
    'com.nordvpn.macos.helper',
    'containerd',
    'coredns',
    'Creative Cloud Content Manager.node',
    'distnoted',
    'docker-language-server-linux-amd64',
    'docker',
    'dockerd',
    'drkonqi-coredump-processor',
    'eksctl',
    'EpicWebHelper',
    'go',
    'grype',
    'gvproxy',
    'helm',
    'incusd',
    'io.tailscale.ipn.macsys.network-extension',
    'IPNExtension',
    'Jabra Direct Helper',
    'java',
    'launcher',
    'limactl',
    'librewolf',
    'mDNSResponder',
    'Meeting Center',
    'melange',
    'msedge',
    'nessusd',
    'node',
    'nuclei',
    'ollama',
    'Pieces OS',
    'plugin-container',
    'ServiceExtension',
    'Signal Helper (Renderer)',
    'signal-desktop',
    'slack',
    'snapd',
    'Socket Process',
    'syncthing',
    'systemd-resolved',
    'tailscaled',
    'Telegram',
    'terraform',
    'terraform-ls',
    'terraform-provi',
    'vunnel',
    'WebexHelper',
    'WhatsApp',
    'wolfictl',
    'yum',
    'ZaloCall',
    'zed',
    'ZoomPhone'
  )
  -- Chromium/Electron apps seem to send stray packets out like nobodies business
  AND basename NOT LIKE '% Helper'
  AND basename NOT LIKE 'terraform-provider-%'
  AND p.name != 'terraform-provi'
  AND p.path NOT LIKE '/snap/%'
  AND pp.path NOT IN ('/usr/bin/containerd-shim-runc-v2')
  -- Workaround for the GROUP_CONCAT subselect adding a blank ent
GROUP BY
  s.remote_address,
  s.remote_port
HAVING
  remote_address != ''
