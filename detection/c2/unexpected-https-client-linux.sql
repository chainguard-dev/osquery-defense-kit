-- Unexpected programs communicating over HTTPS (state-based)
--
-- This query is a bit awkward and hobbled due to the lack of osquery support
-- for looking up binary signatures in Linux.
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net often
-- platform: linux
SELECT
  s.remote_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  s.state,
  hash.sha256,
  -- This intentionally avoids file.path, as it won't join across mount namespaces
  CONCAT (
    MIN(p.euid, 500),
    ',',
    REPLACE(
      REPLACE(
        REGEX_MATCH (p.path, '(/.*?)/', 1),
        '/nix',
        '/usr'
      ),
      '/snap',
      '/opt'
    ),
    '/',
    REGEX_MATCH (p.path, '.*/(.*?)$', 1),
    ',',
    MIN(f.uid, 500),
    'u,',
    MIN(f.gid, 500),
    'g,',
    p.name
  ) AS exception_key
FROM
  process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON p.path = hash.path
WHERE
  protocol IN (6, 17)
  AND s.remote_port = 443
  AND s.remote_address NOT IN ('127.0.0.1', '::ffff:127.0.0.1', '::1')
  AND s.remote_address NOT LIKE 'fe80:%'
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND p.path != ''
  AND NOT exception_key IN (
    '0,/usr/dockerd,0u,0g,dockerd',
    '0,/usr/flatpak-system-helper,0u,0g,flatpak-system-',
    '0,/usr/launcher,0u,0g,launcher',
    '0,/usr/packagekitd,0u,0g,packagekitd',
    '0,/usr/tailscaled,0u,0g,tailscaled',
    '0,/usr/.tailscaled-wrapped,0u,0g,.tailscaled-wra',
    '500,/app/slack,u,g,slack',
    '500,/app/zoom.real,u,g,zoom.real',
    '500,/home/chainctl,500u,500g,chainctl',
    '500,/ko-app/chainctl,u,g,chainctl',
    '500,/ko-app/controlplane,u,g,controlplane',
    '500,/opt/chrome,0u,0g,chrome',
    '500,/opt/firefox,0u,0g,firefox',
    '500,/opt/slack,0u,0g,slack',
    '500,/opt/spotify,0u,0g,spotify',
    '500,/usr/chrome,0u,0g,chrome',
    '500,/usr/code,0u,0g,code',
    '500,/usr/curl,0u,0g,curl',
    '500,/usr/electron,0u,0g,electron',
    '500,/usr/firefox,0u,0g,firefox',
    '500,/usr/firefox,0u,0g,.firefox-wrappe',
    '500,/usr/flatpak-oci-authenticator,0u,0g,flatpak-oci-aut',
    '500,/usr/geoclue,0u,0g,geoclue',
    '500,/usr/gitsign,0u,0g,gitsign',
    '500,/usr/gnome-software,0u,0g,gnome-software',
    '500,/usr/kubectl,500u,500g,kubectl',
    '500,/usr/slack,0u,0g,slack',
    '500,/usr/syncthing,0u,0g,syncthing'
  ) -- stay weird, NixOS (Fastly nix mirror)
  AND NOT child_cmd = '/run/current-system/sw/bin/bash'
  AND NOT exception_key LIKE '500,/usr/node,0u,0g,npm exec %'
GROUP BY
  p.cmdline
