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
    '0,/opt/snapd,0u,0g,snapd',
    '0,/usr/bash,0u,0g,mkinitcpio',
    '0,/usr/containerd,u,g,containerd',
    '0,/usr/dockerd,0u,0g,dockerd',
    '0,/usr/flatpak-system-helper,0u,0g,flatpak-system-',
    '0,/usr/launcher,0u,0g,launcher',
    '0,/usr/nix,0u,0g,nix',
    '0,/usr/packagekitd,0u,0g,packagekitd',
    '0,/usr/pacman,0u,0g,pacman',
    '0,/usr/python3.10,0u,0g,dnf',
    '0,/usr/python3.10,0u,0g,yum',
    '0,/usr/rpi-imager,0u,0g,rpi-imager',
    '0,/usr/snapd,0u,0g,snapd',
    '0,/usr/tailscaled,0u,0g,tailscaled',
    '0,/usr/.tailscaled-wrapped,0u,0g,.tailscaled-wra',
    '105,/usr/http,0u,0g,https',
    '500,/app/slack,u,g,slack',
    '500,/app/thunderbird,u,g,thunderbird',
    '500,/app/zoom.real,u,g,zoom.real',
    '500,/home/chainctl,500u,100g,chainctl',
    '500,/home/chainctl,500u,500g,chainctl',
    '500,/home/code,500u,500g,code',
    '500,/home/gitsign,500u,500g,gitsign',
    '500,/home/go,500u,500g,go',
    '500,/home/grype,500u,500g,grype',
    '500,/home/java,500u,500g,java',
    '500,/home/jcef_helper,500u,500g,jcef_helper',
    '500,/home/steam,500u,100g,steam',
    '500,/home/steamwebhelper,500u,100g,steamwebhelper',
    '500,/home/WPILibInstaller,500u,500g,WPILibInstaller',
    '500,/ko-app/chainctl,u,g,chainctl',
    '500,/ko-app/controlplane,u,g,controlplane',
    '500,/opt/1password,0u,0g,1password',
    '500,/opt/Brackets,0u,0g,Brackets',
    '500,/opt/chrome,0u,0g,chrome',
    '500,/opt/firefox,0u,0g,firefox',
    '500,/opt/firefox,0u,0g,Socket Process',
    '500,/opt/kubectl,0u,0g,kubectl',
    '500,/opt/slack,0u,0g,slack',
    '500,/opt/spotify,0u,0g,spotify',
    '500,/usr/abrt-action-generate-core-backtrace,0u,0g,abrt-action-gen',
    '500,/usr/cargo,0u,0g,cargo',
    '500,/usr/chainctl,0u,0g,chainctl',
    '500,/usr/chrome,0u,0g,chrome',
    '500,/usr/code,0u,0g,code',
    '500,/usr/cosign,500u,500g,cosign',
    '500,/usr/curl,0u,0g,curl',
    '500,/usr/electron,0u,0g,electron',
    '500,/usr/firefox,0u,0g,firefox',
    '500,/usr/firefox,0u,0g,.firefox-wrappe',
    '500,/usr/firefox,0u,0g,Socket Process',
    '500,/usr/flameshot,0u,0g,flameshot',
    '500,/usr/flatpak-oci-authenticator,0u,0g,flatpak-oci-aut',
    '500,/usr/geoclue,0u,0g,geoclue',
    '500,/usr/git-remote-http,0u,0g,git-remote-http',
    '500,/usr/gitsign,0u,0g,gitsign',
    '500,/usr/gnome-recipes,0u,0g,gnome-recipes',
    '500,/usr/gnome-shell,0u,0g,gnome-shell',
    '500,/usr/gnome-software,0u,0g,gnome-software',
    '500,/usr/go,0u,0g,go',
    '500,/usr/go,500u,500g,go',
    '500,/usr/gsd-datetime,0u,0g,gsd-datetime',
    '500,/usr/gvfsd-http,0u,0g,gvfsd-http',
    '500,/usr/java,0u,0g,java',
    '500,/usr/kubectl,500u,500g,kubectl',
    '500,/usr/rpi-imager,0u,0g,rpi-imager',
    '500,/usr/signal-desktop,0u,0g,signal-desktop',
    '500,/usr/slack,0u,0g,slack',
    '500,/usr/syncthing,0u,0g,syncthing',
    '500,/usr/terraform,0u,0g,terraform',
    '500,/usr/trivy,0u,0g,trivy',
    '500,/usr/WebKitNetworkProcess,0u,0g,WebKitNetworkPr',
    '500,/usr/xmobar,0u,0g,xmobar',
    '500,/usr/yay,0u,0g,yay'
  )
  -- Exceptions where we have to be more flexible for the process name
  AND NOT exception_key LIKE '500,/usr/node,0u,0g,npm exec %'
  AND NOT exception_key LIKE '500,%/terraform-provider-aws_%,500u,500g,terraform-provi'
  -- stay weird, NixOS (Fastly nix mirror)
  AND NOT (
    pp.cmdline = '/run/current-system/sw/bin/bash'
    AND p.path LIKE '/nix/store/%'
    AND s.remote_address LIKE '151.101.%'
    AND s.state = 'ESTABLISHED'
  )
  AND NOT (
    exception_key = '500,/tmp/main,500u,500g,main'
    AND p.path LIKE '/tmp/go-build%/exe/main'
  )
GROUP BY
  p.cmdline
