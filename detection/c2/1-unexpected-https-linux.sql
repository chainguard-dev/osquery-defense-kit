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
  p.cgroup_path,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  s.local_address,
  s.local_port,
  s.state,
  hash.sha256,
  -- This intentionally avoids file.path, as it won't join across mount namespaces
  CONCAT (
    MIN(p.euid, 500),
    ',',
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
  AND p.path NOT LIKE '/app/bin/%'
  AND p.path NOT LIKE '/usr/bin/%'
  AND p.path NOT LIKE '/usr/local/bin/%'
  AND p.path NOT LIKE '/opt/%'
  AND NOT exception_key IN (
    '0,.tailscaled-wrapped,0u,0g,.tailscaled-wra',
    '0,agentbeat,0u,0g,agentbeat',
    '0,apk,u,g,apk',
    '0,applydeltarpm,0u,0g,applydeltarpm',
    '0,bash,0u,0g,bash',
    '0,bash,0u,0g,mkinitcpio',
    '0,bash,0u,0g,sh',
    '0,canonical-livepatchd,0u,0g,canonical-livep',
    '0,chainctl,0u,0g,chainctl',
    '0,chainctl,500u,500g,chainctl',
    '0,cmake,u,g,cmake',
    '0,containerd,u,g,containerd',
    '0,dirmngr,0u,0g,dirmngr',
    '0,dockerd,0u,0g,dockerd',
    '0,elastic-agent,0u,0g,elastic-agent',
    '0,elastic-agent,u,g,elastic-agent',
    '0,elastic-endpoint,0u,0g,elastic-endpoin',
    '0,filebeat,0u,0g,filebeat',
    '0,flatpak,0u,0g,flatpak',
    '0,flatpak-system-helper,0u,0g,flatpak-system-',
    '0,git-remote-http,0u,0g,git-remote-http',
    '0,go,0u,0g,go',
    '0,gtk4-update-icon-cache,0u,0g,gtk-update-icon',
    '0,http,0u,0g,https',
    '0,incusd,0u,0g,incusd',
    '0,ir_agent,0u,0g,ir_agent',
    '0,kmod,0u,0g,depmod',
    '0,launcher,0u,0g,launcher',
    '0,launcher,500u,500g,launcher',
    '0,ldconfig,0u,0g,ldconfig',
    '0,make,0u,0g,make',
    '0,melange,500u,500g,melange',
    '0,metricbeat,0u,0g,metricbeat',
    '0,multipassd,0u,0g,multipassd',
    '0,nessusd,0u,0g,nessusd',
    '0,nix,0u,0g,nix',
    '0,nix,0u,0g,nix-daemon',
    '0,orbit,0u,0g,orbit',
    '0,osqueryd,0u,0g,osqueryd',
    '0,packagekit-dnf-refresh-repo,0u,0g,packagekit-dnf-',
    '0,packagekitd,0u,0g,packagekitd',
    '0,packetbeat,0u,0g,packetbeat',
    '0,pacman,0u,0g,pacman',
    '0,rapid7_endpoint_broker,0u,0g,rapid7_endpoint',
    '0,rpi-imager,0u,0g,rpi-imager',
    '0,skopeo,0u,0g,skopeo',
    '0,snapd,0u,0g,snapd',
    '0,systemctl,0u,0g,systemctl',
    '0,tailscaled,0u,0g,tailscaled',
    '0,tailscaled,500u,500g,tailscaled',
    '0,velociraptor,0u,0g,velociraptor_cl',
    '0,yay,0u,0g,yay',
    '105,http,0u,0g,https',
    '106,geoclue,0u,0g,geoclue',
    '114,geoclue,0u,0g,geoclue',
    '115,geoclue,0u,0g,geoclue',
    '120,fwupdmgr,0u,0g,fwupdmgr',
    '128,fwupdmgr,0u,0g,fwupdmgr',
    '129,fwupdmgr,0u,0g,fwupdmgr',
    '42,http,0u,0g,https',
    '500,sus,500u,500g,sus'
  ) -- Exceptions where we have to be more flexible for the process name
  -- Regular user binaries
  AND NOT exception_key LIKE '500,%,500u,500g,%'
  AND NOT exception_key LIKE '500,%,0u,0g,%'
  AND NOT exception_key LIKE '500,%,u,g,%'
  AND NOT exception_key LIKE '0,python3.%,0u,0g,dnf'
  AND NOT exception_key LIKE '0,python3.%,0u,0g,dnf-automatic'
  AND NOT exception_key LIKE '0,python3.%,0u,0g,yum'
  AND NOT exception_key LIKE '0,python3.%,500u,500g,dnf-automatic'
  AND NOT (
    exception_key = '0,curl,0u,0g,curl'
    AND p.cmdline LIKE 'curl --fail %'
  ) -- Exclude processes running inside of containers
  AND NOT p.cgroup_path LIKE '/system.slice/docker-%'
  AND NOT p.cgroup_path LIKE '/system.slice/system.slice:docker:%'
  AND NOT p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%' -- Tests
  AND NOT p.path LIKE '/tmp/go-build%.test'
GROUP BY
  p.cmdline
