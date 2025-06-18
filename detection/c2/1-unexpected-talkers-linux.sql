-- Unexpected programs communicating over non-HTTPS protocols (state-based)
--
-- This query is a bit awkward and hobbled due to the lack of osquery support
-- for looking up binary signatures in Linux.
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net rapid
-- platform: linux
SELECT
  s.remote_address,
  s.remote_port,
  s.local_port,
  s.local_address,
  p.name,
  p.path,
  p.cmdline AS child_cmd,
  p.cwd,
  p.euid,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  p.cgroup_path,
  s.state,
  hash.sha256,
  -- This intentionally avoids file.path, as it won't join across mount namespaces
  CONCAT (
    MIN(s.remote_port, 32768),
    ',',
    s.protocol,
    ',',
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
  protocol > 0
  AND s.remote_port > 0 -- See unexpected-https-client
  AND NOT (
    s.remote_port = 443
    AND protocol IN (6, 17)
  ) -- See unexpected-dns-traffic
  AND NOT (
    s.remote_port = 53
    AND protocol IN (6, 17)
  )
  AND s.remote_address NOT IN (
    '127.0.0.1',
    '::ffff:127.0.0.1',
    '::1',
    '::',
    '0.0.0.0'
  )
  AND s.remote_address NOT LIKE 'fe80:%'
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '100.7%'
  AND s.remote_address NOT LIKE '169.254.%'
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE '::ffff:192.168.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND p.path != ''
  AND NOT (
    s.remote_address LIKE '100.%'
    AND s.local_address LIKE '100.%'
    AND exception_key = '32768,6,%,sshd,0u,0g,sshd'
  )
  AND NOT exception_key IN (
    '123,17,106,chronyd,0u,0g,chronyd',
    '123,17,125,chronyd,0u,0g,chronyd',
    '123,17,473,chronyd,0u,0g,chronyd',
    '123,17,500,chronyd,0u,0g,chronyd',
    '19305,6,500,msedge,0u,0g,msedge',
    '21,6,0,rpm-ostree,0u,0g,rpm-ostree',
    '22,6,500,azure,500u,500g,azure',
    '22,6,500,gce,500u,500g,gce',
    '22,6,500,gcp,500u,500g,gcp',
    '25565,6,500,java,500u,500g,java',
    '25567,6,500,java,500u,500g,java',
    '27018,6,500,pasta.avx2,0u,0g,pasta.avx2',
    '32520,6,0,rpm-ostree,0u,0g,rpm-ostree',
    '32768,6,0,registry,u,g,registry',
    '32768,6,0,tailscaled,0u,0g,tailscaled',
    '32768,6,22,sshd-auth,0u,0g,sshd-auth',
    '32768,6,500,mumble,0u,0g,mumble',
    '32768,6,500,slirp4netns,0u,0g,slirp4netns',
    '4070,6,500,spotify,0u,0g,spotify',
    '4070,6,500,spotify,u,g,spotify',
    '4433,6,500,openssl,0u,0g,openssl',
    '4460,6,106,chronyd,0u,0g,chronyd',
    '4460,6,125,chronyd,0u,0g,chronyd',
    '49152,6,500,ContinuityCaptureAgent,Software Signing',
    '5222,6,500,msedge,0u,0g,msedge',
    '587,6,500,perl,0u,0g,git-send-email',
    '67,17,0,NetworkManager,0u,0g,NetworkManager',
    '80,6,0,dnf5,0u,0g,dnf',
    '80,6,0,dnf5,0u,0g,dnf5',
    '80,6,0,grep,0u,0g,grep',
    '80,6,0,incusd,0u,0g,incusd',
    '80,6,0,kmod,0u,0g,depmod',
    '80,6,0,kubelet,u,g,kubelet',
    '80,6,0,ldconfig,0u,0g,ldconfig',
    '80,6,0,melange,500u,500g,melange',
    '80,6,0,NetworkManager,0u,0g,NetworkManager',
    '80,6,0,packagekit-dnf-refresh-repo,0u,0g,packagekit-dnf-',
    '80,6,0,packagekitd,0u,0g,packagekitd',
    '80,6,0,pacman,0u,0g,pacman',
    '80,6,0,pdftex,0u,0g,pdftex',
    '80,6,0,python2.7,500u,500g,yum',
    '80,6,0,python3.10,0u,0g,dnf',
    '80,6,0,python3.10,0u,0g,dnf-automatic',
    '80,6,0,python3.10,0u,0g,yum',
    '80,6,0,python3.11,0u,0g,dnf',
    '80,6,0,python3.11,0u,0g,dnf-automatic',
    '80,6,0,python3.11,0u,0g,yum',
    '80,6,0,python3.12,0u,0g,apport-gtk',
    '80,6,0,python3.12,0u,0g,dnf',
    '80,6,0,python3.12,0u,0g,dnf-automatic',
    '80,6,0,python3.12,0u,0g,yum',
    '80,6,0,python3.12,500u,500g,dnf-automatic',
    '80,6,0,python3.9,u,g,yum',
    '80,6,0,rpm-ostree,0u,0g,rpm-ostree',
    '80,6,0,sort,0u,0g,sort',
    '80,6,0,systemd-hwdb,0u,0g,systemd-hwdb',
    '80,6,0,tailscaled,0u,0g,tailscaled',
    '80,6,0,wget,0u,0g,wget',
    '80,6,0,zstd,0u,0g,zstd',
    '80,6,0,zypper,0u,0g,Zypp-main',
    '80,6,100,http,0u,0g,http',
    '80,6,105,http,0u,0g,http',
    '80,6,42,http,0u,0g,http',
    '80,6,500,aws-iam-authenticator,0u,0g,aws-iam-authent',
    '80,6,500,brave,0u,0g,brave',
    '80,6,500,chrome,0u,0g,chrome',
    '80,6,500,chrome,u,g,chrome',
    '80,6,500,chromium,0u,0g,chromium',
    '80,6,500,cloud_sql_proxy,0u,0g,cloud_sql_proxy',
    '80,6,500,code,0u,0g,code',
    '80,6,500,code-oss,u,g,code-oss',
    '80,6,500,copilot-agent-linux,500u,500g,copilot-agent-l',
    '80,6,500,curl,0u,0g,curl',
    '80,6,500,dotnet,u,g,dotnet',
    '80,6,500,dropbox,500u,500g,dropbox',
    '80,6,500,electron,0u,0g,electron',
    '80,6,500,firefox,0u,0g,.firefox-wrappe',
    '80,6,500,firefox,0u,0g,firefox',
    '80,6,500,firefox-bin,0u,0g,firefox-bin',
    '80,6,500,firefox-bin,500u,500g,firefox-bin',
    '80,6,500,firefox-bin,u,g,firefox-bin',
    '80,6,500,firefox-esr,0u,0g,firefox-esr',
    '80,6,500,flatpak,0u,0g,flatpak',
    '80,6,500,git-remote-http,0u,0g,git-remote-http',
    '80,6,500,gnome-software,0u,0g,gnome-software',
    '80,6,500,http,0u,0g,http',
    '80,6,500,http,u,g,http',
    '80,6,500,java,0u,0g,java',
    '80,6,500,java,u,g,java',
    '80,6,500,librewolf,0u,0g,librewolf',
    '80,6,500,main,500u,500g,main',
    '80,6,500,mateweather-applet,0u,0g,mateweather-app',
    '80,6,500,mconvert,500u,500g,mconvert',
    '80,6,500,mediawriter,u,g,mediawriter',
    '80,6,500,melange,500u,500g,melange',
    '80,6,500,minecraft-launcher,500u,500g,minecraft-launc',
    '80,6,500,msedge,0u,0g,msedge',
    '80,6,500,obs-browser-page,u,g,obs-browser-pag',
    '80,6,500,ocsp.test,u,g,ocsp.test',
    '80,6,500,pacman,0u,0g,pacman',
    '80,6,500,python3.10,0u,0g,aws',
    '80,6,500,python3.10,0u,0g,yum',
    '80,6,500,python3.11,0u,0g,abrt-action-ins',
    '80,6,500,python3.11,0u,0g,dnf',
    '80,6,500,python3.11,0u,0g,yum',
    '80,6,500,python3.12,0u,0g,pull-lp-source',
    '80,6,500,qemu-system-x86_64,0u,0g,qemu-system-x86',
    '80,6,500,qemu-system-x86_64,500u,500g,qemu-system-x86',
    '80,6,500,rpi-imager,0u,0g,rpi-imager',
    '80,6,500,signal-desktop,0u,0g,signal-desktop',
    '80,6,500,signal-desktop,u,g,signal-desktop',
    '80,6,500,slack,0u,0g,slack',
    '80,6,500,slirp4netns,500u,500g,slirp4netns',
    '80,6,500,spotify,0u,0g,spotify',
    '80,6,500,spotify,500u,500g,spotify',
    '80,6,500,spotify,u,g,spotify',
    '80,6,500,spotify-launcher,0u,0g,spotify-launche',
    '80,6,500,steam,500u,100g,steam',
    '80,6,500,steam,500u,500g,steam',
    '80,6,500,steamwebhelper,500u,500g,steamwebhelper',
    '80,6,500,telegram-desktop,u,g,telegram-deskto',
    '80,6,500,terraform,0u,0g,terraform',
    '80,6,500,terraform,500u,500g,terraform',
    '80,6,500,thunderbird,0u,0g,thunderbird',
    '80,6,500,thunderbird,u,g,thunderbird',
    '80,6,500,thunderbird-bin,0u,0g,thunderbird-bin',
    '80,6,500,thunderbird-bin,u,g,thunderbird-bin',
    '80,6,500,updater,500u,500g,updater',
    '80,6,500,vlc,0u,0g,vlc',
    '80,6,500,WebKitNetworkProcess,0u,0g,WebKitNetworkPr',
    '80,6,500,wget,0u,0g,wget',
    '80,6,500,wine64-preloader,0u,0g,control.exe',
    '80,6,500,zen,u,g,zen',
    '80,6,500,zoom,0u,0g,zoom',
    '80,6,500,zoom.real,u,g,zoom.real',
    '80,6,500,ZoomWebviewHost,0u,0g,ZoomWebviewHost',
    '8000,6,500,brave,0u,0g,brave',
    '8000,6,500,chrome,0u,0g,chrome',
    '8000,6,500,firefox,0u,0g,firefox',
    '8080,6,500,bambu-studio,u,g,bambustu_main',
    '8080,6,500,brave,0u,0g,brave',
    '8080,6,500,chrome,0u,0g,chrome',
    '8080,6,500,firefox,0u,0g,firefox',
    '8080,6,500,goland,500u,500g,goland',
    '8080,6,500,goland,u,g,goland',
    '8080,6,500,idea,0u,0g,idea',
    '8080,6,500,java,u,g,java',
    '8080,6,500,msedge,0u,0g,msedge',
    '8080,6,500,pycharm,500u,500g,pycharm',
    '8080,6,500,python3.11,0u,0g,speedtest-cli',
    '8080,6,500,python3.12,u,g,hass',
    '8080,6,500,speedtest,0u,0g,speedtest',
    '8080,6,500,speedtest,500u,500g,speedtest',
    '8443,6,500,chrome,0u,0g,chrome',
    '8443,6,500,firefox,0u,0g,firefox',
    '8443,6,500,WebKitNetworkProcess,0u,0g,WebKitNetworkPr',
    '88,6,500,syncthing,0u,0g,syncthing',
    '8801,17,500,zoom,0u,0g,zoom',
    '8801,17,500,zoom.real,u,g,zoom.real',
    '8883,6,500,bambu-studio,u,g,bambustu_main',
    '8883,6,500,WebKitWebProcess,u,g,WebKitWebProces',
    '89,6,500,chrome,0u,0g,chrome',
    '8987,6,500,whois,0u,0g,whois',
    '9,17,0,launcher,0u,0g,launcher',
    '9418,6,0,git,0u,0g,git',
    '9418,6,500,git,0u,0g,git',
    '993,6,500,evolution,0u,0g,evolution',
    '993,6,500,mbsync,0u,0g,mbsync',
    '993,6,500,thunderbird,0u,0g,thunderbird',
    '993,6,500,thunderbird,u,g,thunderbird',
    '993,6,500,thunderbird-bin,0u,0g,thunderbird-bin',
    '9999,6,500,firefox,0u,0g,firefox'
  )
  AND NOT exception_key LIKE '%,6,500,nuclei,500u,500g,nuclei'
  AND NOT exception_key LIKE '%,6,500,ssh,0u,0g,ssh'
  AND NOT exception_key LIKE '80,6,500,terraform_1.1.5,500u,500g,terraform'
  AND NOT exception_key LIKE '%,6,0,rpm-ostree,0u,0g,rpm-ostree'
  AND NOT exception_key LIKE '%,6,0,sshd-session,0u,0g,sshd-session'
  AND NOT exception_key LIKE '%,6,22,sshd-auth,0u,0g,sshd-auth'

  AND NOT (
    s.remote_port = 80
    AND s.protocol = 6
    AND p.euid > 500
    AND (
      p.path LIKE '%/bin/%'
      OR p.path LIKE '/app/%'
      OR p.path LIKE '/opt/%'
    )
  )
  AND NOT (
    p.name = 'java'
    AND p.cmdline LIKE '/home/%/.local/share/JetBrains/Toolbox/%'
    AND s.remote_port > 1024
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'ruby'
    AND p.cmdline LIKE '%fluentd%'
    AND s.remote_port > 1024
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name IN ('java', 'jcef_helper')
    AND p.cmdline LIKE '/home/%/PhpStorm%'
    AND s.remote_port > 79
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'syncthing'
    AND f.filename = 'syncthing'
    AND s.remote_port > 900
    AND s.protocol = 6
    AND p.euid > 500
  )
  AND NOT (
    p.name IN ('chrome', 'chromium')
    AND f.filename IN ('chrome', 'chromium')
    AND s.remote_port > 1024
    AND s.protocol IN (6, 17)
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'steam'
    AND f.filename = 'steam'
    AND s.remote_port > 27000
    AND s.protocol IN (6, 17)
    AND p.euid > 500
  )
  AND NOT (
    p.name = 'brave'
    AND f.filename = 'brave'
    AND s.remote_port > 3000
    AND s.protocol IN (6, 17)
    AND p.euid > 500
  )
  AND NOT (
    p.name IN (
      'firefox',
      'firefox-bin',
      'firefox-esr',
      'librewolf'
    )
    AND f.filename IN (
      'firefox',
      'firefox-bin',
      'firefox-esr',
      'librewolf'
    )
    AND s.remote_port > 3000
    AND s.protocol IN (6, 17)
    AND p.euid > 500
  ) -- TODO: Move this to a custom override overlay, as it is extremely obscure (small ISP)
  AND NOT (
    exception_key = '32768,6,500,ssh,0u,0g,ssh'
    AND s.remote_port = 40022
  ) -- Qualys
  AND NOT (
    exception_key = '80,6,0,curl,0u,0g,curl'
    AND p.cgroup_path = '/system.slice/qualys-cloud-agent.service'
    AND child_cmd LIKE ' curl -sS -H Metadata:true http://169.254.169.254/metadata/instance%'
  )
  AND NOT (
    s.remote_port = 80
    AND (
      p.cgroup_path LIKE '/system.slice/docker-%'
      OR p.cgroup_path LIKE '/user.slice/user-%.slice/user@%.service/user.slice/nerdctl-%'
    )
  )
  AND NOT parent_cmd IN ('/opt/microsoft/msedge/msedge')
  AND NOT (
    exception_key LIKE '%,6,500,sshd-session,0u,0g,sshd-session'
    AND parent_cmd LIKE '%chainguard_dev%'
  )
  AND NOT p.path = '/opt/docker-desktop/bin/com.docker.backend'
GROUP BY
  p.cmdline
