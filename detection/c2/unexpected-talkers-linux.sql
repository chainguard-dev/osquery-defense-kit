-- Programs communicating over the network in unexpected ways (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/
--
-- tags: transient state net rapid
-- platform: linux
SELECT
  s.family,
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
  s.net_namespace,
  pp.path AS parent_path,
  p.parent AS parent_pid,
  pp.cmdline AS parent_cmd,
  hash.sha256,
  CONCAT (
    MIN(s.remote_port, 32768),
    ',',
    protocol,
    ',',
    MIN(p.uid, 500),
    ',',
    p.name
  ) AS exception_key
FROM
  process_open_sockets s
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
WHERE
  protocol > 0
  AND s.remote_port > 0
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
  AND s.state != 'LISTEN' -- DNS clients
  AND NOT (
    remote_port = 53
    AND protocol IN (6, 17)
    AND p.name IN (
      '1password',
      'apt',
      'apt-get',
      'Brackets',
      'chainctl',
      'chrome',
      'chronyd',
      'cloud_sql_proxy',
      'code',
      'containerd',
      'controlplane',
      'crc',
      'curl',
      'dig',
      'dnf',
      'electron',
      'firefox',
      '.firefox-wrappe',
      'flameshot',
      'gh',
      'git-remote-http',
      'gitsign',
      'gnome-software',
      'go',
      'grafana-server',
      'grype',
      'host',
      'htop',
      'istioctl',
      'jcef_helper',
      'k6',
      'k9s',
      'ko',
      'kolide-pipeline',
      'launcher',
      'NetworkManager',
      'ngrok',
      'nix',
      'node',
      'nscd',
      'obs',
      'obs-browser-page',
      'obs-ffmpeg-mux',
      'obsidian',
      'opera',
      'pacman',
      'ping',
      'podman',
      'prometheus',
      'rootlessport',
      'signal-desktop',
      'slack',
      'slirp4netns',
      'snapd',
      'snap-store',
      'Socket Process',
      'spotify',
      'ssh',
      'steam',
      'steamwebhelper',
      'syncthing',
      'systemd-resolve',
      'tailscaled',
      '.tailscaled-wra',
      'terraform',
      'terraform-provi',
      'tkn',
      'traceroute',
      'vcluster',
      'wget',
      'whois',
      'xmobar',
      'yay',
      'zoom'
    )
  ) -- General exceptions
  AND NOT exception_key IN (
    '123,17,,',
    '123,17,500,chronyd',
    '22067,6,500,syncthing',
    '22,6,,',
    '22,6,500,ssh',
    '27024,6,500,steam',
    '3100,6,500,firefox',
    '3100,6,500,k6',
    '32768,6,0,tailscaled',
    '3307,6,500,cloud_sql_proxy',
    '4070,6,500,spotify',
    '443,17,500,chrome',
    '443,17,500,electron',
    '443,17,500,jcef_helper',
    '443,17,500,slack',
    '443,17,500,spotify',
    '443,6,0,apk',
    '443,6,0,containerd',
    '443,6,0,depmod',
    '443,6,0,dirmngr',
    '443,6,0,dnf',
    '443,6,0,dockerd',
    '443,6,0,influxd',
    '443,6,0,launcher',
    '443,6,0,nix',
    '443,6,0,nix-daemon',
    '443,6,0,packagekitd',
    '443,6,0,pacman',
    '443,6,0,snapd',
    '443,6,0,systemctl',
    '443,6,0,tailscaled',
    '443,6,0,.tailscaled-wra',
    '443,6,0,yum',
    '443,6,105,https',
    '443,6,472,grafana-server',
    '443,6,500,1password',
    '443,6,500,authentik-proxy',
    '443,6,500,aws',
    '443,6,500,Brackets',
    '443,6,500,celery',
    '443,6,500,chainctl',
    '443,6,500,chrome',
    '443,6,500,cloud_sql_proxy',
    '443,6,500,code',
    '443,6,500,containerd',
    '443,6,500,controlplane',
    '443,6,500,cosign',
    '443,6,500,crane',
    '443,6,500,CrBrowserMain',
    '443,6,500,crc',
    '443,6,500,CrUtilityMain',
    '443,6,500,curl',
    '443,6,500,Discord',
    '443,6,500,electron',
    '443,6,500,emacs',
    '443,6,500,firefox',
    '443,6,500,.firefox-wrappe',
    '443,6,500,flameshot',
    '443,6,500,geoclue',
    '443,6,500,gh',
    '443,6,500,git-remote-http',
    '443,6,500,gitsign',
    '443,6,500,gnome-shell',
    '443,6,500,gnome-software',
    '443,6,500,go',
    '443,6,500,___go_build_github_com_anchore_grype,a.out,',
    '443,6,500,grafana-server',
    '443,6,500,grype',
    '443,6,500,gunicorn',
    '443,6,500,gvfsd-http',
    '443,6,500,htop',
    '443,6,500,influxd',
    '443,6,500,istioctl',
    '443,6,500,java',
    '443,6,500,jcef_helper',
    '443,6,500,jetbrains-toolb',
    '443,6,500,k6',
    '443,6,500,k9s',
    '443,6,500,ko',
    '443,6,500,kolide-pipeline',
    '443,6,500,kubectl',
    '443,6,500,minicli',
    '443,6,500,ngrok',
    '443,6,500,nix',
    '443,6,500,node',
    '443,6,500,obs',
    '443,6,500,obs-browser-page',
    '443,6,500,obs-ffmpeg-mux',
    '443,6,500,obsidian',
    '443,6,500,pingsender',
    '443,6,500,pip',
    '443,6,500,podman',
    '443,6,500,signal-desktop',
    '443,6,500,slack',
    '443,6,500,slirp4netns',
    '443,6,500,snap-store',
    '443,6,500,Socket Process',
    '443,6,500,spotify',
    '443,6,500,steamwebhelper',
    '443,6,500,teams',
    '443,6,500,terraform',
    '443,6,500,terraform-provi',
    '443,6,500,tkn',
    '443,6,500,.tox-wrapped',
    '443,6,500,trivy',
    '443,6,500,vcluster',
    '443,6,500,vim',
    '443,6,500,WebKitNetworkPr',
    '443,6,500,wget',
    '443,6,500,wineserver',
    '443,6,500,x11-ssh-askpass',
    '443,6,500,xmobar',
    '443,6,500,yay',
    '443,6,500,zoom',
    '5228,6,500,chrome',
    '6000,6,500,ssh',
    '80,6,0,mkinitcpio',
    '67,17,0,NetworkManager',
    '7903,6,500,syncthing',
    '8006,6,500,chrome',
    '80,6,0,dnf',
    '80,6,0,gdk-pixbuf-quer',
    '80,6,0,NetworkManager',
    '80,6,0,pacman',
    '80,6,0,tailscaled',
    '80,6,0,.tailscaled-wra',
    '443,6,0,yay',
    '80,6,0,yum',
    '443,6,500,rustup',
    '443,6,500,cargo',
    '80,6,500,thunderbird',
    '80,6,105,http',
    '80,6,500,curl',
    '80,6,500,firefox',
    '80,6,500,.firefox-wrappe',
    '80,6,500,gitsign',
    '80,6,500,slack',
    '80,6,500,spotify',
    '80,6,500,steam',
    '80,6,500,steamwebhelper',
    '80,6,500,syncthing',
    '8801,17,500,zoom',
    '9090,6,500,firefox',
    '9090,6,500,k6',
    '9090,6,500,prometheus',
    '9090,6,500,rootlessport'
  ) -- These programs would normally never make an outgoing connection, but thanks to Nix, it can happen.
  AND NOT (
    (
      remote_address LIKE '151.101.%'
      OR remote_address LIKE '140.82.%'
    )
    AND remote_port = 443
    AND protocol = 6
    AND (
      parent_path LIKE '/nix/%/bin/bash'
      OR parent_path LIKE '/nix/%/bin/zsh'
      OR parent_path LIKE '%/bin/nix'
      OR p.path LIKE '/nix/store/%'
    )
  )
  AND NOT p.cmdline LIKE 'bash --rcfile /tmp/nix-shell.%' -- Other more complicated situations
  AND NOT (
    p.name = 'rootlessport'
    AND remote_port > 1024
  )
  AND NOT (
    p.name = 'syncthing'
    AND (
      remote_port IN (53, 80, 88, 110, 443, 587, 993, 3306, 7451)
      OR remote_port > 1024
    )
  )
  AND NOT (
    p.name IN (
      'chrome',
      'Google Chrome Helper',
      'Brave Browser Helper',
      'Chromium Helper',
      'Opera Helper'
    )
    AND remote_port IN (
      53,
      3100,
      443,
      80,
      8006,
      9000,
      5004,
      8009,
      8080,
      8888,
      8443,
      5228,
      32211,
      53,
      10001,
      3478,
      19305,
      19306,
      19307,
      19308,
      19309
    )
  )
  AND NOT (
    p.name IN ('thunderbird')
    AND remote_port IN (53, 143, 443, 587, 465, 585, 993)
  )
  AND NOT (
    p.name IN ('spotify', 'Spotify Helper', 'Spotify')
    AND remote_port IN (53, 443, 8009, 4070, 32211)
  )
  AND NOT (
    remote_port IN (443, 53)
    AND p.name LIKE 'terraform-provider-%'
  )
  AND NOT (
    remote_port IN (443, 53)
    AND p.name LIKE 'npm exec %'
  )
  AND NOT (
    remote_port iN (443, 53)
    AND p.name LIKE 'kubectl.%'
  )
  AND NOT (
    p.cmdline LIKE '%google-cloud-sdk/lib/gcloud.py%'
    AND remote_port IN (80, 53, 443)
  )
GROUP BY
  p.cmdline
