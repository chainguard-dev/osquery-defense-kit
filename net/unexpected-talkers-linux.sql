SELECT
  s.family, protocol, s.local_port, s.remote_port, s.local_address,
  s.remote_address, p.name, p.path, p.cmdline AS child_cmd, p.cwd, s.pid, s.net_namespace,
  p.parent AS parent_pid, pp.cmdline AS parent_cmd, hash.sha256,
  CONCAT(MIN(s.remote_port, 32768), ",", protocol, ",", MIN(p.uid, 500), ",", p.name) AS exception_key
FROM process_open_sockets s
LEFT JOIN processes p ON s.pid = p.pid
LEFT JOIN processes pp ON p.parent = pp.pid
LEFT JOIN hash ON p.path = hash.path
WHERE protocol > 0
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
AND s.state != 'LISTEN'
AND NOT (remote_port=53 AND protocol IN (6,17)) -- Like, everything uses DNS
AND NOT exception_key IN (
      '22067,6,500,syncthing',
  '22,6,500,ssh',
    '22,6,,', -- shortlived SSH (git push)
    '27024,6,500,steam',
    '3307,6,500,cloud_sql_proxy',
    '4070,6,500,spotify',
    '443,17,500,chrome',
    '443,17,500,spotify',
    '443,6,0,dnf',
    '443,6,0,launcher',
    '443,6,0,pacman',
    '443,6,0,tailscaled',
    '443,6,0,.tailscaled-wra',
    '443,6,472,grafana-server',
    '443,6,500,1password',
    '443,6,500,chainctl',
    '443,6,500,chrome',
    '443,6,500,cloud_sql_proxy',
    '443,6,500,code',
    '443,6,500,containerd',
    '443,6,500,controlplane',
    '443,6,500,crc',
    '443,6,500,electron',
    '443,6,500,firefox',
    '443,6,500,.firefox-wrappe',
    '443,6,500,gh',
    '443,6,500,git-remote-http',
    '443,6,500,gitsign',
    '443,6,500,gnome-software',
    '443,6,500,go',
    '443,6,500,grype',
    '443,6,500,htop',
    '443,6,500,istioctl',
    '443,6,500,k6',
    '443,6,500,k9s',
    '443,6,500,ko',
    '443,6,500,kolide-pipeline',
    '443,6,500,ngrok',
    '443,6,500,nix',
    '443,6,500,node',
    '443,6,500,obs',
    '443,6,500,obs-browser-page',
    '443,6,500,obs-ffmpeg-mux',
    '443,6,500,obsidian',
    '443,6,500,signal-desktop',
    '443,6,500,slack',
    '443,6,500,snap-store',
    '443,6,500,spotify',
    '443,6,500,steamwebhelper',
    '443,6,500,terraform',
    '443,6,500,terraform-provi',
    '443,6,500,tkn',
    '123,17,500,chronyd',
    '443,6,500,vcluster',
    '443,6,500,xmobar',
    '443,6,500,yay',
    '443,6,500,zoom',
    '5228,6,500,chrome',
    '80,6,0,dnf',
    '80,6,0,NetworkManager',
    '80,6,0,.tailscaled-wra',
    '80,6,500,firefox',
    '80,6,500,steam',
    '80,6,500,syncthing'

)
AND NOT (p.name = 'syncthing' AND (remote_port IN (53,80,88,110,443,587,993,3306,7451) OR remote_port > 8000))
AND NOT (p.name IN ('chrome', 'Google Chrome Helper','Brave Browser Helper', 'Chromium Helper', 'Opera Helper') AND remote_port IN (443,80,8009,8080,8888,8443,5228,32211,53,10001,3478,19305,19306,19307,19308,19309))
AND NOT (p.name IN ('Mail', 'thunderbird', 'Spark', 'Notes') AND remote_port IN (143,443,587,465,585,993))
AND NOT (p.name IN ('spotify', 'Spotify Helper', 'Spotify') AND remote_port IN (53,443,8009,4070,32211))
AND NOT (remote_port=443 AND protocol=6 AND p.name LIKE 'terraform-provider-%')
AND NOT (remote_port=443 AND protocol=6 AND p.name LIKE 'kubectl.%')
AND NOT (p.cmdline LIKE '%google-cloud-sdk/lib/gcloud.py%' AND remote_port IN (80,443))
GROUP BY s.pid