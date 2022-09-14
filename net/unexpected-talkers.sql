SELECT
  s.family, protocol, s.local_port, s.remote_port, s.local_address,
  s.remote_address, p.name, p.path, p.cmdline AS child_cmd, p.cwd, s.pid, s.net_namespace,
  p.parent AS parent_pid, pp.cmdline AS parent_cmd, hash.sha256
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
JOIN processes pp ON pp.pid = p.parent
JOIN hash ON p.path = hash.path
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
AND NOT (p.cmdline LIKE '%.com.flexibits.fantastical2.mac.helper' AND remote_port = 443)
AND NOT (p.cmdline LIKE '%google-cloud-sdk/lib/gcloud.py%' AND remote_port = 443)
AND NOT (p.name = 'launcher' AND p.cwd='/' AND remote_port=443 AND protocol=6)
-- See https://relays.syncthing.net/ for the hella-suspicious ports it connects to
AND NOT (p.name = 'syncthing' AND (remote_port IN (53,80,88,110,443,587,993,3306,7451) OR remote_port > 8000))
AND NOT (p.name = 'zoom.us' AND remote_port IN (443,8801))
AND NOT (p.name = 'avconferenced' AND remote_port = 1234)
AND NOT (p.name IN ('chrome', 'Google Chrome Helper', 'Chromium Helper', 'Opera Helper') AND remote_port IN (8080,8000,8008,8443,8888) AND remote_address LIKE '192.168.%')
AND NOT (p.name IN ('chrome', 'Google Chrome Helper','Brave Browser Helper', 'Chromium Helper', 'Opera Helper') AND remote_port IN (443,80,8009,8080,8888,8443,5228,32211,53,10001,3478,19305,19306,19307,19308,19309))
AND NOT (p.name IN ('Mail', 'thunderbird', 'Spark', 'Notes') AND remote_port IN (443,587,465,585,993))
AND NOT (p.name IN ('spotify', 'Spotify Helper', 'Spotify') AND remote_port IN (53,443,8009,4070,32211))
AND NOT (p.name='cloud_sql_proxy' AND remote_port IN (443,3307))
AND NOT (p.name='coredns' AND remote_port=53 AND protocol=17)
AND NOT (p.name='java' AND remote_port IN (30031,25565) AND protocol=6)
AND NOT (p.name='ssh' AND remote_port=22 AND protocol=6)
AND NOT (p.name='crc' AND remote_port IN (53,443) AND protocol IN (6,17))
AND NOT (p.name='systemd-resolve' AND remote_port=53 AND protocol=17)
AND NOT (p.path = '/usr/bin/dnf' AND remote_port IN (80,443))
AND NOT (p.path = '/usr/bin/gnome-software' AND remote_port = 443)
AND NOT (p.path = '/usr/bin/sample' AND remote_port = 443)
AND NOT (p.path = '/usr/lib/snapd/snapd' AND remote_port = 443)
AND NOT (p.path = '/usr/libexec/rapportd' AND remote_port > 49000 and protocol=6)
AND NOT (p.path IN ('/usr/libexec/timed', '/Applications/Red Hat OpenShift Local.app/Contents/Resources/crc') AND remote_port = 123) AND protocol=17
AND NOT (p.name IN ('chronyd', 'crc') AND remote_port = 123 AND protocol=17)
AND NOT (p.path = '/usr/libexec/trustd' AND remote_port IN (80,443))
AND NOT (p.path LIKE '/private/var/folders/%/Reflect 2.app/Contents/Frameworks/Reflect Helper.app/Contents/MacOS/Reflect Helper' AND p.cwd='/' AND remote_port=443 AND s.protocol IN (6,17))
AND NOT (p.path LIKE '/private/var/folders/%/Reflect 2.app/Contents/MacOS/Reflect' AND p.cwd='/' AND remote_port=443 AND s.protocol IN (6,17))
AND NOT (p.path LIKE '/Users/%/.cache/trunk/cli/%/trunk' AND remote_port=443 AND s.protocol=6)
AND NOT (p.path LIKE '/Users/%/Library/Application Support/WebEx Folder/%/Meeting Center.app/Contents/MacOS/Meeting Center' AND p.cwd='/' AND remote_port=443 AND protocol=6)
AND NOT (p.path LIKE '/Users/%/Library/Application Support/WebEx Folder/%/Meeting Center.app/Contents/MacOS/Meeting Center' AND p.cwd='/' AND remote_port=9000 AND protocol=17)
AND NOT (p.path LIKE '%/firefox' AND remote_port IN (443,80) OR remote_port > 1024)
AND NOT (p.path LIKE '%/NetworkManager' AND remote_port IN (67,80))
AND NOT (p.path LIKE '%tailscaled%' AND remote_port IN (443,80))
AND NOT (p.path LIKE '%tailscaled%' AND remote_port > 32000)
AND NOT (p.path LIKE '%Tailscale%' AND remote_port > 32000)
AND NOT (p.path='/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter' AND p.cwd='/' AND remote_port=4500 AND protocol=17)
AND NOT (p.path='/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter' AND p.cwd='/' AND remote_port=500 AND protocol=17)
AND NOT (p.path='/System/Library/Frameworks/CoreTelephony.framework/Support/CommCenter' AND p.cwd='/' AND remote_port>5000 AND protocol=6)
AND NOT (p.path='/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking' AND remote_port>1023 AND protocol=17)
AND NOT (p.path='/System/Library/PrivateFrameworks/ApplePushService.framework/apsd' AND p.cwd='/' AND remote_port=5223 AND protocol=6)
AND NOT (p.path='/usr/local/libexec/ReceiverHelper.app/Contents/MacOS/ReceiverHelper' AND p.cwd='/' AND remote_port=443 AND protocol=6)
AND NOT (remote_port = 443 AND protocol IN (6,17) AND p.path = '/usr/bin/yay')
AND NOT (remote_port = 443 AND protocol IN (6,17) AND p.cmdline = 'npm update')
AND NOT (remote_port IN (443,53) AND protocol IN (6,17) AND p.path = '/usr/sbin/mDNSResponder')
AND NOT (remote_port = 443 AND protocol=6 AND p.path LIKE '/usr/libexec/%')
AND NOT (remote_port IN (80, 443) AND protocol IN (6,17) AND p.path LIKE '/Applications/%.app/Contents/%')
AND NOT (remote_port IN (80, 443) AND protocol IN (6,17) AND p.path LIKE '/Library/Apple/System/Library/%')
AND NOT (remote_port IN (80, 443) AND protocol IN (6,17) AND p.name = 'ksfetch')
AND NOT (remote_port IN (80, 443) AND protocol IN (6,17) AND p.path LIKE '/System/Applications/%')
AND NOT (remote_port IN (80, 443) AND protocol IN (6,17) AND p.path LIKE '/System/Library/%')
AND NOT (remote_port IN (80, 443) AND protocol IN (6,17) AND parent_cmd = '/Applications/Minecraft.app/Contents/MacOS/launcher')
AND NOT (remote_port>49000 AND protocol IN (6,17) AND p.path LIKE '/System/Library/PrivateFrameworks/MobileDevice.framework/%')
AND NOT (remote_port IN (80,443,17) AND p.name='curl')
AND NOT (remote_port IN (53,443) AND protocol IN (6,17) AND p.name IN (
        '1password',
        'Acrobat Update Helper',
        'Adobe Desktop Service',
        'Brackets',
        'chainctl',
        'Code Helper',
        'code',
        'containerd',
        'controlplane',
        'electron',
        'figma_agent',
        'gh',
        'git-remote-http',
        'gitsign',
        'go',
        'grype',
        'htop',
        'istioctl',
        'jcef_helper',
        'k9s',
        'ko',
        'kolide-pipeline',
        'ktail',
        'kubectl',
        'launcher-Helper',
        'Microsoft Update Assistant',
        'ngrok',
        'nix',
        'node',
        'obs-browser-page',
        'obs-ffmpeg-mux',
        'obs',
        'obsidian',
        'pacman',
        'pingsender',
        'signal-desktop',
        'Slack Helper',
        'slack',
        'Slack',
        'snap-store',
        'steam_osx',
        'terraform-provi',
        'terraform',
        'tkn',
        'vcluster',
        'xmobar',
        'zoom'
    )
)
AND NOT (remote_port=443 AND protocol=6 AND p.name LIKE 'terraform-provider-%')
AND NOT (remote_port=443 AND protocol=6 AND p.name LIKE 'kubectl.%')

