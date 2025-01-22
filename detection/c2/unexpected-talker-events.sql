-- Unexpected socket events
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net extra events
-- interval: 601
-- platform: posix
SELECT
  s.status,
  s.family,
  s.path,
  s.fd,
  REPLACE(s.remote_address, "::ffff:", "") AS remote_address,
  s.remote_port,
  s.local_port,
  COALESCE(REGEX_MATCH (s.path, '.*/(.*)', 1), s.path) AS basename,
  REPLACE(f.directory, u.directory, '~') AS homedir,
  CONCAT (
    MIN(s.auid, 500),
    ",",
    MIN(f.uid, 500),
    ",",
    MIN(s.remote_port, 32768),
    ",",
    COALESCE(REGEX_MATCH (s.path, '.*/(.*)', 1), s.path)
  ) as exception_key,
  RTRIM(
    COALESCE(
      REGEX_MATCH (
        REPLACE(f.directory, u.directory, '~'),
        '([/~].*?/.*?)/',
        1
      ),
      f.directory
    ),
    "/"
  ) AS top2_dir,
  -- Child
  s.path AS p0_path,
  s.pid AS p0_pid,
  s.auid AS p0_euid,
  TRIM(COALESCE(p.cmdline, pe.cmdline)) AS p0_cmd,
  TRIM(COALESCE(p.cwd, pe.cwd)) AS p0_cwd,
  hash.sha256 AS p0_sha256,
  -- Parent
  COALESCE(p.parent, pe.parent) AS p1_pid
FROM
  socket_events AS s
  LEFT JOIN process_events pe ON s.pid = pe.pid
  AND pe.time > (strftime('%s', 'now') -7200)
  LEFT JOIN processes p ON s.pid = p.pid
  LEFT JOIN file f ON s.path = f.path
  LEFT JOIN users u ON f.uid = u.uid
  LEFT JOIN hash ON s.path = hash.path
WHERE
  s.time > (strftime('%s', 'now') -600)
  AND s.action = "connect"
  AND s.remote_port > 10
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
  AND s.remote_address NOT LIKE '172.1%'
  AND s.remote_address NOT LIKE '172.2%'
  AND s.remote_address NOT LIKE '0000:%'
  AND s.remote_address NOT LIKE '172.30.%'
  AND s.remote_address NOT LIKE '172.31.%'
  AND s.remote_address NOT LIKE '::ffff:172.%'
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '::ffff:10.%'
  AND s.remote_address NOT LIKE '::ffff:192.168.%'
  AND s.remote_address NOT LIKE 'fc00:%'
  AND NOT s.path LIKE '/Applications/%' -- NOTE: Do not filter out /bin (bash) or /usr/bin (nc)
  AND NOT s.path LIKE '/private/var/folders/%/T/go-build%'
  AND NOT s.path = '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Resources/Java Updater.app/Contents/MacOS/Java Updater'
  AND NOT top2_dir IN (
    '/Library/Apple',
    '/Library/Application Support',
    '/Library/Developer',
    '/Library/Kandji',
    '/opt/homebrew',
    '/snap/firefox',
    '/System/Applications',
    '/System/Library',
    '/System/Volumes',
    '/usr/bin',
    '/usr/libexec',
    '/usr/local',
    '/usr/sbin',
    '~/.provisio',
    '~/Applications',
    '~/Apps',
    '~/bin',
    '~/code',
    '~/github',
    '~/go',
    '~/homebrew',
    '~/src',
    '~/work'
  )
  AND NOT homedir IN (
    '/opt/spotify',
    '/usr/lib/google-cloud-sdk/platform/bundledpythonunix/bin',
    '~/Library/Application Support/Foxit Software/Addon/Foxit PDF Reader/FoxitPDFReaderUpdateService.app/Contents/MacOS'
  )
  AND NOT exception_key IN (
    '0,velociraptor,velociraptor,500u,80g',
    '500,0,110,syncthing',
    '500,0,123,sntp',
    '500,0,1234,spotify',
    '500,0,20480,com.adguard.mac.adguard.network-extension',
    '500,0,20480,io.tailscale.ipn.macsys.network-extension',
    '500,0,22,ssh',
    '500,0,27668,com.adguard.mac.adguard.network-extension',
    '500,0,31488,sntp',
    '500,0,32768,Authy',
    '500,0,32768,BDLDaemon',
    '500,0,32768,com.adguard.mac.adguard.network-extension',
    '500,0,32768,com.apple.MobileSoftwareUpdate.UpdateBrainService',
    '500,0,32768,com.apple.NRD.UpdateBrainService',
    '500,0,32768,elastic-endpoint',
    '500,0,32768,firefox',
    '500,0,32768,git-remote-http',
    '500,0,32768,io.tailscale.ipn.macsys.network-extension',
    '500,0,32768,ir_agent',
    '500,0,32768,ksfetch',
    '500,0,32768,networkQuality',
    '500,0,32768,syncthing',
    '500,0,3478,firefox',
    '500,0,4070,spotify',
    '500,0,43,whois',
    '500,0,443,Authy',
    '500,0,443,BDCoreIssues',
    '500,0,443,BDLDaemon',
    '500,0,443,bdredline',
    '500,0,443,BDUpdDaemon',
    '500,0,443,Brackets',
    '500,0,443,chrome_crashpad_handler',
    '500,0,443,chrome',
    '500,0,443,com.adguard.mac.adguard.network-extension',
    '500,0,443,com.apple.MobileSoftwareUpdate.UpdateBrainService',
    '500,0,443,com.apple.NRD.UpdateBrainService',
    '500,0,443,com.bitdefender.cst.net.dci.dci-network-extension',
    '500,0,443,com.docker.backend',
    '500,0,443,com.fortinet.forticlient.macos.vpn.nwextension',
    '500,0,443,com.google.one.NetworkExtension',
    '500,0,443,curl',
    '500,0,443,docker-buildx',
    '500,0,443,elastic-agent',
    '500,0,443,elastic-endpoint',
    '500,0,443,electron',
    '500,0,443,filebeat',
    '500,0,443,firefox',
    '500,0,443,fwupdmgr',
    '500,0,443,git-remote-http',
    '500,0,443,gnome-software',
    '500,0,443,go',
    '500,0,443,http',
    '500,0,443,incusd',
    '500,0,443,io.tailscale.ipn.macsys.network-extension',
    '500,0,443,ir_agent',
    '500,0,443,kioslave5',
    '500,0,443,ksfetch',
    '500,0,443,launcher',
    '500,0,443,metricbeat',
    '500,0,443,nessusd',
    '500,0,443,networkQuality',
    '500,0,443,node',
    '500,0,443,OneDriveStandaloneUpdater',
    '500,0,443,packetbeat',
    '500,0,443,pingsender',
    '500,0,443,Python',
    '500,0,443,rapid7_endpoint_broker',
    '500,0,443,slack',
    '500,0,443,snapd',
    '500,0,443,spotify',
    '500,0,443,ssh',
    '500,0,443,syncthing',
    '500,0,443,terraform',
    '500,0,443,velociraptor',
    '500,0,443,wget',
    '500,0,5228,chrome',
    '500,0,53,Brackets',
    '500,0,53,chrome',
    '500,0,53,electron',
    '500,0,53,firefox',
    '500,0,53,git',
    '500,0,53,launcher',
    '500,0,53,nessusd',
    '500,0,53,NetworkManager',
    '500,0,53,slack',
    '500,0,53,spotify',
    '500,0,53,wget',
    '500,0,5632,ssh',
    '500,0,80,BDUpdDaemon',
    '500,0,80,chrome',
    '500,0,80,com.adguard.mac.adguard.network-extension',
    '500,0,80,com.apple.NRD.UpdateBrainService',
    '500,0,80,com.bitdefender.cst.net.dci.dci-network-extension',
    '500,0,80,electron',
    '500,0,80,filebeat',
    '500,0,80,firefox',
    '500,0,80,http',
    '500,0,80,incusd',
    '500,0,80,io.tailscale.ipn.macsys.network-extension',
    '500,0,80,ir_agent',
    '500,0,80,ksfetch',
    '500,0,80,metricbeat',
    '500,0,80,slack',
    '500,0,8080,com.bitdefender.cst.net.dci.dci-network-extension',
    '500,0,9,launcher',
    '500,0,9,snapd',
    '500,500,13568,Code Helper',
    '500,500,20480,Code Helper',
    '500,500,20480,Google Chrome Helper',
    '500,500,20480,GoogleUpdater',
    '500,500,20480,ksfetch',
    '500,500,22,ssh',
    '500,500,2304,cloud_sql_proxy',
    '500,500,2304,terraform-provider-google_v4.37.0_x5',
    '500,500,3024,ZwiftAppSilicon',
    '500,500,32768,Chromium Helper',
    '500,500,32768,cloud-sql-proxy',
    '500,500,32768,Code Helper',
    '500,500,32768,DropboxMacUpdate',
    '500,500,32768,Electron',
    '500,500,32768,G2MUpdate',
    '500,500,32768,GoogleUpdater',
    '500,500,32768,java',
    '500,500,32768,ksfetch',
    '500,500,32768,melange',
    '500,500,32768,Microsoft.ServiceHub.Controller',
    '500,500,32768,Microsoft.VisualStudio.Code.Server',
    '500,500,32768,Microsoft.VisualStudio.Code.ServiceHost',
    '500,500,32768,node',
    '500,500,32768,old',
    '500,500,32768,rzls',
    '500,500,32768,terraform-ls',
    '500,500,3307,cloud_sql_proxy',
    '500,500,4318,Code Helper (Plugin)',
    '500,500,443,Acrobat Updater',
    '500,500,443,apk',
    '500,500,443,aws',
    '500,500,443,chainctl',
    '500,500,443,Chromium Helper',
    '500,500,443,Cisco WebEx Start',
    '500,500,443,CleanMyMac X Updater',
    '500,500,443,cloud_sql_proxy',
    '500,500,443,Code Helper (Plugin)',
    '500,500,443,Code Helper (Renderer)',
    '500,500,443,Code Helper',
    '500,500,443,copilot-agent-macos-arm64',
    '500,500,443,DropboxMacUpdate',
    '500,500,443,Electron',
    '500,500,443,figma_agent',
    '500,500,443,gh',
    '500,500,443,git-remote-http',
    '500,500,443,gitsign',
    '500,500,443,GitX',
    '500,500,443,go',
    '500,500,443,Google Chrome Helper',
    '500,500,443,GoogleUpdater',
    '500,500,443,grype',
    '500,500,443,istioctl',
    '500,500,443,ksfetch',
    '500,500,443,kubectl',
    '500,500,443,Meeting Center',
    '500,500,443,minikube',
    '500,500,443,node',
    '500,500,443,old',
    '500,500,443,Signal Helper (Renderer)',
    '500,500,443,Signal',
    '500,500,443,sublime_text',
    '500,500,443,syft',
    '500,500,443,webexmtaV2',
    '500,500,443,wolfibump',
    '500,500,443,wolfictl',
    '500,500,443,ZwiftAppSilicon',
    '500,500,53,Code Helper',
    '500,500,53,gitsign',
    '500,500,53,Google Chrome Helper',
    '500,500,53,Meeting Center',
    '500,500,80,cloud_sql_proxy',
    '500,500,80,Code Helper (Plugin)',
    '500,500,80,Code Helper',
    '500,500,80,copilot-agent-macos-arm64',
    '500,500,80,elastic-agent',
    '500,500,80,firefox-bin',
    '500,500,80,Google Chrome Helper',
    '500,500,80,GoogleUpdater',
    '500,500,80,ksfetch',
    '500,500,80,node',
    '500,500,9000,Meeting Center',
    '500,99,13568,Slack Helper',
    '500,99,32768,Slack Helper',
    '500,99,32768,Slack',
    '500,99,443,Slack Helper',
    '500,99,443,Slack',
    '500,99,53,Slack Helper'
  )
  AND NOT exception_key LIKE '500,0,%,chrome'
  AND NOT exception_key LIKE '500,0,%,syncthing'
  AND NOT exception_key LIKE '500,500,%,chrome'
  AND NOT exception_key LIKE '500,500,%,Google Chrome Helper'
  AND NOT exception_key LIKE '500,500,2304,terraform%'
  AND NOT exception_key LIKE '500,500,32768,terraform-provider-%'
  AND NOT exception_key LIKE '500,500,443,___%_%'
  AND NOT exception_key LIKE '500,500,443,kubectl.%'
  AND NOT exception_key LIKE '500,500,443,terraform%'
  AND NOT exception_key LIKE '500,500,53,terraform%'
  AND NOT exception_key LIKE '500,500,80,terraform%'
  AND NOT p0_path LIKE '/private/var/folders/%/T/AppTranslocation/%/%.app/Contents/MacOS/%'
  AND NOT p0_path LIKE '/System/%'
  AND NOT p0_path LIKE '/Users/%/code/%'
  AND NOT p0_path LIKE '/Users/%/dev/%'
  AND NOT p0_path LIKE '/Users/%/go/%'
  AND NOT p0_path LIKE '/Users/%/Library/Caches/JetBrains/GoLand%'
  AND NOT p0_path LIKE '/Users/%/src/%'
  AND NOT (
    basename = "Python"
    AND (
      p0_cmd LIKE '%/gcloud.py%'
      OR p0_cmd LIKE '%/bin/aws%'
      OR p0_cmd LIKE '%/google-cloud-sdk/%'
      OR p0_cmd LIKE '%googlecloudsdk/%'
      OR p0_cmd LIKE '%pip install%'
      OR p0_cmd LIKE "%/gsutil/%"
    )
  )
GROUP BY
  s.pid,
  exception_key
