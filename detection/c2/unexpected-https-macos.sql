-- Unexpected programs communicating over HTTPS (state-based)
--
-- references:
--   * https://attack.mitre.org/techniques/T1071/ (C&C, Application Layer Protocol)
--
-- tags: transient state net often
-- platform: macos
SELECT
  pos.protocol,
  pos.local_port,
  pos.remote_port,
  pos.remote_address,
  pos.local_port,
  pos.local_address,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    REGEX_MATCH (p0.path, '.*/(.*?)$', 1),
    ',',
    p0.name,
    ',',
    s.authority,
    ',',
    s.identifier
  ) AS exception_key,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    REGEX_MATCH (p0.path, '.*/(.*?)$', 1),
    ',',
    p0.name,
    ',',
    MIN(f.uid, 500),
    'u,',
    MIN(f.gid, 500),
    'g'
  ) AS alt_exception_key,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  s.authority AS p0_sauth,
  s.identifier AS p0_sid,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  process_open_sockets pos
  LEFT JOIN processes p0 ON pos.pid = p0.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN signature s ON p0.path = s.path
WHERE
  pos.protocol IN (6, 17)
  AND pos.remote_port = 443
  AND pos.remote_address NOT IN ('127.0.0.1', '::ffff:127.0.0.1', '::1')
  AND pos.remote_address NOT LIKE 'fe80:%'
  AND pos.remote_address NOT LIKE '127.%'
  AND pos.remote_address NOT LIKE '192.168.%'
  AND pos.remote_address NOT LIKE '172.1%'
  AND pos.remote_address NOT LIKE '172.2%'
  AND pos.remote_address NOT LIKE '172.30.%'
  AND pos.remote_address NOT LIKE '172.31.%'
  AND pos.remote_address NOT LIKE '::ffff:172.%'
  AND pos.remote_address NOT LIKE '10.%'
  AND pos.remote_address NOT LIKE '::ffff:10.%'
  AND pos.remote_address NOT LIKE 'fdfd:%'
  AND pos.remote_address NOT LIKE 'fc00:%'
  AND pos.state != 'LISTEN' -- Ignore most common application paths
  AND p0.path NOT LIKE '/Applications/%.app/Contents/%'
  AND p0.path NOT LIKE '/Library/Apple/System/Library/%'
  AND p0.path NOT LIKE '/Library/Application Support/%/Contents/%'
  AND p0.path NOT LIKE '/System/Applications/%'
  AND p0.path NOT LIKE '/System/Library/%'
  AND p0.path NOT LIKE '/Users/%/Library/%.app/Contents/MacOS/%'
  AND p0.path NOT LIKE '/Users/%/code/%'
  AND p0.path NOT LIKE '/Users/%/src/%'
  AND p0.path NOT LIKE '/Users/%/bin/%'
  AND p0.path NOT LIKE '/System/%'
  AND p0.path NOT LIKE '/opt/homebrew/Cellar/%/bin/%'
  AND p0.path NOT LIKE '/usr/libexec/%'
  AND p0.path NOT LIKE '/usr/sbin/%'
  AND p0.path NOT LIKE '/usr/local/kolide-k2/%'
  AND p0.path NOT LIKE '/private/var/folders/%/go-build%/%' -- Apple programs running from weird places, like the UpdateBrainService
  AND NOT (
    s.identifier LIKE 'com.apple.%'
    AND s.authority = 'Software Signing'
  )
  AND NOT exception_key IN (
    '0,AGSService,AGSService,Developer ID Application: Adobe Inc. (JQ525L2MZD),com.adobe.ags',
    '0,EdgeUpdater,EdgeUpdater,Developer ID Application: Microsoft Corporation (UBF8T346G9),com.microsoft.EdgeUpdater',
    '0,Install,Install,Developer ID Application: Adobe Inc. (JQ525L2MZD),com.adobe.Install',
    '0,Setup,Setup,Developer ID Application: Adobe Inc. (JQ525L2MZD),com.adobe.acc.Setup',
    '0,com.fortinet.forticlient.macos.vpn.nwextension,com.fortinet.forticlient.macos.vpn.nwextension,Developer ID Application: Fortinet, Inc (AH4XFXJ7DK),com.fortinet.forticlient.macos.vpn.nwextension',
    '0,com.google.one.NetworkExtension,com.google.one.NetworkExtension,Developer ID Application: Google LLC (EQHXZ8M8AV),com.google.one.NetworkExtension',
    '0,kandji-daemon,kandji-daemon,Developer ID Application: Kandji, Inc. (P3FGV63VK7),kandji-daemon',
    '0,kandji-library-manager,kandji-library-manager,Developer ID Application: Kandji, Inc. (P3FGV63VK7),kandji-library-manager',
    '0,kandji-parameter-agent,kandji-parameter-agent,Developer ID Application: Kandji, Inc. (P3FGV63VK7),kandji-parameter-agent',
    '0,launcher,launcher,Developer ID Application: Kolide, Inc (X98UFR7HA3),com.kolide.agent',
    '0,logioptionsplus_installer,logioptionsplus_installer,Developer ID Application: Logitech Inc. (QED4VVPZWA),com.logi.optionsplus.installer',
    '0,multipassd,multipassd,Developer ID Application: Canonical Group Limited (X4QN7LTP59),com.canonical.multipass.multipassd',
    '0,nessusd,nessusd,Developer ID Application: Tenable, Inc. (4B8J598M7U),nessusd',
    '500,Authy,Authy,Apple iPhone OS Application Signing,com.authy',
    '500,Signal Helper (Renderer),Signal Helper (Renderer),Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR),org.whispersystems.signal-desktop.helper.Renderer',
    '500,Code Helper (Plugin),Code Helper (Plugin),Developer ID Application: Microsoft Corporation (UBF8T346G9),com.github.Electron.helper',
    '500,Code Helper (Renderer),Code Helper (Renderer),Developer ID Application: Microsoft Corporation (UBF8T346G9),com.github.Electron.helper',
    '500,Code Helper,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9),com.microsoft.VSCode.helper',
    '500,Ecamm Live Stream Deck Plugin,Ecamm Live Stream Deck Plugin,Developer ID Application: Ecamm Network, LLC (5EJH68M642),Ecamm Live Stream Deck Plugin',
    '500,Electron,Electron,Developer ID Application: Microsoft Corporation (UBF8T346G9),com.microsoft.VSCode',
    '500,Elgato Capture Device Utility,Elgato Capture Device Utility,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5),com.elgato.CaptureDeviceUtility',
    '500,Fleet,~/Library/Caches/JetBrains/Fleet',
    '500,Install Spotify,Install Spotify,Developer ID Application: Spotify (2FNC3A47ZF),com.spotify.installer',
    '500,IterableRichNotifications,IterableRichNotifications,Apple iPhone OS Application Signing,com.plexapp.plex.IterableRichNotifications',
    '500,Java Updater,Java Updater,Developer ID Application: Oracle America, Inc. (VB5E2TV963),com.oracle.java.Java-Updater',
    '500,Kindle,Kindle,TestFlight Beta Distribution,com.amazon.Lassen',
    '500,OneDriveStandaloneUpdater,OneDriveStandaloneUpdater,Developer ID Application: Microsoft Corporation (UBF8T346G9),com.microsoft.OneDriveStandaloneUpdater',
    '500,Paintbrush,Paintbrush,Developer ID Application: Michael Schreiber (G966ML7VBG),com.soggywaffles.paintbrush',
    '500,PlexMobile,PlexMobile,Apple iPhone OS Application Signing,com.plexapp.plex',
    '500,Reflect Helper,Reflect Helper,Developer ID Application: Reflect App, LLC (789ULN5MZB),app.reflect.ReflectDesktop',
    '500,Reflect,Reflect,Developer ID Application: Reflect App, LLC (789ULN5MZB),app.reflect.ReflectDesktop',
    '500,SteelSeriesEngine,SteelSeriesEngine,Developer ID Application: SteelSeries (6WGL6CHFH2),SteelSeriesEngine',
    '500,SteelSeriesGG,SteelSeriesGG,Developer ID Application: SteelSeries (6WGL6CHFH2),SteelSeriesGG',
    '500,GitX,GitX,Developer ID Application: Farhan Ahmed (4RZN52RN5P),net.phere.GitX',
    '500,Transmit,Transmit,Developer ID Application: Panic, Inc. (VE8FC488U5),com.panic.Transmit',
    '500,TwitchStudioStreamDeck,TwitchStudioStreamDeck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5),TwitchStudioStreamDeck',
    '500,bash,bash,,bash',
    '500,Google Chrome Helper,Google Chrome Helper,Developer ID Application: Google LLC (EQHXZ8M8AV),com.google.Chrome.helper',
    '500,Slack Helper,Slack Helper,Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL),com.tinyspeck.slackmacgap.helper',
    '0,io.tailscale.ipn.macsys.network-extension,io.tailscale.ipn.macsys.network-extension,Developer ID Application: Tailscale Inc. (W5364U7YZB),io.tailscale.ipn.macsys.network-extension',
    '500,chrome_crashpad_handler,chrome_crashpad_handler,Developer ID Application: Microsoft Corporation (UBF8T346G9),chrome_crashpad_handler',
    '500,cloud_sql_proxy,cloud_sql_proxy,,a.out',
    '500,git-remote-http,git-remote-http,,git-remote-http-55554944748a32c47cdc35cfa7f071bb69a39ce4',
    '500,go,go,Developer ID Application: Google LLC (EQHXZ8M8AV),org.golang.go',
    '500,grype,grype,Developer ID Application: ANCHORE, INC. (9MJHKYX5AT),grype',
    '500,ksfetch,ksfetch,Developer ID Application: Google LLC (EQHXZ8M8AV),ksfetch',
    '500,melange,melange,,a.out',
    '500,ngrok,ngrok,Developer ID Application: ngrok LLC (TEX8MHRDQ9),a.out',
    '500,ngrok,ngrok,Developer ID Application: ngrok LLC (TEX8MHRDQ9),darwin_amd64',
    '500,node,node,Developer ID Application: Node.js Foundation (HX7739G8FX),node',
    '500,old,old,Developer ID Application: Denver Technologies, Inc (2BBY89MBSN),dev.warp.Warp-Stable',
    '500,op,op,Developer ID Application: AgileBits Inc. (2BUA8C4S2C),com.1password.op',
    '500,sdaudioswitch,sdaudioswitch,,sdaudioswitch',
    '500,snyk-ls_darwin_arm64,snyk-ls_darwin_arm64,,a.out',
    '500,steam_osx,steam_osx,Developer ID Application: Valve Corporation (MXGJJ98X76),com.valvesoftware.steam',
    '500,syncthing,syncthing,,syncthing',
    '500,terraform,terraform,Developer ID Application: Hashicorp, Inc. (D38WU7D763),terraform',
    '500,zoom.us,zoom.us,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3),us.zoom.xos'
  )
  AND NOT exception_key LIKE '500,tor-%-darwin-brave-%,tor-%-darwin-brave-%,Developer ID Application: Brave Software, Inc. (KL8N8XSYF4),tor-%-darwin-brave-%'
  AND NOT alt_exception_key IN (
    '0,velociraptor,velociraptor,0u,0g',
    '0,velociraptor,velociraptor,0u,80g',
    '500,apko,apko,0u,0g',
    '500,apko,apko,500u,20g',
    '500,aws,aws,0u,0g',
    '500,cargo,cargo,500u,80g',
    '500,chainctl,chainctl,0u,0g',
    '500,chainctl,chainctl,500u,20g',
    '500,chainlink,chainlink,500u,20g',
    '500,cilium,cilium,500u,123g',
    '500,cloud-sql-proxy,cloud-sql-proxy,500u,20g',
    '500,cosign,cosign,0u,500g',
    '500,snyk-macos-arm64,snyk-macos-arm64,500u,20g',
    '500,cosign,cosign,500u,20g',
    '500,cosign,cosign,500u,80g',
    '500,git-credential-osxkeychain,git-credential-osxkeychain,500u,80g',
    '500,cpu,cpu,500u,20g',
    '500,crane,crane,0u,500g',
    '500,crane,crane,500u,80g',
    '500,gh-dash,gh-dash,500u,20g',
    '500,git,git,0u,500g',
    '500,git-remote-http,git-remote-http,500u,20g',
    '500,git-remote-http,git-remote-http,500u,80g',
    '500,istioctl,istioctl,,a.out',
    '500,gitsign,gitsign,500u,20g',
    '500,go,go,500u,80g',
    '500,vexi,vexi,500u,20g',
    '500,.man-wrapped,.man-wrapped,0u,500g',
    '500,pprof,pprof,500u,80g',
    '500,pulumi-resource-gcp,pulumi-resource-gcp,500u,20g',
    '500,sdaudioswitch,sdaudioswitch,500u,20g',
    '500,sdzoomplugin,sdzoomplugin,500u,20g',
    '500,vim,vim,0u,500g',
    '500,wolfictl,wolfictl,500u,20g'
  )
  AND NOT alt_exception_key LIKE '500,terraform-provider-%,terraform-provider-%,500u,20g'
  AND NOT p0.path LIKE '/private/var/folders/%/T/GoLand/%'
  AND NOT (
    exception_key = '500,Python,Python,,org.python.python'
    AND p0_cmd LIKE '% main.py'
    AND p0_cwd LIKE "%/neko"
  )
  AND NOT (
    exception_key IN (
      '500,Python,Python,,org.python.python',
      '500,Python,Python,,Python',
      '500,Python,Python,,',
      '500,Python,Python,Developer ID Application: Ned Deily (DJ3H93M7VJ),org.python.python'
    )
    AND (
      p0_cmd LIKE '%/gcloud.py%'
      OR p0_cmd LIKE '%/google-cloud-sdk/bin/%'
      OR p0_cmd LIKE '%/google-cloud-sdk/platform/%'
      OR p0_cmd LIKE '%pip install%'
      OR p0_cmd LIKE '%googlecloudsdk/core/metrics_reporter.py%'
      OR p0_cmd LIKE '%/bin/aws%'
      OR p0_cmd LIKE "%/gsutil/gsutil %"
      OR p0_cwd LIKE "/Users/%/github/%"
      OR p0_cwd LIKE "/Users/%/src/%"
    )
  ) -- theScore and other iPhone apps
  AND NOT (
    s.authority = 'Apple iPhone OS Application Signing'
    AND p0.cwd = '/'
    AND p0.path = '/private/var/folders/%/Wrapper/%.app/%'
  ) -- nix socket inheritance
  AND NOT (
    p0.path LIKE '/nix/store/%/bin/%'
    AND p1.path LIKE '/nix/store/%/bin/%'
  )
GROUP BY
  p0.cmdline
