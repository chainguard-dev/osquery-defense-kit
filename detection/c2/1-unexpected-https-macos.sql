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
  AND p0.path NOT LIKE '/opt/%'
  AND p0.path NOT LIKE '/private/var/folders/%/go-build%/%' -- Apple programs running from weird places, like the UpdateBrainService
  AND p0.path NOT LIKE '/System/%'
  AND p0.path NOT LIKE '/System/Applications/%'
  AND p0.path NOT LIKE '/System/Library/%'
  AND p0.path NOT LIKE '/Users/%/bin/%'
  AND p0.path NOT LIKE '/Users/%/code/%'
  AND p0.path NOT LIKE '/Users/%/Library/%.app/Contents/MacOS/%'
  AND p0.path NOT LIKE '/Users/%/Library/Caches/JetBrains/%/tmp/GoLand/___%'
  AND p0.path NOT LIKE '/Users/%/src/%'
  AND p0.path NOT LIKE '/usr/libexec/%'
  AND p0.path NOT LIKE '/usr/local/kolide-k2/%'
  AND p0.path NOT LIKE '/usr/sbin/%'
  AND p0.path NOT LIKE '/nix/var/nix/profiles/default/bin/%'
  AND p0.path NOT LIKE '/nix/store/%/bin/%'
  AND NOT (
    s.identifier LIKE 'com.apple.%'
    AND s.authority = 'Software Signing'
  )
  AND NOT exception_key IN (
    '0,AGSService,AGSService,Developer ID Application: Adobe Inc. (JQ525L2MZD),com.adobe.ags',
    '0,at.obdev.littlesnitch.networkextension,at.obdev.littlesnitch.networkextension,Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R),at.obdev.littlesnitch.networkextension',
    '0,chainctl,chainctl,,a.out',
    '0,com.nordvpn.macos.helper,com.nordvpn.macos.helper,Developer ID Application: Nordvpn S.A. (W5W395V82Y),com.nordvpn.macos.helper',
    '0,licenseDaemon,licenseDaemon,Developer ID Application: PACE Anti-Piracy, Inc. (TFZ8226T6X),com.paceap.eden.licenseDaemon',
    '500,.Telegram-wrapped,.Telegram-wrapped,,Telegram',
    '500,agent,agent,Developer ID Application: Datadog, Inc. (JKFCB4CN7C),agent',
    '500,apko,apko,,a.out',
    '500,apkoaas,apkoaas,,a.out',
    '500,Arc Helper,Arc Helper,Developer ID Application: The Browser Company of New York Inc. (S6N382Y83G),company.thebrowser.browser.helper',
    '500,art,art,,a.out',
    '500,art,art,,a.out',
    '500,Authy,Authy,Apple iPhone OS Application Signing,com.authy',
    '500,bash,bash,,bash',
    '500,cloud_sql_proxy,cloud_sql_proxy,,a.out',
    '500,com.docker.backend,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R),com.docker.docker',
    '500,com.docker.build,com.docker.build,Developer ID Application: Docker Inc (9BNSXJN65R),com.docker',
    '500,copilot-language-server,copilot-language-server,Developer ID Application: GitHub (VEKTX9H2N7),copilot-language-server',
    '500,core,core,Developer ID Application: TPZ Solucoes Digitais Ltda (X37R283V2T),com.topaz.warsaw.core',
    '500,CrossyRoad,CrossyRoad,Apple iPhone OS Application Signing,com.hipsterwhale.crossy',
    '500,Fleet,~/Library/Caches/JetBrains/Fleet',
    '500,codebook-lsp,codebook-lsp,500u,20g',
    '500,gh,gh,,gh',
    '500,git-remote-http,git-remote-http,,git-remote-http-55554944748a32c47cdc35cfa7f071bb69a39ce4',
    '500,goland,goland,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.goland',
    '500,IterableRichNotifications,IterableRichNotifications,Apple iPhone OS Application Signing,com.plexapp.plex.IterableRichNotifications',
    '500,Java Updater,Java Updater,Developer ID Application: Oracle America, Inc. (VB5E2TV963),com.oracle.java.Java-Updater',
    '500,java,java,Developer ID Application: Azul Systems, Inc. (TDTHCUPYFR),com.azul.zulu.java',
    '500,java,java,Developer ID Application: Oracle America, Inc. (VB5E2TV963),com.oracle.java.8u401.java',
    '500,jcef Helper,jcef Helper,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),org.jcef.jcef.helper',
    '500,Kindle,Kindle,TestFlight Beta Distribution,com.amazon.Lassen',
    '500,krisp Helper,krisp Helper,Developer ID Application: Krisp Technologies, Inc. (U5R26XM5Z2),ai.krisp.krispMac.helper',
    '500,krisp,krisp,Developer ID Application: Krisp Technologies, Inc. (U5R26XM5Z2),ai.krisp.krispMac',
    '500,kubectl,kubectl,Developer ID Application: Docker Inc (9BNSXJN65R),kubectl',
    '500,melange,melange,,a.out',
    '500,nami,nami,,a.out',
    '500,ngrok,ngrok,Developer ID Application: ngrok LLC (TEX8MHRDQ9),a.out',
    '500,node,node,Developer ID Application: Node.js Foundation (HX7739G8FX),node',
    '500,odo-darwin-amd64-b4853e1fa,odo-darwin-amd64-b4853e1fa,500u,20g',
    '500,Paintbrush,Paintbrush,Developer ID Application: Michael Schreiber (G966ML7VBG),com.soggywaffles.paintbrush',
    '500,Plex,Plex,Developer ID Application: Plex Inc. (K4QJ56KR4A),tv.plex.desktop',
    '500,PlexMobile,PlexMobile,Apple iPhone OS Application Signing,com.plexapp.plex',
    '500,podman,podman,Developer ID Application: Red Hat, Inc. (HYSCB8KRL2),podman',
    '500,PowerPoint,PowerPoint,Apple Development: Zack Hoherchak (SS9PSPF8UF),PowerPoint',
    '500,process-agent,process-agent,Developer ID Application: Datadog, Inc. (JKFCB4CN7C),process-agent',
    '500,proctor,proctor,,a.out',
    '500,pycharm,pycharm,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3),com.jetbrains.pycharm',
    '500,Realm,Realm,Apple iPhone OS Application Signing,camera.youpi.metareal',
    '500,sdaudioswitch,sdaudioswitch,,sdaudioswitch',
    '500,Signal Helper (Renderer),Signal Helper (Renderer),500u,20g',
    '500,Skitch,Skitch,Developer ID Application: Skitch Inc (J8RPQ294UB),com.skitch.skitch',
    '500,Sky Go,Sky Go,Developer ID Application: Sky UK Limited (GJ24C8864F),com.bskyb.skygoplayer',
    '500,snyk-ls_darwin_arm64,snyk-ls_darwin_arm64,,a.out',
    '500,syncthing,syncthing,,syncthing',
    '500,TextExpander,TextExpander,Developer ID Application: SmileOnMyMac, LLC (7PKJ6G4DXL),com.smileonmymac.textexpander',
    '500,trunk,trunk,Developer ID Application: Trunk Technologies, Inc. (LDR5F9BL92),trunk-cli',
    '500,WebexHelper,WebexHelper,Developer ID Application: Cisco (DE8Y96K9QP),Cisco-Systems.SparkHelper',
    '500,zed,zed,Developer ID Application: Zed Industries, Inc. (MQ55VZLNZQ),dev.zed.Zed'
  )
  AND NOT alt_exception_key IN (
    '0,velociraptor,velociraptor,0u,0g',
    '500,sdaudioswitch,sdaudioswitch,500u,0g',
    '500,Python,Python,0u,80g',
    '0,nix,nix,0u,350g',
    '0,velociraptor,velociraptor,0u,80g'
  )
  AND NOT alt_exception_key LIKE '500,%,500u,20g'
  AND NOT alt_exception_key LIKE '500,%,0u,0g'

  AND NOT s.authority IN (
    'Developer ID Application: Adguard Software Limited (TC3Q7MAJXF)',
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: AgileBits Inc. (2BUA8C4S2C)',
    'Developer ID Application: AMZN Mobile LLC (94KV3E626L)',
    'Developer ID Application: Bookry Ltd (4259LE8SU5)',
    'Developer ID Application: ANCHORE, INC. (9MJHKYX5AT)',
    'Developer ID Application: Autodesk (XXKJ396S2Y)',
    'Developer ID Application: Bitdefender SRL (GUNFMW623Y)',
    'Developer ID Application: Brave Software, Inc. (KL8N8XSYF4)',
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Determinate Systems, Inc. (X3JQ4VPJZ6)',
    'Developer ID Application: Denver Technologies, Inc (2BBY89MBSN)',
    'Developer ID Application: Determinate Systems, Inc. (X3JQ4VPJZ6)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Ecamm Network, LLC (5EJH68M642)',
    'Developer ID Application: Elasticsearch, Inc (2BT3HPN62Z)',
    'Developer ID Application: Farhan Ahmed (4RZN52RN5P)',
    'Developer ID Application: Fortinet, Inc (AH4XFXJ7DK)',
    'Developer ID Application: GitHub (VEKTX9H2N7)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Hashicorp, Inc. (D38WU7D763)',
    'Developer ID Application: Kandji, Inc. (P3FGV63VK7)',
    'Developer ID Application: Kolide, Inc (X98UFR7HA3)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Michael Schreiber (G966ML7VBG)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    'Developer ID Application: Panic, Inc. (VE8FC488U5)',
    'Developer ID Application: PSI Services LLC (73AT498HPV)',
    'Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    'Developer ID Application: Rapid7 LLC (UL6CGN7MAL)',
    'Developer ID Application: Reflect App, LLC (789ULN5MZB)',
    'Developer ID Application: Slack Technologies, Inc. (BQR82RBBHL)',
    'Developer ID Application: SLACK TECHNOLOGIES L.L.C. (BQR82RBBHL)',
    'Developer ID Application: Spotify (2FNC3A47ZF)',
    'Developer ID Application: SteelSeries (6WGL6CHFH2)',
    'Developer ID Application: Sublime HQ Pty Ltd (Z6D26JE4Y4)',
    'Developer ID Application: Tailscale Inc. (W5364U7YZB)',
    'Developer ID Application: TechSmith Corporation (7TQL462TU8)',
    'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    'Developer ID Application: The Browser Company of New York Inc. (S6N382Y83G)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)',
    'Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    'Developer ID Application: Zwift, Inc (C2GM8Y9VFM)'
  )
GROUP BY
  p0.cmdline
