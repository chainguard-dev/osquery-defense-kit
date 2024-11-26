-- Unexpected programs listening on a TCP port.
--
-- references:
--   * https://attack.mitre.org/techniques/T1571/ (Non-Standard Port)
--
-- tags: persistent state net low
-- platform: darwin
SELECT
  lp.address,
  lp.port,
  lp.protocol,
  p.uid,
  p.pid,
  p.name,
  p.path,
  p.cmdline,
  p.cwd,
  hash.sha256,
  signature.authority AS program_authority,
  CONCAT (
    MIN(lp.port, 49152),
    ',',
    lp.protocol,
    ',',
    MIN(p.uid, 500),
    ',',
    p.name,
    ',',
    signature.authority
  ) AS exception_key
FROM
  listening_ports lp
  LEFT JOIN processes p ON lp.pid = p.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN signature ON p.path = signature.path
WHERE
  port != 0
  AND lp.address NOT IN ('224.0.0.251', '::1')
  AND lp.address NOT LIKE '127.0.0.%'
  AND lp.address NOT LIKE '172.1%'
  AND lp.address NOT LIKE 'fe80::%'
  AND lp.address NOT LIKE '::ffff:127.0.0.%' -- All outgoing UDP (protocol 17) sessions are 'listening'
  AND NOT (
    lp.protocol = 17
    AND lp.port > 1024
  ) -- Random webservers
  AND NOT (
    p.uid > 500
    AND lp.port IN (8000, 8080)
    AND lp.protocol = 6
  ) -- Filter out unmapped raw sockets
  AND NOT (p.pid == '') -- Exceptions: the uid is capped at 500 to represent regular users versus system users
  -- port is capped at 49152 to represent transient ports
  AND NOT exception_key IN (
    '10011,6,0,launchd,Software Signing',
    '10011,6,0,webfilterproxyd,Software Signing',
    '1024,6,0,systemmigrationd,Software Signing',
    '10250,6,500,OrbStack Helper,Developer ID Application: Orbital Labs, LLC (U.S.) (HUAQ24HBR6)',
    '111,17,1,rpcbind,Software Signing',
    '111,6,1,rpcbind,Software Signing',
    '1144,6,500,fuscript,Developer ID Application: Blackmagic Design Inc (9ZGFBWLSYP)',
    '1234,6,500,qemu-system-aarch64,',
    '5001,6,500,Record It,Apple Mac OS Application Signing',
    '1313,6,500,hugo,',
    '1338,6,500,ec2-metadata-mock,',
    '1338,6,500,registry,',
    '4466,6,500,headlamp-server,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '137,17,0,launchd,Software Signing',
    '137,17,222,netbiosd,Software Signing',
    '138,17,0,launchd,Software Signing',
    '138,17,222,netbiosd,Software Signing',
    '15611,6,500,Postman,Developer ID Application: Postdot Technologies, Inc (H7H8Q7M5CK)',
    '16587,6,500,RescueTime,Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
    '17500,6,500,Dropbox,Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    '1824,6,500,WaveLink,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '1834,6,500,Camera Hub,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '2112,6,500,fake,',
    '49152,6,0,webfilterproxyd,Software Signing',
    '2112,6,500,rekor-server,',
    '2112,6,500,timestamp-server,',
    '22000,6,500,syncthing,',
    '22000,6,500,syncthing,Developer ID Application: Jakob Borg (LQE5SYM783)',
    '22000,6,500,syncthing,Developer ID Application: Kastelo AB (LQE5SYM783)',
    '22,6,0,launchd,Software Signing',
    '22,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '2345,6,500,dlv,',
    '24678,6,500,node,',
    '24800,6,500,deskflow-server,',
    '24800,6,500,synergy-core,Developer ID Application: Symless Ltd (4HX897Y6GJ)',
    '24802,6,500,synergy-service,Developer ID Application: Symless Ltd (4HX897Y6GJ)',
    '24851,6,500,HueSync,Developer ID Application: Signify Netherlands B.V. (PREPN2W95S)',
    '25565,6,500,java,',
    '26000,6,500,node20,Developer ID Application: Node.js Foundation (HX7739G8FX)',
    '27036,6,500,steam_osx,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '28197,6,500,Stream Deck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '28198,6,500,Stream Deck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '2968,6,500,EEventManager,Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    '33060,6,74,mysqld,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '3306,6,500,mariadbd,',
    '3306,6,74,mysqld,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '33333,6,500,Ultimate,',
    '49152,6,500,Windsurf Helper (Plugin),Developer ID Application: EXAFUNCTION, INC. (83Z2LHX6XW)',
    '3400,6,500,Sonos,Developer ID Application: Sonos, Inc. (2G4LW83Q3E)',
    '3491,6,500,MuteDeck,Developer ID Application: Martijn Smit (GX645XXEAX)',
    '3492,6,500,MuteDeck,Developer ID Application: Martijn Smit (GX645XXEAX)',
    '3493,6,500,MuteDeck,Developer ID Application: Martijn Smit (GX645XXEAX)',
    '4000,6,500,OrbStack Helper,Developer ID Application: Orbital Labs, LLC (U.S.) (HUAQ24HBR6)',
    '41949,6,500,IPNExtension,Apple Mac OS Application Signing',
    '43398,6,500,IPNExtension,Apple Mac OS Application Signing',
    '44000,6,500,Podman Desktop,Developer ID Application: Red Hat, Inc. (HYSCB8KRL2)',
    '443,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,crc,Developer ID Application: Red Hat, Inc. (HYSCB8KRL2)',
    '443,6,500,limactl,',
    '443,6,500,OrbStack Helper,Developer ID Application: Orbital Labs, LLC (U.S.) (HUAQ24HBR6)',
    '44450,6,500,Linear Helper,Developer ID Application: Linear Orbit, Inc. (7VZ2S3V9RV)',
    '44554,6,500,Luna Display,Developer ID Application: Astro HQ LLC (8356ZZ8Y5K)',
    '45972,6,500,IPNExtension,Apple Mac OS Application Signing',
    '46788,6,0,io.tailscale.ipn.macsys.network-extension,Developer ID Application: Tailscale Inc. (W5364U7YZB)',
    '4710,6,500,UA Mixer Engine,Developer ID Application: Universal Audio (4KAC9AX6CG)',
    '49152,6,0,AirPlayXPCHelper,Software Signing',
    '49152,6,0,io.tailscale.ipn.macsys.network-extension,Developer ID Application: Tailscale Inc. (W5364U7YZB)',
    '49152,6,0,launchd,Software Signing',
    '49152,6,0,remoted,Software Signing',
    '49152,6,0,remotepairingdeviced,Software Signing',
    '49152,6,500,AUHostingServiceXPC_arrow,Software Signing',
    '49152,6,500,barrier',
    '49152,6,500,CaptureCoreService,Developer ID Application: Capture One A/S (5WTDB5F65L)',
    '49152,6,500,Capture One,Developer ID Application: Capture One A/S (5WTDB5F65L)',
    '49152,6,500,com.adguard.mac.adguard.network-extension,Developer ID Application: Adguard Software Limited (TC3Q7MAJXF)',
    '49152,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,com.docker.supervisor,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,ContinuityCaptureAgent,Software Signing',
    '49152,6,500,Cypress,Developer ID Application: Cypress.Io, Inc. (7D655LWGLY)',
    '49152,6,500,dbeaver,Developer ID Application: DBeaver Corporation (42B6MDKMW8)',
    '49152,6,500,EcammLiveRemoteXPCServer,Developer ID Application: Ecamm Network, LLC (5EJH68M642)',
    '49152,6,500,GarageBand,Apple Mac OS Application Signing',
    '49152,6,500,git-daemon,',
    '49152,6,500,HP Smart,Apple Mac OS Application Signing',
    '49152,6,500,idea,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    '49152,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,500,java,Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
    '49152,6,500,java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '49152,6,500,jetbrains-toolbox,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    '49152,6,500,Logic Pro X,Apple Mac OS Application Signing',
    '49152,6,500,LogiMgrDaemon,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    '49152,6,500,logioptionsplus_agent,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    '49152,6,500,Luna Display,Developer ID Application: Astro HQ LLC (8356ZZ8Y5K)',
    '49152,6,500,Music,Software Signing',
    '49152,6,500,node,',
    '49152,6,500,qemu-system-aarch64,',
    '49152,6,500,rapportd,Software Signing',
    '49152,6,500,Resolve,Developer ID Application: Blackmagic Design Inc (9ZGFBWLSYP)',
    '49152,6,500,Signal,Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '49152,6,500,Signal Helper (Renderer),Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '49152,6,500,Signal Helper (Renderer),Developer ID Application: Signal Messenger, LLC (U68MSDN6DR)',
    '49152,6,500,siriactionsd,Software Signing',
    '49152,6,500,Sketch,Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
    '49152,6,500,SketchMirrorHelper,Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
    '49152,6,500,Spotify,Developer ID Application: Spotify (2FNC3A47ZF)',
    '49152,6,500,Stream Deck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '49152,6,500,telepresence,',
    '49152,6,500,vpnkit-bridge,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,Webcam-desktop,Developer ID Application: Shenzhen Arashi Vision Co., Ltd. (847R5ZLN8S)',
    '49152,6,500,WebexHelper,Developer ID Application: Cisco (DE8Y96K9QP)',
    '49152,6,500,WorkflowAppControl,Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    '49152,6,65,mDNSResponder,Software Signing',
    '5000,6,500,ControlCenter,Software Signing',
    '5001,6,500,crane,',
    '5001,6,500,gvproxy,',
    '500,6,8883,BambuStudio,BambuStudio,500u,80g',
    '5060,6,500,CommCenter,Software Signing',
    '53,17,500,dnsmasq,',
    '53,17,500,server,',
    '53,17,65,mDNSResponder,Software Signing',
    '53,6,500,dnsmasq,',
    '53,6,65,mDNSResponder,Software Signing',
    '5432,6,500,postgres,Developer ID Application: EnterpriseDB Corporation (26QKX55P9K)',
    '5432,6,500,postgres',
    '5433,6,500,postgres',
    '5454,6,0,xrdd,Developer ID Application: X-Rite, Incorporated (2K7GT73B4R)',
    '546,17,0,configd,Software Signing',
    '547,17,500,dhcp6d,Software Signing',
    '5900,6,0,launchd,Software Signing',
    '5900,6,0,screensharingd,Software Signing',
    '5990,6,500,goland,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    '6000,6,500,X11.bin,Developer ID Application: Apple Inc. - XQuartz (NA574AWV7E)',
    '631,6,0,cupsd,Software Signing',
    '67,17,0,bootpd,Software Signing',
    '67,17,0,launchd,Software Signing',
    '68,17,0,configd,Software Signing',
    '6996,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)',
    '7000,6,500,ControlCenter,Software Signing',
    '7265,6,500,Raycast,Developer ID Application: Raycast Technologies Inc (SY64MV22J9)',
    '8055,6,500,java,Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
    '80,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '80,6,500,crc,Developer ID Application: Red Hat, Inc. (HYSCB8KRL2)',
    '80,6,500,limactl,',
    '80,6,500,OrbStack Helper,Developer ID Application: Orbital Labs, LLC (U.S.) (HUAQ24HBR6)',
    '8081,6,500,crane,',
    '8123,6,500,Brackets-node,Developer ID Application: CORE.AI SCIENTIFIC TECHNOLOGIES PRIVATE LIMITED (8F632A866K)',
    '8125,6,500,Brackets-node,Developer ID Application: CORE.AI SCIENTIFIC TECHNOLOGIES PRIVATE LIMITED (8F632A866K)',
    '81,6,500,nginx,',
    '8770,6,500,sharingd,Software Signing',
    '8771,6,500,sharingd,Software Signing',
    '88,17,0,kdc,Software Signing',
    '8834,6,0,nessusd,Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    '88,6,0,kdc,Software Signing',
    '8888,6,500,otel-desktop-viewer,',
    '8933,6,500,WebexHelper,Developer ID Application: Cisco (DE8Y96K9QP)',
    '8934,6,500,WebexHelper,Developer ID Application: Cisco (DE8Y96K9QP)',
    '9101,6,500,github_actions_exporter,',
    '9991,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)'
  )
  AND NOT exception_key LIKE '%,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)'
  AND NOT exception_key LIKE '88%,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)'
  AND NOT exception_key LIKE '%,0,rpc.%,Software Signing'
  AND NOT (
    signature.authority = 'Developer ID Application: Linear Orbit, Inc. (7VZ2S3V9RV)'
    AND lp.port > 1024
  )
  AND NOT (
    signature.authority = 'Developer ID Application: Microsoft Corporation (UBF8T346G9)'
    AND lp.port > 5000
  )
  AND NOT (
    exception_key LIKE '%,6,500,IPNExtension,Apple Mac OS Application Signing'
    AND lp.port > 5000
  )
  AND NOT (
    exception_key LIKE '3%,6,500,java,'
    AND p.cwd LIKE '/Users/%'
  )
  AND NOT (
    p.path LIKE ',ko-app,%'
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    (
      p.name IN (
        'caddy',
        'com.docker.backend',
        'controller',
        'crane',
        'crc',
        'OrbStack Helper',
        'docker-proxy',
        'hugo',
        'kubectl',
        'ssh',
        'node',
        'webhook'
      )
      OR p.name LIKE 'kubectl.%'
      OR p.name LIKE '__%_go'
    )
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    p.path LIKE '/private/var/folders/%/go-build%/exe/%'
    AND lp.port > 1024
    AND lp.protocol = 6
  )
  AND NOT (
    (
      p.cwd LIKE '/Users/%/src/%'
      OR p.cwd LIKE '/Users/%/dev/%'
    )
    AND p.cmdline LIKE './%'
    AND lp.port > 1024
    AND lp.protocol = 6
  )
  AND NOT (
    (
      p.path = '/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/MacOS/ARDAgent'
      AND lp.port = 3283
      AND lp.protocol = 6
    )
  )
  AND NOT (
    (
      exception_key LIKE '80,6,500,ssh,Software Signing'
      AND p.cmdline LIKE '%/.colima/_lima/colima-docker/ssh.sock%'
    )
  )
GROUP BY
  exception_key
