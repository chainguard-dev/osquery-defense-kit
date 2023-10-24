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
    '1024,6,0,systemmigrationd,Software Signing',
    '1313,6,500,hugo,',
    '1338,6,500,registry,',
    '137,17,0,launchd,Software Signing',
    '137,17,222,netbiosd,Software Signing',
    '138,17,0,launchd,Software Signing',
    '138,17,222,netbiosd,Software Signing',
    '16587,6,500,RescueTime,Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
    '17500,6,500,Dropbox,Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    '1834,6,500,Camera Hub,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '2112,6,500,fake,',
    '2112,6,500,rekor-server,',
    '3181,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)',
    '2112,6,500,timestamp-server,',
    '22,6,0,launchd,Software Signing',
    '22000,6,500,syncthing,',
    '22000,6,500,syncthing,Developer ID Application: Jakob Borg (LQE5SYM783)',
    '2345,6,500,dlv,',
    '24678,6,500,node,',
    '24802,6,500,synergy-service,Developer ID Application: Symless Ltd (4HX897Y6GJ)',
    '27036,6,500,steam_osx,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '28197,6,500,Stream Deck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '28198,6,500,Stream Deck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '2968,6,500,EEventManager,Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    '3080,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)',
    '3090,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)',
    '3180,6,500,sourcegraph-backend,Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)',
    '3306,6,500,mariadbd,',
    '3306,6,74,mysqld,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '33060,6,74,mysqld,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '3400,6,500,Sonos,Developer ID Application: Sonos, Inc. (2G4LW83Q3E)',
    '41949,6,500,IPNExtension,Apple Mac OS Application Signing',
    '43398,6,500,IPNExtension,Apple Mac OS Application Signing',
    '443,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,limactl,',
    '44450,6,500,Linear Helper,Developer ID Application: Linear Orbit, Inc. (7VZ2S3V9RV)',
    '44554,6,500,Luna Display,Developer ID Application: Astro HQ LLC (8356ZZ8Y5K)',
    '45972,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,0,AirPlayXPCHelper,Software Signing',
    '49152,6,0,launchd,Software Signing',
    '49152,6,0,remoted,Software Signing',
    '49152,6,0,remotepairingdeviced,Software Signing',
    '49152,6,500,EcammLiveRemoteXPCServer,Developer ID Application: Ecamm Network, LLC (5EJH68M642)',
    '49152,6,500,GarageBand,Apple Mac OS Application Signing',
    '49152,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,500,LogiMgrDaemon,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    '49152,6,500,Luna Display,Developer ID Application: Astro HQ LLC (8356ZZ8Y5K)',
    '49152,6,500,Music,Software Signing',
    '49152,6,500,Resolve,Developer ID Application: Blackmagic Design Inc (9ZGFBWLSYP)',
    '49152,6,500,Signal Helper (Renderer),Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '49152,6,500,Signal,Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
    '49152,6,500,Sketch,Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
    '49152,6,500,SketchMirrorHelper,Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
    '49152,6,500,Spotify,Developer ID Application: Spotify (2FNC3A47ZF)',
    '49152,6,500,Stream Deck,Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    '49152,6,500,Webcam-desktop,Developer ID Application: Shenzhen Arashi Vision Co., Ltd. (847R5ZLN8S)',
    '49152,6,500,WorkflowAppControl,Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    '49152,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,com.docker.supervisor,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,java,Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
    '49152,6,500,java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '49152,6,500,jetbrains-toolbox,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    '49152,6,500,logioptionsplus_agent,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    '49152,6,500,node,',
    '49152,6,500,rapportd,Software Signing',
    '49152,6,500,telepresence,',
    '49152,6,500,vpnkit-bridge,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '5000,6,500,ControlCenter,Software Signing',
    '5001,6,500,crane,',
    '5001,6,500,gvproxy,',
    '5060,6,500,CommCenter,Software Signing',
    '53,17,500,dnsmasq,',
    '53,17,65,mDNSResponder,Software Signing',
    '53,6,500,dnsmasq,',
    '53,6,65,mDNSResponder,Software Signing',
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
    '7000,6,500,ControlCenter,Software Signing',
    '80,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '80,6,500,limactl,',
    '8081,6,500,crane,',
    '81,6,500,nginx,',
    '49152,6,500,qemu-system-aarch64,',
    '8123,6,500,Brackets-node,Developer ID Application: CORE.AI SCIENTIFIC TECHNOLOGIES PRIVATE LIMITED (8F632A866K)',
    '8770,6,500,sharingd,Software Signing',
    '8771,6,500,sharingd,Software Signing',
    '88,17,0,kdc,Software Signing',
    '88,6,0,kdc,Software Signing',
    '8828,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8829,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8830,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8831,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8832,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8833,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8834,6,0,nessusd,Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    '8834,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8888,6,500,otel-desktop-viewer,',
    '9101,6,500,github_actions_exporter,'
  )
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
    p.path LIKE ',ko-app,%'
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    p.name IN (
      'caddy',
      'com.docker.backend',
      'controller',
      'crane',
      'docker-proxy',
      'hugo',
      'kubectl',
      'node',
      'webhook'
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
GROUP BY
  exception_key
