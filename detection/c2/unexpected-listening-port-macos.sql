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
  AND lp.address NOT LIKE '::ffff:127.0.0.%'
  -- All outgoing UDP (protocol 17) sessions are 'listening'
  AND NOT (
    lp.protocol = 17
    AND lp.port > 1024
  )
  -- Random webservers
  AND NOT (
    p.uid > 500
    AND lp.port IN (8000, 8080)
    AND lp.protocol = 6
  )
  -- Filter out unmapped raw sockets
  AND NOT (p.pid == '')
  -- Exceptions: the uid is capped at 500 to represent regular users versus system users
  -- port is capped at 49152 to represent transient ports
  AND NOT exception_key IN (
    '10011,6,0,launchd,Software Signing',
    '1313,6,500,hugo,',
    '1338,6,500,registry,',
    '137,17,0,launchd,Software Signing',
    '137,17,222,netbiosd,Software Signing',
    '138,17,0,launchd,Software Signing',
    '138,17,222,netbiosd,Software Signing',
    '16587,6,500,RescueTime,Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
    '17500,6,500,Dropbox,Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    '2112,6,500,fake,',
    '2112,6,500,rekor-server,',
    '22000,6,500,syncthing,',
    '22,6,0,launchd,Software Signing',
    '24678,6,500,node,',
    '2968,6,500,EEventManager,Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
    '33060,6,74,mysqld,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '3306,6,500,mariadbd,',
    '3306,6,74,mysqld,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '3400,6,500,Sonos,Developer ID Application: Sonos, Inc. (2G4LW83Q3E)',
    '41949,6,500,IPNExtension,Apple Mac OS Application Signing',
    '43398,6,500,IPNExtension,Apple Mac OS Application Signing',
    '443,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '44450,6,500,Linear Helper,Developer ID Application: Linear Orbit, Inc. (7VZ2S3V9RV)',
    '45972,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,0,AirPlayXPCHelper,Software Signing',
    '49152,6,0,launchd,Software Signing',
    '49152,6,0,remoted,Software Signing',
    '49152,6,0,remotepairingdeviced,Software Signing',
    '49152,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,GarageBand,Apple Mac OS Application Signing',
    '49152,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,500,java,Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
    '49152,6,500,java,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '49152,6,500,jetbrains-toolbox,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    '49152,6,500,LogiMgrDaemon,Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    '49152,6,500,Music,Software Signing',
    '49152,6,500,node,',
    '49152,6,500,rapportd,Software Signing',
    '49152,6,500,Sketch,Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
    '49152,6,500,SketchMirrorHelper,Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
    '49152,6,500,Spotify,Developer ID Application: Spotify (2FNC3A47ZF)',
    '49152,6,500,telepresence,',
    '49152,6,500,vpnkit-bridge,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,WorkflowAppControl,Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
    '5000,6,500,ControlCenter,Software Signing',
    '5060,6,500,CommCenter,Software Signing',
    '546,17,0,configd,Software Signing',
    '5900,6,0,launchd,Software Signing',
    '5900,6,0,screensharingd,Software Signing',
    '6000,6,500,X11.bin,Developer ID Application: Apple Inc. - XQuartz (NA574AWV7E)',
    '631,6,0,cupsd,Software Signing',
    '68,17,0,configd,Software Signing',
    '7000,6,500,ControlCenter,Software Signing',
    '80,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '8770,6,500,sharingd,Software Signing',
    '88,17,0,kdc,Software Signing',
    '8828,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8829,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8830,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8831,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8832,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8833,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '8834,6,0,nessusd,Developer ID Application: Tenable, Inc. (4B8J598M7U)',
    '8834,6,500,Code Helper,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '88,6,0,kdc,Software Signing',
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
    p.path LIKE ',ko-app,%'
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    p.name IN ('hugo', 'node', 'com.docker.backend', 'kubectl')
    AND lp.port > 1024
    and lp.protocol = 6
  )
  AND NOT (
    p.path LIKE '/private/var/folders/%/go-build%/exe/%'
    AND lp.port > 1024
    AND lp.protocol = 6
  )
  AND NOT (
    p.cwd LIKE '/Users/%/src/%'
    AND p.cmdline LIKE './%'
    AND lp.port > 1024
    AND lp.protocol = 6
  )
GROUP BY
  exception_key
