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
  AND NOT (p.pid = '') -- Exceptions: the uid is capped at 500 to represent regular users versus system users
  -- port is capped at 49152 to represent transient ports
  AND NOT exception_key IN (
    '10011,6,0,launchd,Software Signing',
    '10011,6,0,webfilterproxyd,Software Signing',
    '1024,6,0,systemmigrationd,Software Signing',
    '111,17,1,rpcbind,Software Signing',
    '111,6,1,rpcbind,Software Signing',
    '1144,6,500,fuscript,',
    '1234,6,500,qemu-system-aarch64,',
    '1313,6,500,hugo,',
    '1338,6,500,ec2-metadata-mock,',
    '1338,6,500,registry,',
    '137,17,0,launchd,Software Signing',
    '137,17,222,netbiosd,',
    '137,17,222,netbiosd,Software Signing',
    '138,17,0,launchd,Software Signing',
    '138,17,222,netbiosd,Software Signing',
    '2112,6,500,fake,',
    '2112,6,500,rekor-server,',
    '2112,6,500,timestamp-server,',
    '22,6,0,launchd,Software Signing',
    '22000,6,500,syncthing,',
    '2345,6,500,dlv,',
    '24678,6,500,node,',
    '24800,6,500,deskflow-server,',
    '25565,6,500,java,',
    '3306,6,500,mariadbd,',
    '33333,6,500,Ultimate,',
    '41949,6,500,IPNExtension,Apple Mac OS Application Signing',
    '43398,6,500,IPNExtension,Apple Mac OS Application Signing',
    '443,6,500,limactl,',
    '443,6,500,ssh,Software Signing',
    '45972,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,0,AirPlayXPCHelper,Software Signing',
    '49152,6,0,launchd,Software Signing',
    '49152,6,0,remoted,Software Signing',
    '49152,6,0,remotepairingdeviced,Software Signing',
    '49152,6,0,webfilterproxyd,Software Signing',
    '49152,6,500,AUHostingServiceXPC_arrow,Software Signing',
    '49152,6,500,ContinuityCaptureAgent,Software Signing',
    '49152,6,500,GarageBand,Apple Mac OS Application Signing',
    '49152,6,500,HP Smart,Apple Mac OS Application Signing',
    '49152,6,500,IPNExtension,Apple Mac OS Application Signing',
    '49152,6,500,Logic Pro X,Apple Mac OS Application Signing',
    '49152,6,500,Music,Software Signing',
    '49152,6,500,OmniFocus,Apple Mac OS Application Signing',
    '49152,6,500,barrier',
    '22,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '80,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '443,6,500,com.docker.backend,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '49152,6,500,git-daemon,',
    '49152,6,500,java,',
    '49152,6,500,node,',
    '49152,6,500,qemu-system-aarch64,',
    '49152,6,500,rapportd,Software Signing',
    '49152,6,500,siriactionsd,Software Signing',
    '49152,6,500,telepresence,',
    '49152,6,65,mDNSResponder,Software Signing',
    '500,6,8883,BambuStudio,BambuStudio,500u,80g',
    '5000,6,500,ControlCenter,Software Signing',
    '5001,6,500,Record It,Apple Mac OS Application Signing',
    '5001,6,500,crane,',
    '5060,6,500,CommCenter,Software Signing',
    '53,17,500,dnsmasq,',
    '53,17,500,server,',
    '53,17,65,mDNSResponder,',
    '53,17,65,mDNSResponder,Software Signing',
    '53,6,500,dnsmasq,',
    '53,6,65,mDNSResponder,Software Signing',
    '5432,6,500,postgres',
    '5433,6,500,postgres',
    '546,17,0,configd,Software Signing',
    '547,17,500,dhcp6d,',
    '547,17,500,dhcp6d,Software Signing',
    '5900,6,0,launchd,Software Signing',
    '5900,6,0,screensharingd,Software Signing',
    '6000,6,500,X11.bin,Developer ID Application: Apple Inc. - XQuartz (NA574AWV7E)',
    '631,6,0,cupsd,Software Signing',
    '6650,6,500,java,',
    '67,17,0,bootpd,Software Signing',
    '67,17,0,launchd,Software Signing',
    '68,17,0,configd,Software Signing',
    '7000,6,500,ControlCenter,Software Signing',
    '773,17,0,startupdiskhelper,Software Signing',
    '80,6,500,com.docker.backend,',
    '80,6,500,crc,',
    '80,6,500,limactl,',
    '80,6,500,ssh,Software Signing',
    '8055,6,500,java,',
    '8081,6,500,crane,',
    '8082,6,500,java,',
    '81,6,500,nginx,',
    '8770,6,500,sharingd,Software Signing',
    '88,17,0,kdc,Software Signing',
    '88,6,0,kdc,Software Signing',
    '8888,6,500,otel-desktop-viewer,',
    '9101,6,500,github_actions_exporter,'
  )
  AND NOT exception_key LIKE '%,0,rpc.%,Software Signing'
  AND NOT (
    lp.port > 1024
    AND lp.protocol = 6
    -- NOTE: Do not include 'Software Signing' in this list, as it may
    -- hide unanticipated uses of system utilities, like Screen Saharing.
    AND signature.authority IN (
      'Apple Development: Jakub Gluszkiewicz (2LC3SFDY52)',
      'Developer ID Application: ARDUINO SA (7KT7ZWMCJT)',
      'Developer ID Application: Adguard Software Limited (TC3Q7MAJXF)',
      'Developer ID Application: Apple Inc. - XQuartz (NA574AWV7E)',
      'Developer ID Application: Astro HQ LLC (8356ZZ8Y5K)',
      'Developer ID Application: Blackmagic Design Inc (9ZGFBWLSYP)',
      'Developer ID Application: Bohemian Coding (WUGMZZ5K46)',
      'Developer ID Application: Brother Industries, LTD. (5HCL85FLGW)',
      'Developer ID Application: CORE.AI SCIENTIFIC TECHNOLOGIES PRIVATE LIMITED (8F632A866K)',
      'Developer ID Application: Capture One A/S (5WTDB5F65L)',
      'Developer ID Application: Cisco (DE8Y96K9QP)',
      'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
      'Developer ID Application: Cypress.Io, Inc. (7D655LWGLY)',
      'Developer ID Application: DBeaver Corporation (42B6MDKMW8)',
      'Developer ID Application: Docker Inc (9BNSXJN65R)',
      'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
      'Developer ID Application: Duet, Inc. (J6L96W8A86)',
      'Developer ID Application: EXAFUNCTION, INC. (83Z2LHX6XW)',
      'Developer ID Application: Ecamm Network, LLC (5EJH68M642)',
      'Developer ID Application: Eclipse Foundation, Inc. (JCDTMS22B4)',
      'Developer ID Application: EnterpriseDB Corporation (26QKX55P9K)',
      'Developer ID Application: Jakob Borg (LQE5SYM783)',
      'Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
      'Developer ID Application: Kastelo AB (LQE5SYM783)',
      'Developer ID Application: Linear Orbit, Inc. (7VZ2S3V9RV)',
      'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
      'Developer ID Application: Loupedeck Oy (M24R8BN5BK)',
      'Developer ID Application: Martijn Smit (GX645XXEAX)',
      'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
      'Developer ID Application: Node.js Foundation (HX7739G8FX)',
      'Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
      'Developer ID Application: Orbital Labs, LLC (U.S.) (HUAQ24HBR6)',
      'Developer ID Application: Postdot Technologies, Inc (H7H8Q7M5CK)',
      'Developer ID Application: Quiet Riddle Ventures LLC (U68MSDN6DR)',
      'Developer ID Application: Raycast Technologies Inc (SY64MV22J9)',
      'Developer ID Application: Red Hat, Inc. (HYSCB8KRL2)',
      'Developer ID Application: Remo Tech Co.,Ltd. (7GJANK3822)',
      'Developer ID Application: RescueTime, Inc (FSY4RB8H39)',
      'Developer ID Application: Roon Labs LLC (WU8DGC424P)',
      'Developer ID Application: SOURCEGRAPH INC (74A5FJ7P96)',
      'Developer ID Application: Seiko Epson Corporation (TXAEAV5RN4)',
      'Developer ID Application: Shenzhen Arashi Vision Co., Ltd. (847R5ZLN8S)',
      'Developer ID Application: Signal Messenger, LLC (U68MSDN6DR)',
      'Developer ID Application: Signify Netherlands B.V. (PREPN2W95S)',
      'Developer ID Application: Sonos, Inc. (2G4LW83Q3E)',
      'Developer ID Application: Spotify (2FNC3A47ZF)',
      'Developer ID Application: Symless Ltd (4HX897Y6GJ)',
      'Developer ID Application: Tailscale Inc. (W5364U7YZB)',
      'Developer ID Application: Tenable, Inc. (4B8J598M7U)',
      'Developer ID Application: Universal Audio (4KAC9AX6CG)',
      'Developer ID Application: Valve Corporation (MXGJJ98X76)',
      'Developer ID Application: X-Rite, Incorporated (2K7GT73B4R)'
    )
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
        'docker-proxy',
        'gvproxy',
        'hugo',
        'kubectl',
        'node',
        'OrbStack Helper',
        'ssh',
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
    p.path = '/System/Library/CoreServices/UniversalControl.app/Contents/MacOS/UniversalControl'
    AND lp.port > 5000
  )
  AND NOT (
    (
      exception_key LIKE '80,6,500,ssh,Software Signing'
      AND p.cmdline LIKE '%/.colima/_lima/colima-docker/ssh.sock%'
    )
  )
GROUP BY
  exception_key
