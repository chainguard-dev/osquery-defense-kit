-- Detects unexpected programs opening files in /dev on Linux
--
-- references:
--   * https://attack.mitre.org/techniques/T1056/001/ (Input Capture: Keylogging)
--
-- platform: darwin
-- tags: persistent state sniffer
SELECT
  pof.pid,
  pof.path AS device,
  s.authority,
  s.identifier,
  CONCAT (
    IIF(
      REGEX_MATCH (pof.path, '(/dev/.*)\d+$', 1) != '',
      REGEX_MATCH (pof.path, '(/dev/.*)\d+', 1),
      pof.path
    ),
    ',',
    REPLACE(
      p0.path,
      RTRIM(p0.path, REPLACE(p0.path, '/', '')),
      ''
    ),
    ',',
    s.authority,
    ',',
    s.identifier
  ) AS exception_key,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
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
  process_open_files pof
  LEFT JOIN processes p0 ON pof.pid = p0.pid
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  pof.path LIKE '/dev/%'
  AND pof.path NOT IN (
    '/dev/null',
    '/dev/ptmx',
    '/dev/random',
    '/dev/zero',
    '/dev/tty',
    '/dev/urandom'
  )
  AND pof.path NOT LIKE '/dev/ttys%'
  -- Assume SIP
  AND p0.path NOT LIKE '/System/%'
  AND p0.path NOT LIKE '/usr/libexec/%'
  AND p0.path NOT LIKE '/usr/sbin/%'
  AND exception_key NOT IN (
    '/dev/afsc_type,revisiond,Software Signing,com.apple.revisiond',
    '/dev/auditpipe,ir_agent,Developer ID Application: Rapid7 LLC (UL6CGN7MAL),ir_agent',
    '/dev/auditpipe,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF),io.osquery.agent',
    '/dev/auditpipe,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF),osqueryd',
    '/dev/auditsessions,GSSCred,Software Signing,com.apple.GSSCred',
    '/dev/bpf,packetbeat,Developer ID Application: Elasticsearch, Inc (2BT3HPN62Z),packetbeat',
    '/dev/auditsessions,TouchBarServer,Software Signing,com.apple.touchbarserver',
    '/dev/auditsessions,authd,Software Signing,com.apple.authd',
    '/dev/auditsessions,securityd,Software Signing,com.apple.securityd',
    '/dev/autofs,automountd,Software Signing,com.apple.automountd',
    '/dev/bpf,BDLDaemon,Developer ID Application: Bitdefender SRL (GUNFMW623Y),com.bitdefender.epsecurity.BDLDaemonApp',
    '/dev/bpf,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/bpf,core,Developer ID Application: TPZ Solucoes Digitais Ltda (X37R283V2T),com.topaz.warsaw.core',
    '/dev/bpf,packetbeat,Developer ID Application: Elasticsearch, Inc (2BT3HPN62Z),packetbeat',
    '/dev/bpf,com.bjango.istatmenus.daemon,Developer ID Application: Bjango Pty Ltd (Y93TK974AT),com.bjango.istatmenus',
    '/dev/console,dbeaver,Developer ID Application: DBeaver Corporation (42B6MDKMW8),org.jkiss.dbeaver.core.product',
    '/dev/console,kernelmanagerd,Software Signing,com.apple.kernelmanagerd',
    '/dev/console,launchd,Software Signing,com.apple.xpc.launchd',
    '/dev/console,launchd_sim,Software Signing,com.apple.xpc.launchd',
    '/dev/cu.BLTH,bluetoothd,Software Signing,com.apple.bluetoothd',
    '/dev/io,ControlCenter,Software Signing,com.apple.controlcenter',
    '/dev/bpf,MHLinkServer,Developer ID Application: Metric Halo Distribution, Inc. (X7EY8SFM86),com.mhlabs.mhlink.server',
    '/dev/io,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/io,WiFiAgent,Software Signing,com.apple.wifi.WiFiAgent',
    '/dev/io,WirelessRadioManagerd,Software Signing,com.apple.WirelessRadioManagerd',
    '/dev/io,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io,symptomsd,Software Signing,com.apple.symptomsd',
    '/dev/console,Arc,Developer ID Application: The Browser Company of New York Inc. (S6N382Y83G),company.thebrowser.Browser',
    '/dev/io8log,ControlCenter,Software Signing,com.apple.controlcenter',
    '/dev/io8log,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/io8log,WiFiAgent,Software Signing,com.apple.wifi.WiFiAgent',
    '/dev/io8log,WirelessRadioManagerd,Software Signing,com.apple.WirelessRadioManagerd',
    '/dev/io8log,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/cu.debug-console,ZwiftAppSilicon,Developer ID Application: Zwift, Inc (C2GM8Y9VFM),ZwiftAppSilicon',
    '/dev/io8log,symptomsd,Software Signing,com.apple.symptomsd',
    '/dev/io8logmt,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io8logtemp,ControlCenter,Software Signing,com.apple.controlcenter',
    '/dev/io8logtemp,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/io8logtemp,WiFiAgent,Software Signing,com.apple.wifi.WiFiAgent',
    '/dev/io8logtemp,WirelessRadioManagerd,Software Signing,com.apple.WirelessRadioManagerd',
    '/dev/io8logtemp,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io8logtemp,symptomsd,Software Signing,com.apple.symptomsd',
    '/dev/kbfuse,kbfs,Developer ID Application: Keybase, Inc. (99229SGT5K),kbfs',
    '/dev/kbfuse,keybase-redirector,Developer ID Application: Keybase, Inc. (99229SGT5K),keybase-redirector',
    '/dev/klog,syslogd,Software Signing,com.apple.syslogd',
    '/dev/macfuse,gcsfuse,,a.out',
    '/dev/macfuse,rclone,,a.out',
    '/dev/auditpipe,osqueryd,,',
    '/dev/oslog,logd,Software Signing,com.apple.logd',
    '/dev/pf,CloudflareWARP,Developer ID Application: Cloudflare Inc. (68WVV388M8),CloudflareWARP',
    '/dev/pf,mullvad-daemon,Developer ID Application: Mullvad VPN AB (CKG9MXH72F),mullvad-daemon',
    '/dev/shm,python3',
    '/dev/zero,bash,Software Signing,com.apple.bash',
    '/dev/tty.usbmodem21430,Bazecor Helper (Renderer),,',
    '/dev/xcpm,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/xcpm,systemstats,Software Signing,com.apple.systemstats',
    '/dev/xcpm,thermald,Software Signing,com.apple.thermald'
  )
GROUP BY
  pof.pid
