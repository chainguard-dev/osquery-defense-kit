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
  p.path AS program,
  p.name AS program_name,
  p.cmdline AS cmdline,
  hash.sha256,
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
      p.path,
      RTRIM(p.path, REPLACE(p.path, '/', '')),
      ''
    ),
    ',',
    s.authority,
    ',',
    s.identifier
  ) AS exception_key
FROM
  process_open_files pof
  LEFT JOIN processes p ON pof.pid = p.pid
  LEFT JOIN hash ON hash.path = p.path
  LEFT JOIN signature s ON p.path = s.path
WHERE
  pof.path LIKE '/dev/%'
  AND pof.path NOT IN (
    '/dev/null',
    '/dev/ptmx',
    '/dev/random',
    '/dev/tty',
    '/dev/urandom'
  )
  AND pof.path NOT LIKE '/dev/ttys%'
  -- Assume SIP
  AND p.path NOT LIKE '/System/%'
  AND p.path NOT LIKE '/usr/libexec/%'
  AND p.path NOT LIKE '/usr/sbin/%'
  AND exception_key NOT IN (
    '/dev/afsc_type,revisiond,Software Signing,com.apple.revisiond',
    '/dev/auditpipe,osqueryd,Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF),osqueryd',
    '/dev/auditsessions,authd,Software Signing,com.apple.authd',
    '/dev/auditsessions,GSSCred,Software Signing,com.apple.GSSCred',
    '/dev/auditsessions,securityd,Software Signing,com.apple.securityd',
    '/dev/auditsessions,TouchBarServer,Software Signing,com.apple.touchbarserver',
    '/dev/autofs,automountd,Software Signing,com.apple.automountd',
    '/dev/bpf,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/console,kernelmanagerd,Software Signing,com.apple.kernelmanagerd',
    '/dev/console,launchd,Software Signing,com.apple.xpc.launchd',
    '/dev/cu.BLTH,bluetoothd,Software Signing,com.apple.bluetoothd',
    '/dev/io8log,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io8log,ControlCenter,Software Signing,com.apple.controlcenter',
    '/dev/io8logmt,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io8log,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/io8log,symptomsd,Software Signing,com.apple.symptomsd',
    '/dev/io8logtemp,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io8logtemp,ControlCenter,Software Signing,com.apple.controlcenter',
    '/dev/io8logtemp,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/io8logtemp,symptomsd,Software Signing,com.apple.symptomsd',
    '/dev/io8logtemp,WiFiAgent,Software Signing,com.apple.wifi.WiFiAgent',
    '/dev/io8logtemp,WirelessRadioManagerd,Software Signing,com.apple.WirelessRadioManagerd',
    '/dev/io8log,WiFiAgent,Software Signing,com.apple.wifi.WiFiAgent',
    '/dev/io8log,WirelessRadioManagerd,Software Signing,com.apple.WirelessRadioManagerd',
    '/dev/io,airportd,Software Signing,com.apple.airport.airportd',
    '/dev/io,ControlCenter,Software Signing,com.apple.controlcenter',
    '/dev/io,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/io,symptomsd,Software Signing,com.apple.symptomsd',
    '/dev/io,WiFiAgent,Software Signing,com.apple.wifi.WiFiAgent',
    '/dev/io,WirelessRadioManagerd,Software Signing,com.apple.WirelessRadioManagerd',
    '/dev/klog,syslogd,Software Signing,com.apple.syslogd',
    '/dev/oslog,logd,Software Signing,com.apple.logd',
    '/dev/xcpm,PerfPowerServices,Software Signing,com.apple.PerfPowerServices',
    '/dev/xcpm,systemstats,Software Signing,com.apple.systemstats',
    '/dev/xcpm,thermald,Software Signing,com.apple.thermald'
  )
GROUP BY
  pof.pid
