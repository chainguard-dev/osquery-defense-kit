-- Unexpected programs communicating over non-HTTPS running from weird locations
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
  remote_address,
  pos.local_port,
  pos.local_address,
  CONCAT (MIN(p0.euid, 500), ',', s.authority) AS signed_exception,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    pos.protocol,
    ',',
    MIN(pos.remote_port, 32768),
    ',',
    COALESCE(REGEX_MATCH (p0.path, '.*/(.*?)$', 1), p0.name),
    ',',
    p0.name
  ) AS unsigned_exception,
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
  p1_hash.sha256 AS p1_sha256
FROM
  process_open_sockets pos
  LEFT JOIN processes p0 ON pos.pid = p0.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN signature s ON p0.path = s.path
WHERE
  pos.pid IN (
    SELECT
      pid
    from
      process_open_sockets
    WHERE
      protocol > 0
      AND local_port > 0
      AND remote_port > 0
      AND NOT (
        remote_port IN (53, 443)
        AND protocol IN (6, 17)
      )
      AND remote_address NOT IN (
        '0.0.0.0',
        '::127.0.0.1',
        '127.0.0.1',
        '::ffff:127.0.0.1',
        '::1',
        '::'
      )
      AND remote_address NOT LIKE 'fe80:%'
      AND remote_address NOT LIKE '127.%'
      AND remote_address NOT LIKE '192.168.%'
      AND remote_address NOT LIKE '172.1%'
      AND remote_address NOT LIKE '172.2%'
      AND remote_address NOT LIKE '169.254.%'
      AND remote_address NOT LIKE '172.30.%'
      AND remote_address NOT LIKE '172.31.%'
      AND remote_address NOT LIKE '::ffff:172.%'
      AND remote_address NOT LIKE '10.%'
      AND remote_address NOT LIKE '::ffff:10.%'
      AND remote_address NOT LIKE 'fc00:%'
      AND remote_address NOT LIKE 'fdfd:%'
      AND state != 'LISTEN'
  ) -- Ignore most common application paths
  AND protocol > 0
  AND p0.path NOT LIKE '/Applications/%.app/Contents/%/MacOS/%'
  AND p0.path NOT LIKE '/Applications/%.app/Contents/MacOS/%'
  AND p0.path NOT LIKE '/Applications/%.app/Contents/Resources/%'
  AND p0.path NOT LIKE '/Users/%/Applications/%.app/Contents/MacOS/%'
  AND p0.path NOT LIKE '/Library/Apple/%'
  AND p0.path NOT LIKE '/Library/Application Support/%/Contents/%'
  AND p0.path NOT LIKE '/opt/%/bin/%'
  AND p0.path NOT LIKE '/System/%'
  AND p0.path NOT LIKE '/Users/%/bin/%'
  AND p0.path NOT LIKE '/usr/bin/%'
  AND p0.path NOT LIKE '/usr/libexec/%'
  AND p0.path NOT LIKE '/usr/sbin/%'
  AND NOT signed_exception IN (
    '0,Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    '0,Developer ID Application: Tailscale Inc. (W5364U7YZB)',
    '0,Developer ID Application: Y Soft Corporation, a.s. (3CPED8WGS9)',
    '500,Apple Mac OS Application Signing',
    '500,Developer ID Application: Docker Inc (9BNSXJN65R)',
    '500,Developer ID Application: Adguard Software Limited (TC3Q7MAJXF)',
    '500,Developer ID Application: Autodesk (XXKJ396S2Y)',
    '500,Developer ID Application: AMZN Mobile LLC (94KV3E626L)',
    '500,Developer ID Application: Azul Systems, Inc. (TDTHCUPYFR)',
    '500,Developer ID Application: Blackmagic Design Inc (9ZGFBWLSYP)',
    '500,Developer ID Application: Cisco (DE8Y96K9QP)',
    '500,Developer ID Application: David Kocher (G69SCX94XU)',
    '500,Developer ID Application: Google LLC (EQHXZ8M8AV)',
    '500,Developer ID Application: JetBrains s.r.o. (2ZEFAR8TH3)',
    '500,Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    '500,Developer ID Application: ngrok LLC (TEX8MHRDQ9)',
    '500,Developer ID Application: Oracle America, Inc. (VB5E2TV963)',
    '500,Developer ID Application: Sky UK Limited (GJ24C8864F)',
    '500,Developer ID Application: Spotify (2FNC3A47ZF)',
    '500,Developer ID Application: The Browser Company of New York Inc. (S6N382Y83G)',
    '500,Developer ID Application: Valve Corporation (MXGJJ98X76)',
    '500,Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)',
    '500,Developer ID Application: Zwift, Inc (C2GM8Y9VFM)',
    '500,Software Signing'
  )
  AND NOT (
    unsigned_exception = '500,6,80,main,main'
    AND p0.path LIKE '/var/folders/%/T/go-build%/b001/exe/main'
  )
  AND NOT (
    unsigned_exception = '500,6,443,.Telegram-wrapped,.Telegram-wrapped'
    AND p0.path LIKE '/nix/store/%-telegram-desktop-%/Applications/Telegram.app/Contents/MacOS/Telegram'
  )
  -- port 0 means the connection has come and gone since the original process_open_sockets entry
  AND NOT unsigned_exception IN (
    '500,0,0,,',
    '500,0,0,.Telegram-wrapped,.Telegram-wrapped',
    '500,0,0,chainlink,chainlink',
    '500,0,0,git,git',
    '500,0,0,gvproxy,gvproxy',
    '500,0,0,jspawnhelper,jspawnhelper',
    '500,0,0,Python,Python',
    '500,17,0,com.adguard.mac.adguard.network-extension,com.adguard.mac.adguard.network-extension',
    '500,17,0,limactl,limactl',
    '500,17,123,gvproxy,gvproxy',
    '500,17,443,,',
    '500,17,53,gvproxy,gvproxy',
    '500,6,0,fuscript,fuscript',
    '500,6,0,gvproxy,gvproxy',
    '500,6,32768,cloud_sql_proxy,cloud_sql_proxy',
    '500,6,32768,gvproxy,gvproxy',
    '500,6,443,,',
    '500,6,443,.Telegram-wrapped,.Telegram-wrapped',
    '500,6,443,chainlink,chainlink',
    '500,6,443,cloud_sql_proxy,cloud_sql_proxy',
    '500,6,443,gvproxy,gvproxy',
    '500,6,5223,apsd,apsd',
    '500,6,5228,,',
    '500,6,5228,Google Chrome for Testing Helper,Google Chrome for Testing Helper',
    '500,6,80,.Telegram-wrapped,.Telegram-wrapped',
    '500,6,80,chainlink,chainlink',
    '500,6,8080,Python,Python',
    '500,6,90,java,java',
    '500,6,9418,git,git'
  )
GROUP BY
  p0.cmdline
