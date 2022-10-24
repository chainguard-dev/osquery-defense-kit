-- Detect unusual calls to osascript
--
-- false positives:
--   * none observed, but they are expected
--
-- interval: 60
-- platform: darwin
-- tags: process events
SELECT
  p.pid,
  p.path,
  TRIM(p.cmdline) AS cmd,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  p.syscall,
  pp.path AS parent_path,
  pp.name AS parent_name,
  TRIM(pp.cmdline) AS parent_cmd,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256,
  signature.identifier AS parent_identifier,
  signature.authority AS parent_auth,
  CONCAT(signature.identifier, ",", signature.authority, ",", SUBSTR(TRIM(p.cmdline), 0, 54)) AS exception_key
FROM
  uptime,
  process_events p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash  ON pp.path = hash.path
  LEFT JOIN signature ON pp.path = signature.path
WHERE
  p.path = '/usr/bin/osascript'
  AND p.time > (strftime('%s', 'now') -60)
  AND exception_key != 'com.vng.zalo,Developer ID Application: VNG ONLINE CO.,LTD (CVB6BX97VM),osascript -ss'
  AND cmd != 'osascript -e user locale of (get system info)'
  AND NOT (
    exception_key='org.python.python,,osascript' AND parent_cmd LIKE '% /opt/homebrew/bin/jupyter-notebook'
  )