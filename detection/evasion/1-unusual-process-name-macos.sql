-- Processes with executable names that feel weird
--
-- references:
--   * https://www.zscaler.com/blogs/security-research/peek-apt36-s-updated-arsenal
--
-- tags: persistent process
SELECT
  p0.name AS pname,
  COALESCE(REGEX_MATCH (p0.path, '.*/(.*)', 1), p0.path) AS basename,
  COALESCE(
    REGEX_MATCH (p0.name, '.*/.*\.([a-z]{2,4})$', 1),
    ""
  ) AS pext,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  s.authority AS p0_sauth,
  s.identifier AS p0_sid,
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
  processes p0
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.start_time < (strftime('%s', 'now') - 43200)
  AND (
    pname LIKE "%kthread%"
    OR pname LIKE '%xprotect%'
    OR pname LIKE "%-help"
    OR pname LIKE "%/%"
    OR pname LIKE "%acpi%"
    OR pname LIKE "%crypt%"
    OR pname LIKE "%flush%"
    OR pname LIKE "%initd%"
    OR pname LIKE "%irq%"
    OR pname LIKE "%kaudit%"
    OR pname LIKE "%kdev%"
    OR pname LIKE "%kdmp%"
    OR pname LIKE "%ksoft%"
    OR pname LIKE "%kswap%"
    OR pname LIKE "%kworker%"
    OR pname LIKE "%launchd%"
    OR pname LIKE "%nvme%"
    OR pname LIKE "%tasks%"
    OR pname LIKE "%thread%"
    OR pname LIKE "%user_dir%"
    OR pname LIKE "%xdg%"
    OR pname LIKE "%zswap%"
    OR pname LIKE "cpu%"
    OR pname LIKE "events%"
    OR pname LIKE "idle_%"
    OR pname LIKE "mm-%"
    OR pname LIKE "nm_%"
    OR pname LIKE "rcu%"
    OR REGEX_MATCH (pname, '([a-z]{16,})', 1) != ""
    OR REGEX_MATCH (pname, '([a-zA-Z0-9]{32,})', 1) != ""
    OR REGEX_MATCH (pname, '(\w{40,})', 1) != ""
    OR REGEX_MATCH (
      pname,
      '([a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+[a-z]+[A-Z]+)',
      1
    ) != ""
    OR REGEX_MATCH (pname, "([a-z].*[A-Z].*\d+.*[a-z].*\d+)", 1) != ""
    OR REGEX_MATCH (pname, "(\d.*[a-z].*\d.*[a-z].*\d+)", 1) != ""
    OR REGEX_MATCH (pname, "(\d{5,})", 1) != ""
    OR REGEX_MATCH (pname, "^(\d\d)", 1) != ""
    OR (
      REGEX_MATCH (pname, "^(\W)", 1) != ""
      AND NOT (
        p0.path LIKE "/nix/store/%/.%-wrapped"
        OR p0.path LIKE "/etc/profiles-per-user/%"
      )
    )
    OR (
      REGEX_MATCH (pname, "(\W)$", 1) != ""
      AND pname NOT LIKE "%)"
    )
    AND pext NOT IN ("", "gui", "cli", "us", "node", "com")
  )
  AND NOT pname IN (
    'at.obdev.littlesnitch.endpointsecurity',
    'at.obdev.littlesnitch.networkextension',
    'at.obdev.littlesnitchmini.networkextension',
    'BetterTouchToolAppleScriptRunner',
    'OneSignalNotificationServiceExtension',
    'BetterTouchToolAppleScriptRunner3',
    'BetterTouchToolShellScriptRunner',
    'com.microsoft.teams2.notificationcenter',
    'cpu',
    'dynamiclinkmanager',
    'dynamiclinkmediaserver',
    'EcammLiveVideoOutAssistantXPCHelper',
    'EncryptMe',
    'launchd_startx',
    'ThingsWidgetExtensionMacAppStore',
    'TwitterNotificationServiceExtension',
    'usercontextservice',
    'xdg-open'
  )
  -- example: 85C27NK92C.com.flexibits.fantastical2.mac.helper
  AND NOT pname LIKE '___1Test%'
  AND NOT pname LIKE '___Test%'
  AND NOT pname LIKE '__%go_build%'
  AND NOT pname LIKE '__debug_bin%'
  AND NOT pname LIKE '%-macos-arm64'
  AND NOT pname LIKE 'BetterTouchToolAppleScriptRunner%'
  AND NOT pname LIKE 'cody-engine-%'
  AND NOT pname LIKE 'debug.test%'
  AND NOT pname LIKE "%.com.flexibits.fantastical2.mac.helper"
  AND NOT s.authority IN (
    "Software Signing",
    "Apple Mac OS Application Signing"
  )
