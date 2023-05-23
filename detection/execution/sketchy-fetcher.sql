-- Suspicious URL requests by built-in fetching tools (state-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--   * https://attack.mitre.org/techniques/T1571/ (Non-Standard Port)
--
-- tags: transient process state
-- platform: posix
SELECT
  REGEX_MATCH (p0.cmdline, '(\w+:\/\/.*)\b', 1) AS url,
  REGEX_MATCH (p0.cmdline, '//(\d+\.\d+\.\d+\.\d+)[:/]', 1) AS ip,
  REGEX_MATCH (p0.cmdline, ':(\d+)', 1) AS port,
  REGEX_MATCH (p0.cmdline, '//([\w\-\.]+)[:/]', 1) AS addr,
  REGEX_MATCH (p0.cmdline, '//[\w\-\.]+\.(\w+)[:/]', 1) AS tld,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.start_time AS p0_start,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.start_time AS p1_start,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.start_time AS p2_start,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  -- NOTE: Sync remaining portion with sketchy-fetcher-events
  (
    INSTR(p0.cmdline, 'wget ') > 0
    OR INSTR(p0.cmdline, 'curl ') > 0
  )
  -- Sketchy fetcher events always seem to contain a switch
  AND p0.cmdline LIKE '%-%'
  AND p0.cmdline LIKE '%/%'
  AND (
    ip NOT IN ('', '127.0.0.1', '::1')
    OR port != ''
    OR tld NOT IN (
      '',
      'app',
      'ca',
      'cloud',
      'com',
      'de',
      'dev',
      'edu',
      'fun',
      'gov',
      'io',
      'md',
      'mil',
      'net',
      'org',
      'se',
      'sh',
      'so',
      'uk'
    )
    OR p0.cmdline LIKE '%chmod%'
    OR p0.cmdline LIKE '%.onion%'
    OR p0.cmdline LIKE '%tor2web%'
    OR p0.cmdline LIKE '%aliyun%'
    OR p0.cmdline LIKE '%pastebin%'
    OR p0.cmdline LIKE '%curl %--user-agent%'
    OR p0.cmdline LIKE '%curl -k%'
    OR p0.cmdline LIKE '%curl -sL %'
    OR p0.cmdline LIKE '%curl%-o-%'
    OR p0.cmdline LIKE '%curl%--insecure%'
    OR p0.cmdline LIKE '%wget %--user-agent%'
    OR p0.cmdline LIKE '%wget %--no-check-certificate%'
    OR p0.cmdline LIKE '%curl%--connect-timeout%'
    OR p0.cmdline LIKE '%wget -nc%'
    OR p0.cmdline LIKE '%wget -t%'
    OR p0.cmdline LIKE '%wget -q%'
    OR (
      p0.cmdline LIKE '%wget %'
      AND p0.euid < 500
      -- TODO: Update this query to understand containers
      AND p1.path NOT IN (
        "/usr/bin/bwrap",
        "/bin/busybox",
        "/usr/bin/melange"
      )
    )
    OR (
      p0.cmdline LIKE '%curl %'
      AND p0.euid < 500
      AND p0.cmdline NOT LIKE "%./configure %--with-curl%"
    )
  )
  -- Exceptions for all calls
  AND p1.name NOT IN ('makepkg') -- Exceptions for non-privileged calls
  AND NOT (
    p0.euid > 500
    AND (
      p0.cmdline LIKE '%--dump-header%'
      OR p0.cmdline LIKE '%/api/v%'
      OR p0.cmdline LIKE '%curl -X %'
      OR p0.cmdline LIKE '%go mod %'
      OR p0.cmdline LIKE '%application/json%'
      OR p0.cmdline LIKE '%grpcurl%'
      OR p0.cmdline LIKE '%Homebrew%'
      OR p0.cmdline LIKE '%Nixpkgs/%'
      OR p0.cmdline LIKE '%If-None-Match%'
      OR p0.cmdline LIKE '%ctlog%'
      OR p0.cmdline LIKE '%.well-known/openid-configuration%'
      OR p0.cmdline LIKE '%/openid/v1/jwks%'
      OR p0.cmdline LIKE '%--progress-bar%'
      OR p1.cmdline LIKE '%brew.rb%'
      OR p1.cmdline LIKE '%brew.sh%'
      OR p1.cmdline LIKE '/nix/store/%-builder.sh'
      OR p0.cmdline LIKE 'git %'
      OR p0.cmdline LIKE '%LICENSES/vendor/%'
      OR p0.cmdline LIKE 'curl -sL wttr.in%'
      OR p0.cmdline LIKE '%localhost:%'
      OR p0.cmdline LIKE '%127.0.0.1:%'
      OR p0.name IN ('apko')
    )
  )
  -- These are typically curl -k calls
  -- We need the addr "IS NOT NULL" to avoid filtering out
  -- NULL entries
  AND NOT (
    addr IS NOT NULL
    AND (
      addr IN (
        'releases.hashicorp.com',
        'github.com',
        'dl.enforce.dev'
      )
      -- Ignore local addresses (Docker development)
      OR addr NOT LIKE '%.%'
      OR ip LIKE '172.21.%'
      OR ip LIKE '192.168.%'
    )
  )
  -- Qualys Cloud Agent
  AND NOT (
    addr = "169.254.169.254"
    AND p2.path = "/usr/local/qualys/cloud-agent/bin/qualys-scan-util"
  )
