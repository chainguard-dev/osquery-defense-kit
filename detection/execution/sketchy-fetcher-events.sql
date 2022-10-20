-- Suspicious URL requests by built-in fetching tools (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--   * https://attack.mitre.org/techniques/T1571/ (Non-Standard Port)
--
-- interval: 60
-- tags: transient process events
-- platform: posix
SELECT
  p.pid,
  p.path,
  p.cmdline,
  REGEX_MATCH (p.cmdline, '/(\d+\.\d+\.\d+\.\d+)[:/]', 1) AS remote_address,
  REGEX_MATCH (p.cmdline, '/(:\d+\/)/', 1) AS remote_port,
  p.mode,
  p.cwd,
  p.euid,
  p.parent,
  p.syscall,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  process_events p
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  p.time > (strftime('%s', 'now') -60)
  -- NOTE: Sync remaining portion with sketchy-fetchers
  AND (
    INSTR(p.cmdline, 'wget ') > 0
    OR INSTR(p.cmdline, 'curl ') > 0
  )
  AND (
    -- If it's an IP or port, it's suspicious
    remote_address NOT IN ('', '127.0.0.1', '::1')
    OR remote_port != ''
    -- Or if it matches weird keywords we've seen
    OR p.cmdline LIKE '%.onion%'
    OR p.cmdline LIKE '%tor2web%'
    OR p.cmdline LIKE '%aliyun%'
    OR p.cmdline LIKE '%pastebin%'
    OR p.cmdline LIKE '%curl.*—write-out%'
    OR p.cmdline LIKE '%curl %--user-agent%'
    OR p.cmdline LIKE '%curl -k%'
    OR p.cmdline LIKE '%curl -sL %'
    OR p.cmdline LIKE '%curl%--connect-timeout%'
    OR p.cmdline LIKE '%curl%--output /dev/null%'
    OR p.cmdline LIKE '%curl%--O /dev/null%'
    OR p.cmdline LIKE '%curl%--insecure%'
    OR p.cmdline LIKE '%wget %--user-agent%'
    OR p.cmdline LIKE '%wget %--no-check-certificate%'
    OR p.cmdline LIKE '%wget -nc%'
    OR p.cmdline LIKE '%wget -t%'
    -- Or anything launched by a system user
    OR (
      p.cmdline LIKE '%wget -%'
      AND p.euid < 500
    )
    OR (
      p.cmdline LIKE '%curl %'
      AND p.euid < 500
      AND p.cmdline NOT LIKE "%./configure %--with-curl%"
    )
  )
  -- Exceptions for all calls
  AND pp.name NOT IN ('makepkg', 'apko') -- Exceptions for non-privileged calls
  AND NOT (
    p.euid > 500
    AND (
      p.cmdline LIKE '%--dump-header%'
      OR p.cmdline LIKE '%127.0.0.1:%'
      OR p.cmdline LIKE '%/192.168.%:%'
      OR p.cmdline LIKE '%/api/v%'
      OR p.cmdline LIKE '%application/json%'
      OR p.cmdline LIKE '%/chainctl_%'
      OR p.cmdline LIKE '%ctlog%'
      OR p.cmdline LIKE '%curl -X %'
      OR p.cmdline LIKE 'git %'
      OR p.cmdline LIKE '%go mod %'
      OR p.cmdline LIKE '%grpcurl%'
      OR p.cmdline LIKE '%Homebrew%'
      OR p.cmdline LIKE '%https://api.github.com/%'
      OR p.cmdline LIKE '%If-None-Match%'
      OR p.cmdline LIKE "%libcurl%"
      OR p.cmdline LIKE '%LICENSES/vendor/%'
      OR p.cmdline LIKE '%localhost:%'
      OR p.cmdline LIKE '%/openid/v1/jwks%'
      OR p.cmdline LIKE '%--progress-bar%'
      OR p.cmdline LIKE '%.well-known/openid-configuration%'
      OR p.cmdline LIKE 'wget --no-check-certificate https://github.com/'
      OR p.cmdline LIKE 'curl -sL wttr.in%'
      OR parent_cmdline LIKE '%brew.rb%'
      OR parent_cmdline LIKE '%brew.sh%'
    )
  )
