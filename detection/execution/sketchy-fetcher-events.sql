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
  pe.pid,
  pe.cmdline,
  REGEX_MATCH (pe.cmdline, '/(\d+\.\d+\.\d+\.\d+)[:/]', 1) AS remote_ip,
  REGEX_MATCH (pe.cmdline, ':(\d+)', 1) AS remote_port,
  REGEX_MATCH (pe.cmdline, '/(\w+[\.-]\w+)[:/]', 1) AS remote_addr,
  REGEX_MATCH (pe.cmdline, '\.(\w+)[:/]', 1) AS remote_tld,
  pe.cwd,
  pe.euid,
  pe.parent,
  pp.parent AS gparent,
  p.cgroup_path,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  gp.cmdline AS gparent_cmdline,
  gp.name AS gparent_name,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256
FROM
  process_events pe
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN processes pp ON pe.parent = pp.pid
  LEFT JOIN processes gp ON pp.parent = gp.pid
  LEFT JOIN hash ON pp.path = hash.path
WHERE
  pe.time > (strftime('%s', 'now') -60)
  -- NOTE: Sync remaining portion with sketchy-fetchers
  AND (
    INSTR(p.cmdline, 'wget ') > 0
    OR INSTR(p.cmdline, 'curl ') > 0
  )
  AND (
    -- If it's an IP or port, it's suspicious
    remote_ip NOT IN ('', '127.0.0.1', '::1')
    OR remote_port != ''
    OR remote_tld NOT IN (
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
    -- Or if it matches weird keywords we've seen
    OR pe.cmdline LIKE '%.onion%'
    OR pe.cmdline LIKE '%tor2web%'
    OR pe.cmdline LIKE '%aliyun%'
    OR pe.cmdline LIKE '%pastebin%'
    OR pe.cmdline LIKE '%curl.*—write-out%'
    OR pe.cmdline LIKE '%curl %--user-agent%'
    OR pe.cmdline LIKE '%curl -k%'
    OR pe.cmdline LIKE '%curl -sL %'
    OR pe.cmdline LIKE '%curl%--connect-timeout%'
    OR pe.cmdline LIKE '%curl%--output /dev/null%'
    OR pe.cmdline LIKE '%curl%--O /dev/null%'
    OR pe.cmdline LIKE '%curl%--insecure%'
    OR pe.cmdline LIKE '%wget %--user-agent%'
    OR pe.cmdline LIKE '%wget %--no-check-certificate%'
    OR pe.cmdline LIKE '%wget -nc%'
    OR pe.cmdline LIKE '%wget -t%'
    -- Or anything launched by a system user
    OR (
      pe.cmdline LIKE '%wget -%'
      AND pe.euid < 500
    )
    OR (
      pe.cmdline LIKE '%curl %'
      AND pe.euid < 500
      AND pe.cmdline NOT LIKE "%./configure %--with-curl%"
    )
  )
  -- Exceptions for all calls
  AND pp.name NOT IN ('makepkg', 'apko') -- Exceptions for non-privileged calls
  AND NOT (
    pe.euid > 500
    AND (
      pe.cmdline LIKE '%--dump-header%'
      OR pe.cmdline LIKE '%127.0.0.1:%'
      OR pe.cmdline LIKE '%/192.168.%:%'
      OR pe.cmdline LIKE '%/api/v%'
      OR pe.cmdline LIKE '%application/json%'
      OR pe.cmdline LIKE '%/chainctl_%'
      OR pe.cmdline LIKE '%ctlog%'
      OR pe.cmdline LIKE '%curl -X %'
      OR pe.cmdline LIKE 'git %'
      OR pe.cmdline LIKE '%go mod %'
      OR pe.cmdline LIKE '%grpcurl%'
      OR pe.cmdline LIKE '%Homebrew%'
      OR pe.cmdline LIKE '%https://api.github.com/%'
      OR pe.cmdline LIKE '%If-None-Match%'
      OR pe.cmdline LIKE "%libcurl%"
      OR pe.cmdline LIKE '%LICENSES/vendor/%'
      OR pe.cmdline LIKE '%localhost:%'
      OR pe.cmdline LIKE '%/openid/v1/jwks%'
      OR pe.cmdline LIKE '%--progress-bar%'
      OR pe.cmdline LIKE '%.well-known/openid-configuration%'
      OR pe.cmdline LIKE 'wget --no-check-certificate https://github.com/%'
      OR pe.cmdline LIKE 'curl -sL wttr.in%'
      OR parent_cmdline LIKE '%brew.rb%'
      OR parent_cmdline LIKE '%brew.sh%'
    )
  )
  -- These are typically curl -k calls
  AND remote_addr NOT IN (
    'releases.hashicorp.com',
    'github.com'
  )