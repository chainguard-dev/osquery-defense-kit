-- Suspicious URL requests by built-in fetching tools (event-based)
--
-- refs:
--   * https://attack.mitre.org/techniques/T1105/ (Ingress Tool Transfer)
--   * https://attack.mitre.org/techniques/T1571/ (Non-Standard Port)
--
-- interval: 120
-- tags: transient process events
-- platform: posix
SELECT
  -- Child
  pe.path AS p0_path,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  pe.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  pe.time AS p0_time,
  p.cgroup_path AS p0_cgroup,
  -- Parent
  pe.parent AS p1_pid,
  p1.cgroup_path AS p1_cgroup,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.path, pe1.path) AS p1_path,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  COALESCE(p1_p2.cgroup_path, pe1_p2.cgroup_path) AS p2_cgroup,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path) AS p2_path,
  COALESCE(
    p1_p2_hash.path,
    pe1_p2_hash.path,
    pe1_pe2_hash.path
  ) AS p2_hash,
  REGEX_MATCH (
    COALESCE(p1_p2.path, pe1_p2.path, pe1_pe2.path),
    '.*/(.*)',
    1
  ) AS p2_name,
  -- Extra fields
  REGEX_MATCH (pe.cmdline, '(\w+:\/\/.*)\b', 1) AS url,
  REGEX_MATCH (pe.cmdline, '[ /](\d+\.\d+\.\d+\.\d+)[:/]', 1) AS ip,
  REGEX_MATCH (pe.cmdline, ':(\d+)', 1) AS port,
  REGEX_MATCH (pe.cmdline, '//([\w\-\.]+)[:/]', 1) AS addr,
  REGEX_MATCH (pe.cmdline, '//[\w\-\.]+\.(\w+)[:/]', 1) AS tld
FROM
  process_events pe,
  uptime
  LEFT JOIN processes p ON pe.pid = p.pid
  -- Parents (via two paths)
  LEFT JOIN processes p1 ON pe.parent = p1.pid
  LEFT JOIN hash p_hash1 ON p1.path = p_hash1.path
  LEFT JOIN process_events pe1 ON pe.parent = pe1.pid
  AND pe1.cmdline != ''
  LEFT JOIN hash pe_hash1 ON pe1.path = pe_hash1.path
  -- Grandparents (via 3 paths)
  LEFT JOIN processes p1_p2 ON p1.parent = p1_p2.pid -- Current grandparent via parent processes
  LEFT JOIN processes pe1_p2 ON pe1.parent = pe1_p2.pid -- Current grandparent via parent events
  LEFT JOIN process_events pe1_pe2 ON pe1.parent = pe1_p2.pid
  AND pe1_pe2.cmdline != '' -- Past grandparent via parent events
  LEFT JOIN hash p1_p2_hash ON p1_p2.path = p1_p2_hash.path
  LEFT JOIN hash pe1_p2_hash ON pe1_p2.path = pe1_p2_hash.path
  LEFT JOIN hash pe1_pe2_hash ON pe1_pe2.path = pe1_pe2_hash.path
  -- Extra fields
WHERE
  pe.time > (strftime('%s', 'now') -120)
  AND pe.cmdline != ''
  -- NOTE: Sync remaining portion with sketchy-fetchers
  AND (
    INSTR(pe.cmdline, 'wget ') > 0
    OR INSTR(pe.cmdline, 'curl ') > 0
  )
  -- Sketchy fetcher events always seem to contain a switch
  AND pe.cmdline LIKE '%-%'
  AND pe.cmdline LIKE '%/%'
  AND (
    -- If it's an IP or port, it's suspicious
    ip NOT IN ('', '127.0.0.1', '0.0.0.0', '::1')
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
      'uk',
      'us'
    )
    -- Or if it matches weird keywords we've seen
    OR p.cmdline LIKE '%chmod%'
    OR pe.cmdline LIKE '%.onion%'
    OR pe.cmdline LIKE '%tor2web%'
    OR pe.cmdline LIKE '%aliyun%'
    OR pe.cmdline LIKE '%pastebin%'
    OR pe.cmdline LIKE '%curl.*—write-out%'
    OR pe.cmdline LIKE '%curl %--user-agent%'
    OR pe.cmdline LIKE '%curl -k%'
    OR pe.cmdline LIKE '%curl -sL %'
    OR pe.cmdline LIKE '%curl%-o-%'
    OR pe.cmdline LIKE '%curl%--connect-timeout%'
    OR pe.cmdline LIKE '%curl%--output /dev/null%'
    OR pe.cmdline LIKE '%curl%--O /dev/null%'
    OR pe.cmdline LIKE '%curl%--insecure%'
    OR pe.cmdline LIKE '%wget %--user-agent%'
    OR pe.cmdline LIKE '%wget %--no-check-certificate%'
    OR pe.cmdline LIKE '%wget -nc%'
    OR pe.cmdline LIKE '%wget -q%'
    OR pe.cmdline LIKE '%wget -t%'
    -- Or anything launched by a system user
    OR (
      pe.cmdline LIKE '%wget -%'
      AND pe.euid < 500
      AND p.cgroup_path NOT LIKE '/system.slice/docker-%'
    )
    OR (
      pe.cmdline LIKE '%curl %'
      AND pe.euid < 500
      AND pe.cmdline NOT LIKE "%./configure %--with-curl%"
      AND p.cgroup_path NOT LIKE '/system.slice/docker-%'
    )
  )
  -- Exceptions for all calls
  AND NOT (
    pe.euid > 500
    AND (
      pe.cmdline LIKE '%--dump-header%'
      OR pe.cmdline LIKE '%127.0.0.1:%'
      OR pe.cmdline LIKE '%/192.168.%:%'
      OR pe.cmdline LIKE '%application/json%'
      OR pe.cmdline LIKE '%/chainctl_%'
      OR pe.cmdline LIKE '%ctlog%'
      OR pe.cmdline LIKE '%curl -X %'
      OR pe.cmdline LIKE '%Authorization: Bearer%'
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
      OR p1_cmd LIKE '%brew.rb%'
      OR p1_cmd LIKE '%brew.sh%'
    )
  )
  AND NOT (
    pe.euid > 500
    AND pe.cmdline LIKE '%/api'
    AND pe.cmdline NOT LIKE '%-o%'
    AND pe.cmdline NOT LIKE '%-O%'
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
        'cdn.zoom.us',
        'dl.enforce.dev'
      )
      -- Ignore local addresses (Docker development)
      OR addr NOT LIKE '%.%'
      OR ip LIKE '172.2%'
      OR ip LIKE '192.168.%'
      OR ip LIKE '127.%'
    )
  )
  AND NOT p1_cmd LIKE '/usr/bin/bash /usr/bin/makepkg %'
