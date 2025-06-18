-- Rust Program that uses both HTTP and Exec
-- tags: persistent
-- interval: 7200
-- platform: posix
SELECT
  yara.*,
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
  JOIN yara ON p0.path = yara.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      start_time > (strftime('%s', 'now') - 7200)
      AND path != ""
      AND NOT path LIKE '/%/.local/zed.app/libexec/zed-editor'
      AND NOT path LIKE '/Applications/%.app/Contents/macOS/%'
      AND NOT path LIKE '/opt/%'
      AND NOT path LIKE '/private/var/folders%/T/go-build%/exe/%'
      AND NOT path LIKE '/System/%'
      AND NOT path LIKE '/Users/%/.terraform/providers/%'
      AND NOT path LIKE '/Users/%/bin/%'
      AND NOT path LIKE '/Users/%/dev/%'
      AND NOT path LIKE '/Users/%/go/%'
      AND NOT path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/%'
      AND NOT path LIKE '/Users/%/src/%'
      AND NOT path LIKE '/usr/libexec/%'
      AND NOT path LIKE '/usr/sbin/%' -- Regular apps
    GROUP BY
      path
  )
  AND yara.sigrule = '
    rule http_exec {
    strings:
        $http_proxy = "HTTP_PROXY" ascii
        $process_unix = "process_unix.rs" ascii
    condition:
        all of them
}'
  AND yara.count > 0
  AND p0.name NOT IN (
    'atuin',
    'cargo',
    'Cody',
    'deno',
    'DevPod',
    'fig-darwin-universal',
    'figma_agent',
    'i3status-rs',
    'i3status-rust',
    'nvim',
    'old',
    'OrbStack Helper',
    'package-version',
    'rpm-ostree',
    'rustc',
    'sg-nvim-agent',
    'sm-agent',
    'stable',
    'toolbase-runner',
    'uv',
    'warp',
    'warp-terminal',
    'wezterm-gui',
    'zed'
  )
  AND p0.name NOT LIKE 'cody-engine-%'
  AND p0.path NOT LIKE '/Users/%/.cargo/bin/%'
  AND p0.path NOT IN (
    '/Applications/safeqclient.app/Contents/MacOS/safeqclient',
    '/Applications/Zed.app/Contents/MacOS/Zed',
    '/usr/local/bin/determinate-nixd',
    '/usr/bin/pop-launcher',
    '/Library/safeqclientcore/bin/safeqclientcore'
  )
