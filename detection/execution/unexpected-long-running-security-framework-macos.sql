-- Find programs that use the Security Framework on macOS - popular among malware authors
--
-- platform: darwin
-- tags: persistent state process seldom
SELECT
  s.authority,
  s.identifier,
  CONCAT (
    MIN(p0.euid, 500),
    ',',
    p0.name,
    ',',
    s.identifier,
    ',',
    s.authority
  ) AS exception_key,
  pmm.path AS lib_path,
  -- Child
  p0.pid AS p0_pid,
  p0.start_time AS p0_start,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.start_time AS p1_start,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.start_time AS p2_start,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  JOIN process_memory_map pmm ON p0.pid = pmm.pid
  LEFT JOIN signature s ON p0.path = s.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE -- Focus on longer-running programs
  p0.pid IN (
    SELECT
      pid
    FROM
      processes
    WHERE
      start_time < (strftime('%s', 'now') - 25200)
      AND parent != 0 -- Assume STP
      AND NOT path LIKE '/System/%'
      AND NOT path LIKE '/usr/libexec/%'
      AND NOT path LIKE '/usr/sbin/%' -- Regular apps
      AND NOT path LIKE '/Applications/%.app/%' -- Other oddball binary paths
      AND NOT path LIKE '/opt/%'
      AND NOT path LIKE '/Users/%/go/%'
      AND NOT path LIKE '/Users/%/dev/%'
      AND NOT path LIKE '/Users/%/src/%'
      AND NOT path LIKE '/Users/%/bin/%'
      AND NOT path LIKE '/nix/store/%'
      AND NOT path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/%'
      AND NOT path LIKE '/Users/%/Library/Application Support/Zed/supermaven/%'
      AND NOT path LIKE '/private/var/folders%/T/go-build%/exe/%'
      AND NOT path LIKE '/Users/%/.terraform/providers/%'
      AND NOT REGEX_MATCH (path, '(.*)/', 1) LIKE '%/bin'
      AND NOT (
        path LIKE '/Users/%/Library/Application Support/com.elgato.StreamDeck/Plugins/com.elgato.cpu.sdPlugin/cpu'
        AND name = 'cpu'
      ) -- Takes arguments
      AND NOT (
        euid >= 500
        AND cmdline LIKE "% --%"
      )
  )
  AND pmm.path LIKE '%Security.framework%'
  AND NOT s.authority IN (
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: Corsair Memory, Inc. (Y93VXCB8Q5)',
    'Developer ID Application: Google, Inc. (EQHXZ8M8AV)',
    'Developer ID Application: Valve Corporation (MXGJJ98X76)'
  )
  AND exception_key NOT IN (
    '0,velociraptor,a.out,',
    '500,cloud_sql_proxy,a.out,',
    '500,docker,docker,',
    '500,gopls,a.out,',
    '500,sdaudioswitch,,',
    '500,sdaudioswitch,sdaudioswitch,',
    '500,sdmicmute,sdmicmute,',
    '500,sdzoomplugin,,'
  )
  AND NOT exception_key LIKE '500,lifx-streamdeck,lifx-streamdeck-%'
  AND NOT exception_key LIKE '500,___Test%.test,a.out'
  AND NOT exception_key LIKE '500,nvim,bob-%,'
  AND NOT exception_key LIKE '500,sm-agent,sm_agent-%'
  AND NOT exception_key LIKE '500,___2go_build_main_go,a.out,'
  AND NOT exception_key LIKE '500,rust-analyzer,rust_analyzer-%,'
  AND NOT exception_key LIKE '500,package-version-server-v%,package_version_server-%,'
  AND NOT exception_key LIKE '500,marksman-macos,marksman-%,'
GROUP BY
  p0.pid
