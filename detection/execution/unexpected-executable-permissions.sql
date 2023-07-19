-- Find processes running that are tied to binaries with unsual permissions. Namely, 0777.
--
-- references:
--   * https://attack.mitre.org/techniques/T1222/
--
-- false positives:
--   * poorly written software
--
-- platform: posix
-- tags: persistent filesystem state
SELECT
  f.mode,
  f.uid,
  f.gid,
  f.ctime,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
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
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  f.mode NOT IN (
    '0500',
    '0544',
    '0555',
    '0711',
    '0755',
    '0775',
    '0744',
    '6755',
    '0700',
    '2755',
    '4511',
    '4555',
    '4755'
  )
  -- Vendors who are very relaxed about permissions
  AND NOT (
    f.path IN (
      '/Applications/Camera Settings.app/Contents/MacOS/LogitechCamera',
      '/Applications/motionVFX/Plugins/mUtility.app/Contents/PlugIns/mUtility XPC Service.pluginkit/Contents/MacOS/mUtility XPC Service',
      '/Library/Application Support/Logitech/com.logitech.vc.LogiVCCoreService/LogiVCCoreService.app/Contents/MacOS/LogiVCCoreService'
    )
    AND f.mode = '0777'
    AND f.uid > 500
  )
  AND NOT (
    f.path LIKE '/Users/%/.local/bin/%'
    AND f.mode = '0777'
    AND f.uid > 500
  )
  AND NOT (
    f.path LIKE '/Users/%/Library/Application Support/Code/User/globalStorage/grafana.vscode-jsonnet/bin/jsonnet-language-server'
    AND f.mode = '0777'
    AND f.uid > 500
  )
  AND NOT (
    f.path LIKE '/Users/%/.vscode/extensions/sumneko.lua-%-darwin-arm64/server/bin/lua-language-server'
    AND f.mode = '0777'
    AND f.uid > 500
  )
  AND NOT (
    f.path LIKE '/Users/%/Library/Application Support/Zwift/ZwiftAppMetal'
    AND f.mode = '0777'
    AND f.uid > 500
  )
  AND NOT (
    f.path = '/usr/bin/sudo'
    AND f.mode = '4111'
    AND f.uid = 0
  )
  AND NOT (
    f.path LIKE '/home/%/.local/share/JetBrains/Toolbox/bin/jetbrains-toolbox'
    AND f.mode = '0744'
  )
  AND NOT (
    f.path LIKE '/Users/%/Applications (Parallels)/%.app/Contents/MacOS/WinAppHelper'
    AND f.mode = '0777'
  )
  AND NOT (
    f.path LIKE '/opt/homebrew/Cellar/socket_vmnet/%/bin/socket_vmnet'
    AND f.mode = '1555'
  )
  AND NOT (
    f.path LIKE '/opt/homebrew/Cellar/dnsmasq/%/sbin/dnsmasq'
    AND f.mode = '1555'
  )
  AND NOT (
    f.path LIKE '/Users/%/Library/Application Support/com.raycast.macos/NodeJS/runtime/%/bin/node'
    AND f.mode = '0754'
  )
