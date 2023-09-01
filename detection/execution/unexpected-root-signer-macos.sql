-- Programs running as root from unusual signers on macOS
--
-- platform: darwin
-- interval: 900
-- tags: transient seldom process state
-- Canonical example of including process parents from process_events
SELECT
  f.directory AS dir,
  REGEX_MATCH (p.path, '(/.*?/.*?)/', 1) AS top_dir,
  -- Child
  pe.path AS p0_path,
  pe.time AS p0_time,
  pe.euid AS p0_euid,
  s.authority AS p0_sauth,
  s.identifier AS p0_sid,
  hash.sha256 AS p0_hash,
  REGEX_MATCH (pe.path, '.*/(.*)', 1) AS p0_name,
  TRIM(pe.cmdline) AS p0_cmd,
  -- pe.cwd is NULL on macOS
  p.cwd AS p0_cwd,
  pe.pid AS p0_pid,
  -- Parent
  pe.parent AS p1_pid,
  TRIM(COALESCE(p1.cmdline, pe1.cmdline)) AS p1_cmd,
  COALESCE(p1.start_time, pe1.time) AS p1_start,
  COALESCE(p1.path, pe1.path) AS p1_path,
  p1.cwd AS p1_cwd,
  COALESCE(p_hash1.sha256, pe_hash1.sha256) AS p1_hash,
  REGEX_MATCH (COALESCE(p1.path, pe1.path), '.*/(.*)', 1) AS p1_name,
  -- Grandparent
  COALESCE(p1.parent, pe1.parent) AS p2_pid,
  TRIM(
    COALESCE(p1_p2.cmdline, pe1_p2.cmdline, pe1_pe2.cmdline)
  ) AS p2_cmd,
  p1_p2.cwd AS p2_cwd,
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
  ) AS p2_name
FROM
  process_events pe
  LEFT JOIN file f ON pe.path = f.path
  LEFT JOIN users u ON pe.uid = u.uid
  LEFT JOIN signature s ON pe.path = s.path
  LEFT JOIN processes p ON pe.pid = p.pid
  LEFT JOIN hash ON pe.path = hash.path
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
WHERE
  p0_euid = 0
  AND pe.time > (strftime('%s', 'now') -900)
  -- query optimization: Exclude SIP protected directories
  AND top_dir NOT IN (
    '/Library/Apple',
    '/System/Library',
    '/usr/bin',
    '/usr/libexec',
    '/usr/sbin'
  )
  AND s.authority NOT IN (
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Canonical Group Limited (X4QN7LTP59)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Ecamm Network, LLC (5EJH68M642)',
    'Developer ID Application: Fortinet, Inc (AH4XFXJ7DK)',
    'Developer ID Application: Foxit Corporation (8GN47HTP75)',
    'Developer ID Application: Fumihiko Takayama (G43BCU2T37)',
    'Developer ID Application: Google LLC (EQHXZ8M8AV)',
    'Developer ID Application: Kandji, Inc. (P3FGV63VK7)',
    'Developer ID Application: Keybase, Inc. (99229SGT5K)',
    'Developer ID Application: Kolide, Inc (X98UFR7HA3)',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Mersive Technologies (63B5A5WDNG)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: Parallels International GmbH (4C6364ACXT)',
    'Developer ID Application: Private Internet Access, Inc. (5357M5NW9W)',
    'Developer ID Application: Rogue Amoeba Software, LLC (7266XEXAPM)',
    'Developer ID Application: Ryan Hanson (XSYZ3E4B7D)',
    'Developer ID Application: Sanford, L.P. (N3S6676K3E)',
    'Developer ID Application: Tailscale Inc. (W5364U7YZB)',
    'Software Signing'
  )
  AND NOT (
    s.authority = ""
    AND pe.path LIKE "/nix/store/%-nix-%/bin/nix"
    AND p1.path = "/sbin/launchd"
  )
  AND NOT (
    s.authority = ""
    AND (
      pe.path LIKE "/nix/store/%-nix-%/bin/nix-%"
      OR pe.path LIKE "/private/var/folders/%/T/tmp.%/nix-installer"
    )
    AND p1_path = "/usr/bin/sudo"
  )
  AND NOT (
    s.authority = ""
    AND pe.path LIKE "/opt/%/bin/socket_vmnet"
    AND p1_path IN ("/usr/bin/sudo", "/sbin/launchd")
  )
  AND NOT (
    s.authority = ""
    AND pe.path LIKE "/opt/homebrew/Cellar/mariadb/%/bin/mariadbd"
    AND p0_cmd LIKE "/opt/homebrew/opt/mariadb/bin/mariadbd %"
  )
  AND NOT (
    s.authority = ""
    AND pe.path LIKE "/opt/homebrew/Cellar/tailscale/%/bin/tailscaled"
    AND p0_cmd LIKE "/opt/homebrew/Cellar/tailscale/%/bin/tailscaled %"
  )
  AND NOT (
    s.authority = "Developer ID Application: Node.js Foundation (HX7739G8FX)"
    AND p0_name = "node"
    AND p1_name IN ("vim", "nvim")
  )
  AND NOT pe.path LIKE '/usr/local/Cellar/htop/%/bin/htop'
