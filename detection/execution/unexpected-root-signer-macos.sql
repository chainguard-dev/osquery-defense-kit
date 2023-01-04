-- Programs running as root from unusual signers on macOS
--
-- platform: darwin
-- tags: transient seldom process state
SELECT
  p.pid,
  p.name,
  p.path,
  p.euid,
  p.gid,
  f.ctime,
  f.directory AS dir,
  REGEX_MATCH (p.path, '(/.*?/.*?)/', 1) AS top_dir,
  p.cmdline,
  hash.sha256,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.euid AS parent_euid,
  hash.sha256 AS parent_sha256,
  signature.identifier,
  signature.authority
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN hash ON hash.path = p.path
  LEFT JOIN users u ON p.uid = u.uid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN signature ON p.path = signature.path
WHERE
  -- query optimization: Exclude SIP protected directories
  p.euid = 0 AND
  top_dir NOT IN (
    '/Library/Apple',
    '/System/Library',
    '/usr/bin',
    '/usr/libexec',
    '/usr/sbin'
  )
  AND signature.authority NOT IN (
    'Developer ID Application: Adobe Inc. (JQ525L2MZD)',
    'Developer ID Application: Docker Inc (9BNSXJN65R)',
    'Developer ID Application: Dropbox, Inc. (G7HH3F8CAK)',
    'Developer ID Application: Foxit Corporation (8GN47HTP75)',
    'Developer ID Application: Fumihiko Takayama (G43BCU2T37)',
    'Developer ID Application: Kolide Inc (YZ3EM74M78)',
    'Developer ID Application: Logitech Inc. (QED4VVPZWA)',
    'Developer ID Application: Mersive Technologies (63B5A5WDNG)',
    'Developer ID Application: Microsoft Corporation (UBF8T346G9)',
    'Developer ID Application: Objective Development Software GmbH (MLZF7K7B5R)',
    'Developer ID Application: Objective-See, LLC (VBG97UB4TA)',
    'Developer ID Application: Opal Camera Inc (97Z3HJWCRT)',
    'Developer ID Application: OSQUERY A Series of LF Projects, LLC (3522FA9PXF)',
    'Developer ID Application: Parallels International GmbH (4C6364ACXT)',
    -- I'm not too thrilled to have this as an exception, to be honest.
    'Developer ID Application: Private Internet Access, Inc. (5357M5NW9W)',
    'Developer ID Application: Sanford, L.P. (N3S6676K3E)',
    'Software Signing'
  )
  AND NOT (
    signature.authority = "" AND
    p.path LIKE "/nix/store/%-nix-%/bin/nix"
    AND pp.path = "/sbin/launchd"
  )