-- Reveal launchd services which are located in a hidden directory.
--
-- This query was written because osquery can't see these entries currently.
-- See https://github.com/osquery/osquery/issues/7703
--
-- references:
--   * https://attack.mitre.org/techniques/T1543/004/ (Create or Modify System Process: Launch Daemon)
--   * https://attack.mitre.org/techniques/T1564/001/ (Hide Artifacts: Hidden Files and Directories)
--
-- platform: darwin
-- tags: persistent daemon
SELECT
  file.path,
  file.type,
  file.filename,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  file.gid,
  hash.sha256,
  signature.identifier,
  signature.authority
FROM
  file
  LEFT JOIN signature ON file.path = signature.path
  LEFT JOIN hash ON file.path = hash.path
WHERE
  (
    file.path LIKE '/Library/LaunchAgents/.%'
    OR file.path LIKE '/Users/%/Library/LaunchAgents/.%'
    OR file.path LIKE '/Users/%/Library/LaunchDaemons/.%'
  )
  AND file.filename NOT IN ('.', '..', '.DS_Store')
  AND NOT (
    file.filename = '.DS_Store'
    AND hash.sha256 = 'd65165279105ca6773180500688df4bdc69a2c7b771752f0a46ef120b7fd8ec3'
  )
