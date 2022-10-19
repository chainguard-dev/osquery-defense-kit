-- Processes that do not exist on disk, running in osquery's namespace
--
-- false positives:
--   * none observed
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/004/ (Indicator Removal on Host: File Deletion)
--
-- tags: persistent process state
-- platform: linux
SELECT
  p.pid,
  p.euid,
  p.cmdline,
  p.path,
  mnt_namespace,
  p.cwd,
  p.on_disk,
  p.state,
  file.inode,
  pp.on_disk AS parent_on_disk,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  ph.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN file ON p.path = file.path
  LEFT JOIN process_namespaces ON p.pid = process_namespaces.pid
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ph ON pp.path = ph.path
WHERE
  p.on_disk != 1
  AND p.path != ''
  -- use osquery as the reference mount namespace
  AND mnt_namespace IN (
    SELECT DISTINCT
      (mnt_namespace)
    FROM
      process_namespaces
      JOIN processes ON processes.pid = process_namespaces.pid
    WHERE
      processes.name IN ('osqueryi', 'osqueryd')
  )
  -- This is truly a missing program, not just one that has been updated with a new binary.
  AND file.inode IS NULL
  -- Snap packages?
  AND p.path NOT LIKE '/tmp/.mount_%'
