-- Find ssh sessions that are hiding from 'w'/'who'
--
-- false positives:
--   * ssh-driven automation which disables the terminal, such as Znapzend
--
-- references:
--   * https://attack.mitre.org/techniques/T1021/004/ (Remote Services: SSH)
--   * https://attack.mitre.org/techniques/T1564/ (Hide Artifacts)
--
-- tags: transient process state
-- platform: posix
SELECT
  *
FROM
  (
    SELECT
      p.pid,
      p.name,
      p.cmdline AS cmd,
      cp.name AS child_name,
      cp.cmdline AS child_cmd,
      gcp.name AS grandchild_name,
      gcp.cmdline AS grandchild_cmd,
      GROUP_CONCAT(DISTINCT pof.path) AS open_files
    FROM
      processes p
      LEFT JOIN process_open_files pof ON p.pid = pof.pid
      LEFT JOIN processes cp ON p.pid = cp.parent
      LEFT JOIN processes gcp ON cp.pid = gcp.parent
    WHERE
      p.name = 'sshd'
    GROUP BY
      p.pid
  )
WHERE
  (
    INSTR(cmd, '@notty') > 0
    OR (
      open_files != '/dev/null'
      AND INSTR(open_files, '/dev/ptmx') = 0
    )
  )
  -- You must specifically check for NULL here, or risk inadvertently filtering everything out.
  AND (
    grandchild_name IS NULL
    OR grandchild_name != 'zfs'
  )
