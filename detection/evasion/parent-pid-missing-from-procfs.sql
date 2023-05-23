-- Find a process which has a parent that is not listed in the process table
--
-- Works well for revealing boopkit, so long as boopkit has a child process.
--
-- references:
--   * https://github.com/krisnova/boopkit
--   * https://attack.mitre.org/techniques/T1014/ (Rootkit)
--
-- false positives:
--   * Can by racy if child and parent exit at the right time
--
-- tags: persistent daemon
SELECT p.*,
  hash.sha256,
  GROUP_CONCAT(DISTINCT pof.path) AS open_files
FROM processes p
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN process_open_files pof ON p.pid = pof.pid
WHERE -- Prevent false positives by avoiding short-lived commands
  p.start_time < (strftime('%s', 'now') -1)
  AND p.parent NOT IN (
    SELECT pid
    FROM processes
  )
  AND p.parent != 0
  AND p.parent IS NOT NULL
GROUP BY p.pid