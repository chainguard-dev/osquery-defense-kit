-- Find a process which has a parent that is not listed in the process table
--
-- Works well for revealing boopkit, so long as boopkit has a child process.
--
-- references:
--   * https://github.com/krisnova/boopkit
--   * https://attack.mitre.org/techniques/T1014/ (Rootkit)
--
-- false positives:
--   * None observed
--
-- tags: persistent daemon
SELECT
  p.*,
  hash.sha256,
  GROUP_CONCAT(DISTINCT pof.path) AS open_files
FROM
  processes p
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN process_open_files pof ON p.pid = pof.pid
WHERE
  p.parent NOT IN (
    SELECT
      pid
    FROM
      processes
  )
  AND p.parent != 0
  AND p.parent IS NOT NULL
GROUP BY
  p.pid
