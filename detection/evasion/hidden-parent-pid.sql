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
  pp.*
FROM
  processes
  JOIN processes pp ON processes.parent = pp.pid
WHERE
  processes.parent NOT IN (
    SELECT
      pid
    FROM
      processes
  )
  AND processes.parent != 0;
