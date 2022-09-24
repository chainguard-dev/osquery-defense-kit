-- Works well for revealing boopkit, so long as boopkit has a child process.
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
