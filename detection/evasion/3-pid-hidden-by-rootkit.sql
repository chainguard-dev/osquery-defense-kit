-- Finds processes that are apparently hidden by a rootkit
--
-- references:
--   * https://attack.mitre.org/techniques/T1014/ (Rootkit)
--
-- Confirmed to catch revenge-rtkit
--
-- false positives:
--   * custom kernel modules
--
-- tags: persistent kernel state
-- platform: linux
WITH RECURSIVE
  cnt (x) AS (
    SELECT
      1
    UNION ALL
    SELECT
      x + 1
    FROM
      cnt
    LIMIT
      32768
  )
SELECT
  p.*
FROM
  cnt
  JOIN processes p ON x = p.pid
WHERE
  x NOT IN (
    SELECT
      pid
    FROM
      processes
  )
  AND p.start_time < (strftime('%s', 'now') - 1) -- Improve how we filter tasks out.
  -- This is not very precise. What we really want to do is verify that
  -- this pid is not listed as a task of any other pid
  AND (
    p.pgroup = p.pid
    OR (
      p.pid = p.parent
      AND p.threads = 1
    )
  )
