-- Inspired by BPFdoor
-- https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
SELECT
  COUNT(*) AS count,
  p.pid,
  p.path,
  p.cmdline
FROM
  process_envs pe
  JOIN processes p ON pe.pid = p.pid
GROUP BY
  p.pid
HAVING
  count == 0;
