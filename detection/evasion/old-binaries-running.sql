-- Alert on programs running that are unusually old (poor timestomping)
--
-- false positive:
--   * legimitely ancient programs. For instance, printer drivers.
--
-- references:
--   * https://attack.mitre.org/techniques/T1070/006/ (Indicator Removal on Host: Timestomp)
--
-- tags: transient process state
SELECT
  p.path,
  p.cmdline,
  p.cwd,
  ((strftime('%s', 'now') - f.ctime) / 86400) AS ctime_age_days,
  ((strftime('%s', 'now') - f.ctime) / 86400) AS mtime_age_days,
  ((strftime('%s', 'now') - f.btime) / 86400) AS btime_age_days,
  h.sha256,
  f.uid,
  f.gid
FROM
  processes p
  JOIN file f ON p.path = f.path
  JOIN hash h ON p.path = h.path
WHERE
  (
    ctime_age_days > 1050
    OR mtime_age_days > 1050
  )
  AND p.path NOT LIKE '%/opt/brackets/Brackets%'
  AND h.sha256 NOT IN (
    'f61dcfce6f0c04263780700e0e9a8ff2363edefc344c08bd792fd401ddaa160f' -- jp.co.canon.MSU.app.Installer
  )
