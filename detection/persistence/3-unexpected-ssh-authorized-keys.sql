-- Find unexpected SSH authorized keys
--
-- references:
--   * https://socradar.io/linux-malware-rapperbot-brute-forcing-ssh-servers/
--   * https://www.countercraftsec.com/blog/dota3-malware-again-and-again/
--   * https://attack.mitre.org/techniques/T1098/004/
--   * https://www.trendmicro.com/en_us/research/21/j/actors-target-huawei-cloud-using-upgraded-linux-malware-.html
--
-- tags: persistent state filesystem
-- platform: posix
SELECT
  file.path,
  file.uid,
  file.gid,
  file.atime,
  file.mtime,
  file.ctime,
  file.size,
  hash.sha256,
  users.username,
  users.uid AS u_uid
FROM
  users
  JOIN file ON file.path = users.directory || "/.ssh/authorized_keys"
  JOIN hash ON file.path = hash.path
WHERE
  file.size > 0
  AND (
    file.uid != u_uid
    OR file.uid < 500
    OR (
      file.path NOT LIKE '/home/%'
      AND file.path NOT LIKE '/Users/%'
    )
  )
