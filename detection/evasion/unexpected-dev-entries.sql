-- Find unexpected files in /dev
--
-- references:
--   * https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- false positives:
--   * programs which have legimate uses for /dev/shm (Chrome, etc)
--
-- tags: persistent state filesystem
-- platform: posix
SELECT
  file.path,
  file.type,
  file.size,
  file.mtime,
  file.uid,
  file.ctime,
  file.gid,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path LIKE '/dev/shm/%%'
    OR file.path LIKE '/dev/%/.%'
    OR file.path LIKE '/dev/.%'
    OR file.path LIKE '/dev/.%/%'
    OR file.path LIKE '/dev/%%/.%/%'
    OR file.path LIKE '/dev/mqueue/%%'
  ) -- We should also use uid for making decisions here
  AND NOT (
    file.uid > 499
    AND (
      file.path NOT LIKE '/dev/shm/.com.google.%'
      OR file.path LIKE '/dev/shm/.org.chromium.%'
      OR file.path LIKE '/dev/shm/wayland.mozilla.%'
      OR file.path LIKE '/dev/shm/shm-%-%-%'
      OR file.path LIKE 'pulse-shm-%'
      OR file.path LIKE 'u1000-Shm%'
      OR file.path LIKE 'u1000-Valve%'
      OR file.path LIKE '/dev/shm/jack_db%'
    )
  )
  AND file.path NOT LIKE '/dev/shm/lttng-ust-wait-%'
  AND file.path NOT LIKE '/dev/shm/flatpak-%'
  AND file.path NOT LIKE '/dev/shm/libpod_rootless_lock_%'
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND file.path NOT IN ('/dev/.mdadm/')
