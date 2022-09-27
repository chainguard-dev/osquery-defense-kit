-- Inspired by BPFdoor
-- https://www.sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
SELECT
  file.path,
  file.type,
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
    file.path LIKE "/dev/shm/%%"
    OR file.path LIKE "/dev/shm/.%"
    OR file.path LIKE "/dev/shm/.%/%"
    OR file.path LIKE "/dev/%/.%"
    OR file.path LIKE "/dev/.%"
    OR file.path LIKE "/dev/.%/%"
    OR file.path LIKE "/dev/mqueue/%%"
    OR file.path LIKE "/dev/mqueue/.%/%"
    OR file.path LIKE "/dev/mqueue/.%"
  )
  AND file.path NOT LIKE '/dev/shm/.com.google.%'
  AND file.path NOT LIKE '/dev/shm/.org.chromium.%'
  AND file.path NOT LIKE '/dev/shm/wayland.mozilla.%'
  AND file.path NOT LIKE "/dev/shm/jack_db%"
  AND file.path NOT LIKE "/dev/shm/lttng-ust-wait-%"
  AND file.path NOT LIKE "/dev/shm/flatpak-%"
  AND file.path NOT LIKE "/dev/shm/libpod_rootless_lock_%"
  AND file.path NOT LIKE "%/../%"
  AND file.path NOT LIKE "%/./%"
  AND filename NOT IN ('..')
  AND filename NOT LIKE "pulse-shm-%"
  AND filename NOT LIKE "u1000-Shm%"
  AND filename NOT LIKE "u1000-Valve%"
  AND file.path NOT IN ('/dev/.mdadm/')
