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
    OR file.path LIKE '/dev/.%'
    OR file.path LIKE '/dev/.%/%'
    OR file.path LIKE '/dev/%/.%'
    OR file.path LIKE '/dev/%%/.%/%'
    OR file.path LIKE '/dev/mqueue/%%'
  )
  AND NOT (
    file.uid > 499
    AND (
      file.path LIKE '/dev/shm/.com.google.%'
      OR file.path LIKE '/dev/shm/.com.microsoft.Edge.%'
      OR file.path LIKE '/dev/shm/.org.chromium.%'
      OR file.path LIKE '/dev/shm/aomshm.%'
      OR file.path LIKE '/dev/shm/byobu-%'
      OR file.path LIKE '/dev/shm/jack_db%'
      OR file.path LIKE '/dev/shm/lsp-catalog-%.lock'
      OR file.path LIKE '/dev/shm/pulse-shm-%'
      OR file.path LIKE '/dev/shm/sem.%autosave'
      OR file.path LIKE '/dev/shm/shm-%-%-%'
      OR file.path LIKE '/dev/shm/u1000-Shm%'
      OR file.path LIKE '/dev/shm/u1000-Valve%'
      OR file.path LIKE '/dev/shm/wayland.mozilla.%'
      OR file.path LIKE '/dev/shm/CefRaster%'
      OR file.path LIKE '/dev/shm/xapp-tmp-%'
      OR file.path LIKE '/dev/mqueue/us.zoom.aom.globalmgr.%.rpc'
    )
  )
  AND NOT (
    file.size <= 32
    AND file.path LIKE '/dev/shm/%'
  )
  AND file.path NOT LIKE '/dev/shm/flatpak-%'
  AND file.path NOT LIKE '/dev/shm/libpod_rootless_lock_%'
  AND file.path NOT LIKE '/dev/shm/lttng-ust-wait-%'
  AND file.path NOT LIKE '/dev/shm/sem.mp-%'
  AND file.path NOT LIKE '%/../%'
  AND file.path NOT LIKE '%/./%'
  AND file.path NOT IN (
    '/dev/.mdadm/',
    '/dev/shm/libpod_lock',
    '/dev/shm/sem.camlock'
  )
