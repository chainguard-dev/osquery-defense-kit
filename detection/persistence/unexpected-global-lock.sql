-- Find unexpected world readable run locks
--
-- false positives:
--   * none known
--
-- references:
--   * https://www.deepinstinct.com/blog/bpfdoor-malware-evolves-stealthy-sniffing-backdoor-ups-its-game
--
-- tags: persistent filesystem state seldom
-- platform: posix
SELECT
  *,
  CONCAT (
    MIN(file.uid, 500),
    ",",
    file.gid,
    ",",
    file.path,
    ",",
    file.type,
    ',',
    mode
  ) AS exception_key
FROM
  file
WHERE
  (
    path LIKE "/tmp/%.lock"
    OR path LIKE "/var/run/%.lock"
    OR path LIKE "/var/tmp/%.lock"
    OR path LIKE "/dev/shm/%.lock"
    OR path LIKE "/dev/mqueue/%.lock"
    OR path LIKE "/tmp/.%.lock"
    OR path LIKE "/var/run/.%.lock"
    OR path LIKE "/var/tmp/.%.lock"
    OR path LIKE "/dev/shm/.%.lock"
    OR path LIKE "/dev/mqueue/.%.lock"
  )
  AND exception_key NOT IN (
    '0,0,/var/run/unattended-upgrades.lock,regular,0640',
    '500,0,/tmp/mysql.sock.lock,regular,0600',
    '500,0,/tmp/mysqlx.sock.lock,regular,0600',
    '0,0,/var/run/xtables.lock,regular,0600',
    '0,0,/var/run/dnf-metadata.lock,regular,0644',
    '0,0,/var/run/ufw.lock,regular,0644',
    '0,0,/var/run/apport.lock,regular,0600',
    '74,0,/tmp/mysql.sock.lock,regular,0600',
    '74,0,/tmp/mysqlx.sock.lock,regular,0600',
    '500,1001,/tmp/nwg-dock.lock,regular,0600'
  )
