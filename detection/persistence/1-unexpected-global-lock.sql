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
    path LIKE "/dev/mqueue/.%.lock"
    OR path LIKE "/dev/mqueue/%.lock"
    OR path LIKE "/dev/shm/.%.lock"
    OR path LIKE "/dev/shm/%.lock"
    OR path LIKE "/tmp/.%.lock"
    OR path LIKE "/tmp/%.lock"
    OR path LIKE "/var/run/.%.lock"
    OR path LIKE "/var/run/%.lock"
    OR path LIKE "/var/tmp/.%.lock"
    OR path LIKE "/var/tmp/%.lock"
  )
  AND exception_key NOT IN (
    '0,0,/var/run/apport.lock,regular,0600',
    '0,0,/var/run/dnf-metadata.lock,regular,0644',
    '0,0,/var/run/ublue-update.lock,regular,0755',
    '0,0,/var/run/ufw.lock,regular,0644',
    '0,0,/var/run/unattended-upgrades.lock,regular,0640',
    '0,0,/var/run/uupd.lock,regular,0644',
    '0,0,/var/run/xtables.lock,regular,0600',
    '0,1,/var/run/prl_desktop_services.lock,regular,0644',
    '0,1,/var/run/prl_desktop_services_foreground.lock,regular,0644',
    '0,1,/var/run/VMware Fusion Services.lock,regular,0600',
    '0,1,/var/run/xv-update-resolv-conf.lock,regular,0600',
    '0,1001,/var/run/keyd.socket.lock,regular,0600',
    '500,0,/tmp/mysql.sock.lock,regular,0600',
    '500,0,/tmp/mysqlx.sock.lock,regular,0600',
    '500,0,/tmp/write.lock,regular,0644',
    '500,1000,/tmp/1000-nwg-bar.lock,regular,0600',
    '500,1000,/tmp/golangci-lint.lock,regular,0600',
    '500,1000,/tmp/minecraftlauncher.1000.pid.lock,regular,0664',
    '500,1001,/tmp/nwg-dock.lock,regular,0600',
    '74,0,/tmp/mysql.sock.lock,regular,0600',
    '74,0,/tmp/mysqlx.sock.lock,regular,0600'
  )
  AND NOT exception_key LIKE '500,0,/tmp/.s.PGSQL.%.lock,regular,0600'
  AND NOT exception_key LIKE '500,1000,/tmp/keepassxc-%.lock,regular,0644'
  AND NOT exception_key LIKE '500,1000,/tmp/keepassxc-%.lock,regular,0664'
  AND NOT exception_key LIKE '500,1000,/tmp/vscode-remote-ssh-%-install.lock,regular,0664'
  AND NOT exception_key LIKE '500,1000,/tmp/%.eksctl.lock,regular,0600'
  AND NOT exception_key LIKE '500,1000,/dev/shm/lsp-catalog-%.lock,regular,0664'
  AND NOT exception_key LIKE '500,0,/tmp/uv-%.lock,regular,0777'
  AND NOT exception_key LIKE '500,1000,/tmp/uv-%.lock,regular,0777'
