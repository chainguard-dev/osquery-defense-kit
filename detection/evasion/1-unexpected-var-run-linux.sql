-- Find unexpected regular files in /var/run
--
-- false positives:
--   * none known
--
-- references:
--   * https://sandflysecurity.com/blog/bpfdoor-an-evasive-linux-backdoor-technical-analysis/
--
-- tags: persistent
-- platform: linux
SELECT
  file.filename,
  uid,
  gid,
  mode,
  file.ctime,
  file.atime,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  file.directory = "/var/run"
  AND file.type = "regular"
  AND file.filename NOT IN (
    'acpid.pid',
    'adduser',
    'agetty.reload',
    'alsactl.pid',
    'apcupsd.pid',
    'apport.lock',
    'atd.pid',
    'atopacctd.pid',
    'auditd.pid',
    'bluetooth.blocked',
    'bootupd-lock',
    'casper-md5check.json',
    'com.rapid7.cnchub.pid',
    'com.rapid7.component_insight_agent.pid',
    'com.rapid7.ir_agent.pid',
    'cron.reboot',
    'crond.pid',
    'crond.reboot',
    'dmeventd.pid',
    'dnf-metadata.lock',
    'do-not-hibernate',
    'docker.pid',
    'firefox-restart-required',
    'gdm3.pid',
    'greetd.run',
    'gssproxy.pid',
    'haproxy.pid',
    'keyd.socket.lock',
    'libvirtd.pid',
    'lightdm.pid',
    'lima-boot-done',
    'lima-ssh-ready',
    'lxcfs.pid',
    'machine-id',
    'mcelog.pid',
    'metalauncher.pid',
    'motd',
    'motd.dynamic',
    'multipathd.pid',
    'nginx.pid',
    'nvidia-powerd.pid',
    'nvidia_runtimepm_enabled',
    'nvidia_runtimepm_supported',
    'ostree-booted',
    'pacct_source',
    'pulseaudio-enable-autospawn',
    'reboot-required',
    'reboot-required.pkgs',
    'rsyslogd.pid',
    'sm-notify.pid',
    'sshd.pid',
    'ublue-update.lock',
    'ufw.lock',
    'unattended-upgrades.lock',
    'unattended-upgrades.pid',
    'unattended-upgrades.progress',
    'usbmuxd.pid',
    'utmp',
    'uupd.lock',
    'virtlockd.pid',
    'virtlogd.pid',
    'xtables.lock',
    'zed.pid',
    'zed.state',
    'zfs_fs_name',
    'zfs_unlock_complete'
  )
  AND NOT file.filename LIKE 'u-d-c-%'
GROUP BY
  file.path;
