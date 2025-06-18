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
    'casper-md5check.json',
    'atd.pid',
    'atopacctd.pid',
    'auditd.pid',
    'bluetooth.blocked',
    'bootupd-lock',
    'dmeventd.pid',
    'do-not-hibernate',
    'greetd.run',
    'com.rapid7.cnchub.pid',
    'com.rapid7.component_insight_agent.pid',
    'com.rapid7.ir_agent.pid',
    'cron.reboot',
    'crond.pid',
    'crond.reboot',
    'dnf-metadata.lock',
    'docker.pid',
    'firefox-restart-required',
    'gdm3.pid',
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
    'motd.dynamic',
    'motd',
    'multipathd.pid',
    'nginx.pid',
    'nvidia_runtimepm_enabled',
    'nvidia_runtimepm_supported',
    'nvidia-powerd.pid',
    'ostree-booted',
    'pacct_source',
    'pulseaudio-enable-autospawn',
    'reboot-required.pkgs',
    'reboot-required',
    'rsyslogd.pid',
    'sm-notify.pid',
    'sshd.pid',
    'u-d-c-nvidia-drm-was-loaded',
    'u-d-c-nvidia-was-loaded',
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
  AND NOT file.filename LIKE 'u-d-c-gpu-0%'
GROUP BY
  file.path;
