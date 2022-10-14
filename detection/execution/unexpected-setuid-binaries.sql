-- Find unexpected setuid binaries on disk
--
-- false positives:
--   * new software
--
-- tags: persistent seldom
-- platform: posix
SELECT
  file.path,
  gid,
  uid,
  mode,
  type,
  size,
  sha256
FROM
  file
  JOIN hash ON file.path = hash.path
WHERE
  (
    file.path LIKE '/bin/%'
    OR file.path LIKE '/home/%/bin/%'
    OR file.path LIKE '/opt/%/bin/%'
    OR file.path LIKE '/opt/%/sbin/%'
    OR file.path LIKE '/sbin/%'
    OR file.path LIKE '/tmp/%'
    OR file.path LIKE '/Users/%/bin/%'
    OR file.path LIKE '/usr/bin/%'
    OR file.path LIKE '/usr/lib/%'
    OR file.path LIKE '/usr/lib64/%'
    OR file.path LIKE '/usr/libexec/%'
    OR file.path LIKE '/usr/local/bin/%'
    OR file.path LIKE '/usr/local/lib/%'
    OR file.path LIKE '/usr/local/lib64/%'
    OR file.path LIKE '/usr/local/libexec/%'
    OR file.path LIKE '/usr/local/sbin/%'
    OR file.path LIKE '/usr/sbin/%'
    OR file.path LIKE '/var/lib/%'
    OR file.path LIKE '/var/tmp/%'
  )
  AND type = 'regular'
  AND mode NOT LIKE '0%'
  AND mode NOT LIKE '1%'
  AND mode NOT LIKE '2%'
  AND NOT (
    mode LIKE '4%11'
    AND uid = 0
    AND gid = 0
    AND file.path IN (
      '/bin/cdda2wav',
      '/bin/cdrecord',
      '/bin/icedax',
      '/bin/mount.nfs',
      '/bin/mount.nfs4',
      '/bin/readcd',
      '/bin/readom',
      '/bin/rscsi',
      '/bin/staprun',
      '/bin/sudo',
      '/bin/sudoedit',
      '/bin/umount.nfs',
      '/bin/umount.nfs4',
      '/bin/wodim',
      '/sbin/cdda2wav',
      '/sbin/cdrecord',
      '/sbin/icedax',
      '/sbin/mount.nfs',
      '/sbin/mount.nfs4',
      '/sbin/readcd',
      '/sbin/readom',
      '/sbin/rscsi',
      '/sbin/umount.nfs',
      '/sbin/umount.nfs4',
      '/sbin/userhelper',
      '/sbin/wodim',
      '/usr/bin/cdda2wav',
      '/usr/bin/cdrecord',
      '/usr/bin/icedax',
      '/usr/bin/mount.nfs',
      '/usr/bin/mount.nfs4',
      '/usr/bin/readcd',
      '/usr/bin/readom',
      '/usr/bin/rscsi',
      '/usr/bin/staprun',
      '/usr/bin/sudo',
      '/usr/bin/sudoedit',
      '/usr/bin/umount.nfs',
      '/usr/bin/umount.nfs4',
      '/usr/bin/wodim',
      '/usr/libexec/security_authtrampoline',
      '/usr/sbin/cdda2wav',
      '/usr/sbin/cdrecord',
      '/usr/sbin/icedax',
      '/usr/sbin/mount.nfs',
      '/usr/sbin/mount.nfs4',
      '/usr/sbin/readcd',
      '/usr/sbin/readom',
      '/usr/sbin/rscsi',
      '/usr/sbin/umount.nfs',
      '/usr/sbin/umount.nfs4',
      '/usr/sbin/userhelper',
      '/usr/sbin/wodim'
    )
  )
  AND NOT (
    mode LIKE '4%55'
    AND uid = 0
    AND gid = 0
    AND file.path IN (
      '/bin/chage',
      '/bin/chfn',
      '/bin/chsh',
      '/bin/crontab',
      '/bin/doas',
      '/bin/expiry',
      '/bin/fusermount-glusterfs',
      '/bin/fusermount',
      '/bin/fusermount3',
      '/bin/gpasswd',
      '/bin/ksu',
      '/bin/mount',
      '/bin/ndisc6',
      '/bin/newgidmap',
      '/bin/newgrp',
      '/bin/newuidmap',
      '/usr/bin/newgidmap',
      '/bin/nvidia-modprobe',
      '/bin/passwd',
      '/bin/pkexec',
      '/bin/ps',
      '/bin/rdisc6',
      '/bin/rltraceroute6',
      '/bin/sg',
      '/bin/su',
      '/bin/sudo',
      '/bin/sudoedit',
      '/bin/suexec',
      '/bin/ubuntu-core-launcher',
      '/bin/umount',
      '/bin/vmware-user-suid-wrapper',
      '/bin/vmware-user',
      '/sbin/chage',
      '/sbin/chfn',
      '/sbin/chsh',
      '/sbin/crontab',
      '/sbin/doas',
      '/sbin/expiry',
      '/sbin/fusermount',
      '/sbin/fusermount3',
      '/sbin/gpasswd',
      '/sbin/grub2-set-bootflag',
      '/sbin/ksu',
      '/sbin/mount.nfs',
      '/sbin/mount.nfs4',
      '/sbin/mount',
      '/sbin/ndisc6',
      '/sbin/newgrp',
      '/sbin/nvidia-modprobe',
      '/sbin/pam_timestamp_check',
      '/sbin/passwd',
      '/sbin/pkexec',
      '/sbin/rdisc6',
      '/sbin/rltraceroute6',
      '/sbin/sg',
      '/sbin/su',
      '/sbin/sudo',
      '/sbin/sudoedit',
      '/sbin/suexec',
      '/sbin/umount.nfs',
      '/sbin/umount.nfs4',
      '/sbin/umount',
      '/sbin/unix_chkpwd',
      '/usr/bin/at',
      '/usr/bin/atq',
      '/usr/bin/atrm',
      '/usr/bin/batch',
      '/usr/bin/chage',
      '/usr/bin/chfn',
      '/usr/bin/chsh',
      '/usr/bin/crontab',
      '/usr/bin/doas',
      '/usr/bin/expiry',
      '/usr/bin/fusermount-glusterfs',
      '/usr/bin/fusermount',
      '/usr/bin/fusermount3',
      '/usr/bin/gpasswd',
      '/usr/bin/ksu',
      '/usr/bin/login',
      '/usr/bin/mount',
      '/usr/bin/ndisc6',
      '/usr/bin/newgrp',
      '/usr/bin/newuidmap',
      '/usr/bin/nvidia-modprobe',
      '/usr/bin/passwd',
      '/usr/bin/pkexec',
      '/usr/bin/quota',
      '/usr/bin/mullvad-exclude',
      '/usr/sbin/mullvad-exclude',
      '/usr/bin/rdisc6',
      '/usr/bin/rltraceroute6',
      '/usr/bin/sg',
      '/sbin/mullvad-exclude',
      '/bin/mullvad-exclude',
      '/usr/bin/su',
      '/usr/bin/sudo',
      '/usr/bin/sudoedit',
      '/usr/bin/suexec',
      '/usr/bin/top',
      '/usr/bin/ubuntu-core-launcher',
      '/usr/bin/umount',
      '/usr/bin/vmware-user-suid-wrapper',
      '/usr/bin/vmware-user',
      '/usr/lib/mail-dotlock',
      '/usr/lib/xf86-video-intel-backlight-helper',
      '/usr/lib/Xorg.wrap',
      '/usr/lib64/mail-dotlock',
      '/usr/lib64/xf86-video-intel-backlight-helper',
      '/usr/lib64/Xorg.wrap',
      '/usr/libexec/authopen',
      '/usr/libexec/polkit-agent-helper-1',
      '/usr/libexec/qemu-bridge-helper',
      '/usr/libexec/Xorg.wrap',
      '/usr/sbin/chage',
      '/usr/sbin/chfn',
      '/usr/sbin/chsh',
      '/usr/sbin/crontab',
      '/usr/sbin/doas',
      '/usr/sbin/expiry',
      '/usr/sbin/fusermount',
      '/usr/sbin/fusermount3',
      '/usr/sbin/gpasswd',
      '/usr/sbin/grub2-set-bootflag',
      '/usr/sbin/ksu',
      '/usr/sbin/mount.nfs',
      '/usr/sbin/mount.nfs4',
      '/usr/sbin/mount',
      '/usr/sbin/ndisc6',
      '/usr/sbin/newgrp',
      '/usr/sbin/nvidia-modprobe',
      '/usr/sbin/pam_timestamp_check',
      '/usr/sbin/passwd',
      '/usr/sbin/pkexec',
      '/usr/sbin/rdisc6',
      '/usr/sbin/rltraceroute6',
      '/usr/sbin/sg',
      '/usr/sbin/su',
      '/usr/sbin/sudo',
      '/usr/sbin/sudoedit',
      '/usr/sbin/suexec',
      '/usr/sbin/traceroute',
      '/usr/sbin/traceroute6',
      '/usr/sbin/umount.nfs',
      '/usr/sbin/umount.nfs4',
      '/usr/sbin/umount',
      '/usr/sbin/unix_chkpwd'
    )
  )
  AND NOT (
    mode = '4754'
    AND uid = 0
    AND gid = 30
    AND file.path IN ('/usr/sbin/pppd', '/sbin/pppd')
  )
  AND NOT (
    mode = '6755'
    AND uid = 0
    AND gid = 0
    AND file.path IN (
      '/bin/mount.cifs',
      '/bin/mount.smb3',
      '/bin/unix_chkpwd',
      '/sbin/mount.cifs',
      '/sbin/mount.smb3',
      '/sbin/unix_chkpwd',
      '/usr/bin/mount.cifs',
      '/usr/bin/mount.smb3',
      '/usr/bin/unix_chkpwd',
      '/usr/lib/xtest',
      '/usr/lib64/xtest',
      '/usr/sbin/mount.cifs',
      '/usr/sbin/mount.smb3',
      '/usr/sbin/unix_chkpwd'
    )
  )
  AND NOT (
    mode = '4110'
    AND uid = 0
    AND gid = 156
    AND file.path IN ('/bin/staprun', '/usr/bin/staprun')
  )
