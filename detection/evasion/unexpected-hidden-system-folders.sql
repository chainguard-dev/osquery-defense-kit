-- Find unexpected hidden directories in operating-system folders
--
-- references:
--   * https://themittenmac.com/what-does-apt-activity-look-like-on-macos/
--
-- false positives:
--   * unusual installers
--
-- platform: posix
-- tags: persistent filesystem state
SELECT
  file.path,
  file.directory,
  uid,
  gid,
  mode,
  mtime,
  ctime,
  type,
  size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (
    file.path LIKE '/lib/.%'
    OR file.path LIKE '/.%'
    OR file.path LIKE '/bin/%/.%'
    OR file.path LIKE '/dev/.%'
    OR file.path LIKE '/etc/.%'
    OR file.path LIKE '/etc/%/.%'
    OR file.path LIKE '/lib/%/.%'
    OR file.path LIKE '/libexec/.%'
    OR file.path LIKE '/Library/.%'
    OR file.path LIKE '/sbin/.%'
    OR file.path LIKE '/sbin/%/.%'
    OR file.path LIKE '/tmp/.%'
    OR file.path LIKE '/usr/bin/.%'
    OR file.path LIKE '/usr/lib/.%'
    OR file.path LIKE '/usr/lib/%/.%'
    OR file.path LIKE '/usr/libexec/.%'
    OR file.path LIKE '/usr/local/bin/.%'
    OR file.path LIKE '/usr/local/lib/.%'
    OR file.path LIKE '/usr/local/lib/.%'
    OR file.path LIKE '/usr/local/libexec/.%'
    OR file.path LIKE '/usr/local/sbin/.%'
    OR file.path LIKE '/usr/sbin/.%'
    OR file.path LIKE '/var/.%'
    OR file.path LIKE '/var/lib/.%'
    OR file.path LIKE '/var/tmp/.%'
  ) -- Avoid mentioning extremely temporary files
  AND strftime('%s', 'now') - file.ctime > 20
  AND file.path NOT IN (
    '/.autorelabel',
    '/dev/.mdadm/',
    '/etc/.clean',
    '/etc/.java/',
    '/etc/selinux/.config_backup',
    '/etc/skel/.mozilla/',
    '/.file',
    '/tmp/../',
    '/tmp/./',
    '/tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress',
    '/tmp/._contentbarrier_installed',
    '/tmp/.dotnet/',
    '/tmp/.dracula-tmux-data',
    '/tmp/.dracula-tmux-weather.lock',
    '/tmp/.font-unix/',
    '/tmp/.ICE-unix/',
    '/tmp/.%.lock',
    '/tmp/.Test-unix/',
    '/tmp/.vbox-t-ipc/',
    '/tmp/.X0-lock',
    '/tmp/.X11-unix/',
    '/tmp/.X1-lock',
    '/tmp/.XIM-unix/',
    '/var/.ntw_cache',
    '/var/.Parallels_swap/',
    '/var/.pwd_cache',
    '/.vol/',
    '/.VolumeIcon.icns'
  )
  AND file.directory NOT IN ('/etc/skel', '/etc/skel/.config')
  AND file.path NOT LIKE '/%bin/bootstrapping/.default_components'
  AND file.path NOT LIKE '/tmp/.#%'
  AND file.path NOT LIKE '/tmp/.%.gcode'
  AND file.path NOT LIKE '/tmp/.vbox-%-ipc/'
  AND file.path NOT LIKE '/tmp/.com.google.Chrome.%'
  AND file.path NOT LIKE '/tmp/.org.chromium.Chromium%'
  AND file.path NOT LIKE '/tmp/.X1%-lock'
  AND file.path NOT LIKE '/usr/local/%/.keepme'
  AND file.path NOT LIKE '%/../'
  AND file.path NOT LIKE '%/./'
  AND file.path NOT LIKE '%/.build-id/'
  AND file.path NOT LIKE '%/.dwz/'
  AND file.path NOT LIKE '%/.updated'
  AND file.path NOT LIKE '%/google-cloud-sdk/.install/'
  AND NOT (
    type = 'regular'
    AND (
      filename LIKE '%.swp'
      OR size < 2
    )
  )
  AND NOT (
    type = 'regular'
    AND filename = '.placeholder'
  ) -- A curious addition seen on a NixOS machine
  AND NOT (
    file.path = '/.cache/'
    AND file.uid = 0
    AND file.gid = 0
    AND file.mode = '0755'
    AND file.size = 3
  )
  AND NOT (
    file.path = '/.config/'
    AND file.uid = 0
    AND file.gid = 0
    AND file.mode IN ('0755', '0700')
    AND file.size = 4
  )
