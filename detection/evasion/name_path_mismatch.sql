-- Processes that have an unrelated name in the process tree than the program on disk.
--
-- false positives:
--   * new software, particularly those using interpreted languages
--
-- references:
--   * https://attack.mitre.org/techniques/T1036/004/ (Masquerade Task or Service)
--
-- tags: persistent daemon high
SELECT
  p.name,
  TRIM(SUBSTR(SPLIT (p.name, ':./ ', 0), 0, 15)) AS short_name,
  TRIM(SUBSTR(SPLIT (f.filename, ':./ ', 0), 0, 15)) AS short_filename,
  f.filename,
  p.path,
  p.cwd,
  p.cmdline AS cmd,
  p.parent AS parent_pid,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmd,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  hash.sha256 AS child_sha256,
  phash.sha256 AS parent_sha256,
  CONCAT (
    'name=',
    TRIM(SUBSTR(SPLIT (p.name, ':./ ', 0), 0, 15)),
    ',file=',
    TRIM(SUBSTR(SPLIT (f.filename, ':./ ', 0), 0, 15)),
    ',',
    MIN(p.uid, 500)
  ) AS exception_key
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN hash AS phash ON pp.path = phash.path
WHERE
  short_filename != short_name
  AND NOT cmd LIKE '/nix/store/%/bin/bash%' -- Serial masqueraders
  AND NOT short_filename IN ('bash', 'ruby', 'python', 'python3', 'perl')
  AND exception_key NOT IN (
    'name=blueman-applet,file=python3,500',
    'name=blueman-tray,file=python3,500',
    'name=cat,file=coreutils,500',
    'name=cc,file=gcc,0',
    'name=chrome-gnome-s,file=python3,500',
    'name=Chroot,file=firefox,500',
    'name=code-oss,file=electron,500',
    'name=exe,file=rootlesskit,500',
    'name=exe,file=rootlessport,500',
    'name=file,file=firefox,500',
    'name=firefox-wrappe,file=firefox,500',
    'name=firewalld,file=python3,0',
    'name=gjs,file=gjs-console,120',
    'name=gjs,file=gjs-console,42',
    'name=gjs,file=gjs-console,500',
    'name=gnome-characte,file=gjs-console,500',
    'name=gnome-character,file=gjs-console,500',
    'name=gnome-tweak-to,file=python3,500',
    'name=gsettings-hel,file=gsettings-help,500',
    'name=iptables,file=xtables-nft-mu,0',
    'name=Isolated,file=firefox,500',
    'name=Isolated,file=thunderbird,500',
    'name=MainThread,file=plugin-contain,500',
    'name=mount,file=ntfs-3g,0',
    'name=mysqld,file=mariadbd,500',
    'name=networkd-dispa,file=python3,0',
    'name=ninja,file=samu,500',
    'name=nix-daemon,file=nix,0',
    'name=npm,file=node,500',
    'name=osqueryi,file=osqueryd,0',
    'name=osqueryi,file=osqueryd,500',
    'name=phpstorm,file=dash,500',
    'name=pidof,file=killall5,0',
    'name=pipewire-pulse,file=pipewire,500',
    'name=Privileged,file=firefox,500',
    'name=RDD,file=firefox,500',
    'name=restorecon,file=setfiles,0',
    'name=sd_espeak-ng-m,file=sd_espeak-ng,500',
    'name=sessionclean,file=dash,0',
    'name=sh,file=busybox,0',
    'name=sh,file=dash,0',
    'name=sh,file=dash,500',
    'name=slic3r_main,file=prusa-slicer,500',
    'name=Socket,file=firefox,500',
    'name=streamdeck,file=python3,500',
    'name=systemd-udevd,file=udevadm,0',
    'name=systemd-udevd,file=udevadm,500',
    'name=terminator,file=python3,500',
    'name=Thunar,file=thunar,500',
    'name=unattended-upg,file=python3,0',
    'name=Utility,file=firefox,500',
    'name=vi,file=nvim,500',
    'name=vi,file=vim,500',
    'name=WebExtensions,file=firefox,500',
    'name=Web,file=firefox,500',
    'name=Web,file=thunderbird,500',
    'name=X,file=Xorg,0',
    'name=zfs-auto-snaps,file=ruby,0',
    'name=zoom,file=ZoomLauncher,500'
  )
  AND NOT (
    short_filename = 'systemd'
    AND short_name LIKE '(sd%'
  )
  AND NOT (
    short_filename LIKE 'emacs%'
    AND short_name = 'emacs'
  )
  AND NOT (p.path LIKE '/nix/store/%/bin/coreutils')
GROUP by
  short_name,
  short_filename
