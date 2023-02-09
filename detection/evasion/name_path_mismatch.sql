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
  CONCAT (
    'name=',
    TRIM(SUBSTR(SPLIT (p0.name, ':./ ', 0), 0, 15)),
    ',file=',
    TRIM(SUBSTR(SPLIT (f.filename, ':./ ', 0), 0, 15)),
    ',',
    MIN(p0.euid, 500)
  ) AS exception_key,
  TRIM(SUBSTR(SPLIT (p0.name, ':./ ', 0), 0, 15)) AS short_name,
  TRIM(SUBSTR(SPLIT (f.filename, ':./ ', 0), 0, 15)) AS short_filename,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.name AS p2_name,
  p2.path AS p2_path,
  p2.cmdline AS p2_cmd,
  p2_hash.sha256 AS p2_sha256
FROM
  processes p0
  LEFT JOIN file f ON p0.path = f.path
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  short_filename != short_name
  AND NOT p0_cmd LIKE '/nix/store/%/bin/bash%' -- Serial masqueraders
  AND NOT short_filename IN (
    'bash',
    'ruby',
    'python',
    'python3',
    'perl',
    'node'
  )
  AND exception_key NOT IN (
    'name=apt,file=dash,0',
    'name=blueman-applet,file=python3,500',
    'name=blueman-tray,file=python3,500',
    'name=cat,file=coreutils,500',
    'name=pipewire-pulse,file=pipewire,120',
    'name=cc,file=gcc,0',
    'name=chrome-gnome-s,file=python3,500',
    'name=Chroot,file=firefox,500',
    'name=code-oss,file=electron,500',
    'name=com,file=docker,500',
    'name=editor,file=nano,500',
    'name=exe,file=Melvor,500',
    'name=exe,file=rootlesskit,500',
    'name=exe,file=rootlessport,500',
    'name=file,file=firefox,500',
    'name=firefox-wrappe,file=firefox,500',
    'name=firewalld,file=python3,0',
    'name=gimp,file=gimp-2,500',
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
    'name=main,file=pyrogenesis,500',
    'name=MainThread,file=plugin-contain,500',
    'name=mount,file=ntfs-3g,0',
    'name=mysqld,file=mariadbd,500',
    'name=networkd-dispa,file=python3,0',
    'name=ninja,file=samu,500',
    'name=nix-daemon,file=nix,0',
    'name=npm,file=node,500',
    'name=obsidian,file=obsidian-appim,500',
    'name=osqueryi,file=osqueryd,0',
    'name=osqueryi,file=osqueryd,500',
    'name=phpstorm,file=dash,500',
    'name=pidof,file=killall5,0',
    'name=pipewire-pulse,file=pipewire,125',
    'name=pipewire-pulse,file=pipewire,500',
    'name=Privileged,file=firefox,500',
    'name=RDD,file=firefox,500',
    'name=restorecon,file=setfiles,0',
    'name=sd_espeak-ng-m,file=sd_espeak-ng,500',
    'name=sessionclean,file=dash,0',
    'name=sh,file=busybox,0',
    'name=sh,file=busybox,500',
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
  AND NOT (p0.path LIKE '/nix/store/%/bin/coreutils')
GROUP by
  short_name,
  short_filename
