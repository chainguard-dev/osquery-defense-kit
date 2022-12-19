-- Programs who were recently added to disk, based on btime/ctime
--
-- false-positives:
--   * many
--
-- tags: transient process state often
-- platform: linux
SELECT
  p.pid,
  p.path,
  p.name,
  p.cmdline,
  p.cwd,
  p.euid,
  p.parent,
  f.directory,
  f.ctime,
  f.btime,
  f.mtime,
  p.cgroup_path,
  p.start_time,
  pp.path AS parent_path,
  pp.name AS parent_name,
  pp.cmdline AS parent_cmdline,
  pp.cwd AS parent_cwd,
  pp.euid AS parent_euid,
  ch.sha256 AS child_sha256,
  ph.sha256 AS parent_sha256
FROM
  processes p
  LEFT JOIN file f ON p.path = f.path
  LEFT JOIN processes pp ON p.parent = pp.pid
  LEFT JOIN hash AS ch ON p.path = ch.path
  LEFT JOIN hash AS ph ON pp.path = ph.path
WHERE
  p.start_time > 0
  AND f.ctime > 0
  AND p.start_time > (strftime('%s', 'now') - 7200)
  AND (p.start_time - MAX(f.ctime, f.btime)) < 180
  AND p.start_time >= MAX(f.ctime, f.ctime)
  AND NOT f.directory IN ('/usr/lib/firefox', '/usr/local/kolide-k2/bin') -- Typically daemons or long-running desktop apps
  -- These are binaries that are known to get updated and subsequently executed
  --
  -- What I would give for osquery to support binary signature verification on Linux
  AND NOT p.path IN (
    '',
    '/opt/google/chrome/chrome',
    '/opt/google/chrome/chrome_crashpad_handler',
    '/opt/google/chrome/nacl_helper',
    '/opt/Lens/chrome_crashpad_handler',
    '/opt/Lens/lens',
    '/opt/sublime_text/sublime_text',
    '/usr/bin/alacritty',
    '/usr/bin/bash',
    '/usr/bin/cargo',
    '/usr/bin/containerd',
    '/usr/bin/containerd-shim-runc-v2',
    '/usr/bin/docker',
    '/usr/bin/dockerd',
    '/usr/bin/docker-proxy',
    '/usr/bin/gedit',
    '/usr/bin/gnome-keyring-daemon',
    '/usr/bin/kbfsfuse',
    '/usr/bin/keybase',
    'usr/bin/keybase-redirector',
    '/usr/bin/NetworkManager',
    '/usr/bin/nm-applet',
    '/usr/bin/obs',
    '/usr/bin/pavucontrol',
    '/usr/bin/pipewire',
    '/usr/bin/rpi-imager',
    '/usr/bin/snap',
    '/usr/bin/tailscaled',
    '/usr/bin/udevadm',
    '/usr/bin/wireplumber',
    '/usr/bin/wpa_supplicant',
    '/usr/lib64/electron/electron',
    '/usr/lib64/firefox/firefox',
    '/usr/lib64/google-cloud-sdk/platform/bundledpythonunix/bin/python3',
    '/usr/lib64/thunderbird/thunderbird',
    '/usr/lib/at-spi2-registryd',
    '/usr/lib/at-spi-bus-launcher',
    '/usr/libexec/bluetooth/bluetoothd',
    '/usr/libexec/docker/docker-proxy',
    '/usr/libexec/fwupd/fwupd',
    '/usr/libexec/snapd/snapd',
    '/usr/libexec/sssd/sssd_kcm',
    '/usr/libexec/tracker-miner-fs-3',
    '/usr/lib/flatpak-session-helper',
    '/usr/lib/fwupd/fwupd',
    '/usr/lib/gdm',
    '/usr/lib/gdm-session-worker',
    '/usr/lib/gdm-x-session',
    '/usr/lib/google-cloud-sdk/platform/bundledpythonunix/bin/python3',
    '/usr/lib/libreoffice/program/oosplash',
    '/usr/lib/libreoffice/program/soffice.bin',
    '/usr/lib/polkit-1/polkitd',
    '/usr/lib/slack/chrome_crashpad_handler',
    '/usr/lib/slack/slack',
    '/usr/lib/snapd/snapd',
    '/usr/lib/systemd/systemd',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd-logind',
    '/usr/lib/systemd/systemd-oomd',
    '/usr/lib/systemd/systemd-resolved',
    '/usr/lib/systemd/systemd-timesyncd',
    '/usr/lib/systemd/systemd-userdbd',
    '/usr/lib/x86_64-linux-gnu/obs-plugins/obs-browser-page',
    '/usr/lib/xdg-desktop-portal-gtk',
    '/usr/lib/xf86-video-intel-backlight-helper',
    '/usr/local/bin/kind',
    '/usr/sbin/alsactl',
    '/usr/sbin/avahi-daemon',
    '/usr/sbin/chronyd',
    '/usr/sbin/cupsd',
    '/usr/sbin/tailscaled',
    '/usr/share/code/chrome_crashpad_handler',
    '/usr/share/code/code',
    '/usr/share/spotify-client/spotify',
    '/usr/share/teams/team'
  )
  AND NOT p.path LIKE '/tmp/go-build%'
  AND NOT p.path LIKE '/home/%/bin/%'
  AND NOT p.path LIKE '/home/%/terraform-provider-%'
  AND NOT p.path LIKE '/home/%/%.test'
  AND NOT p.path LIKE '/home/%/Projects/%'
  AND NOT p.path LIKE '/home/%/.local/share/nvim/mason/packages/%'
  AND NOT p.path LIKE '/home/%/node_modules/.bin/%'
  AND NOT p.path LIKE '/nix/store/%/bin/%'
  AND NOT p.path LIKE '/nix/store/%/libexec/%'
  AND NOT p.path LIKE '/usr/local/bin/%'
  AND NOT p.path LIKE '/opt/%'
  AND NOT p.path LIKE '/usr/local/Cellar/%'
  AND NOT p.path LIKE '/home/%/.local/share/Steam/ubuntu12_64/%'
  AND NOT p.path LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND NOT p.path LIKE '%/.vscode/extensions/%'
  AND NOT p.path LIKE '/tmp/terraform_%/terraform'
  AND NOT pp.path IN ('/usr/bin/gnome-shell') -- Filter out developers working on their own code
  AND NOT (
    p.path LIKE '/home/%'
    AND p.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p.uid
    AND p.cmdline LIKE './%'
  )
  AND NOT (
    p.path LIKE '/home/%/.magefile/%'
    AND p.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p.uid
  )
GROUP BY
  p.pid
