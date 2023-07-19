-- Long-running programs who were recently added to disk, based on btime/ctime
--
-- false-positives:
--   * many
--
-- tags: transient process state
-- platform: linux
SELECT
  f.ctime AS p0_ctime,
  f.mtime AS p0_mtime,
  -- Child
  p0.pid AS p0_pid,
  p0.path AS p0_path,
  p0.start_time AS p0_start,
  p0.name AS p0_name,
  p0.cmdline AS p0_cmd,
  p0.cwd AS p0_cwd,
  p0.cgroup_path AS p0_cgroup,
  p0.euid AS p0_euid,
  p0_hash.sha256 AS p0_sha256,
  -- Parent
  p0.parent AS p1_pid,
  p1.path AS p1_path,
  p1.start_time AS p1_start,
  p1.name AS p1_name,
  p1.euid AS p1_euid,
  p1.cmdline AS p1_cmd,
  p1_hash.sha256 AS p1_sha256,
  -- Grandparent
  p1.parent AS p2_pid,
  p2.start_time AS p2_start,
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
  p0.start_time > 0
  AND f.ctime > 0
  AND p0.start_time > (strftime('%s', 'now') - 43200)
  AND (p0.start_time - MAX(f.ctime, f.btime)) < 45
  AND p0.start_time >= MAX(f.ctime, f.ctime)
  AND NOT f.directory IN ('/usr/lib/firefox', '/usr/local/kolide-k2/bin') -- Typically daemons or long-running desktop apps
  -- These are binaries that are known to get updated and subsequently executed
  --
  -- What I would give for osquery to support binary signature verification on Linux
  AND NOT p0.path IN (
    '',
    '/bin/containerd',
    '/bin/containerd-shim-runc-v2',
    '/opt/google/chrome/chrome',
    '/opt/google/chrome/chrome_crashpad_handler',
    '/opt/google/chrome/nacl_helper',
    '/opt/Lens/chrome_crashpad_handler',
    '/opt/Lens/lens',
    '/opt/sublime_text/sublime_text',
    '/usr/bin/alacritty',
    '/usr/bin/appstreamcli',
    '/usr/bin/bash',
    '/usr/bin/cargo',
    '/usr/bin/cmake',
    '/usr/bin/containerd',
    '/usr/bin/containerd-shim-runc-v2',
    '/usr/bin/dash',
    '/usr/bin/docker',
    '/usr/bin/dockerd',
    '/usr/bin/docker-proxy',
    '/usr/bin/faked',
    '/usr/bin/fusermount3',
    '/usr/bin/gedit',
    '/usr/bin/gitsign-credential-cache',
    '/usr/bin/gjs-console',
    '/usr/bin/gnome-calendar',
    '/usr/bin/gnome-keyring-daemon',
    '/usr/bin/gnome-shell',
    '/usr/bin/gnome-software',
    '/usr/bin/golangci-lint',
    '/usr/bin/hugo',
    '/usr/bin/ibus-daemon',
    '/usr/bin/kbfsfuse',
    '/usr/bin/keybase',
    '/usr/bin/keybase-redirector',
    '/usr/bin/limactl',
    '/usr/bin/make',
    '/usr/bin/NetworkManager',
    '/usr/bin/nm-applet',
    '/usr/bin/nvidia-persistenced',
    '/usr/bin/obs',
    '/usr/bin/packer',
    '/usr/bin/pavucontrol',
    '/usr/bin/pipewire',
    '/usr/bin/pipewire-pulse',
    '/usr/bin/python3.11',
    '/usr/bin/rpi-imager',
    '/usr/bin/rpmbuild',
    '/usr/bin/snap',
    '/usr/bin/ssh-agent',
    '/usr/bin/sshfs',
    '/usr/bin/sudo',
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
    '/usr/lib/docker/cli-plugins/docker-compose',
    '/usr/lib/electron25/electron',
    '/usr/libexec/accounts-daemon',
    '/usr/libexec/bluetooth/bluetoothd',
    '/usr/libexec/docker/docker-proxy',
    '/usr/libexec/flatpak-system-helper',
    '/usr/libexec/fwupd/fwupd',
    '/usr/libexec/gnome-shell-calendar-server',
    '/usr/libexec/gstreamer-1.0/gst-plugin-scanner',
    '/usr/libexec/ibus-dconf',
    '/usr/libexec/ibus-engine-simple',
    '/usr/libexec/ibus-extension-gtk3',
    '/usr/libexec/ibus-portal',
    '/usr/libexec/ibus-x11',
    '/usr/libexec/power-profiles-daemon',
    '/usr/libexec/snapd/snapd',
    '/usr/libexec/sssd/sssd_kcm',
    '/usr/libexec/tracker-extract-3',
    '/usr/libexec/tracker-miner-fs-3',
    '/usr/lib/flatpak-session-helper',
    '/usr/lib/fwupd/fwupd',
    '/usr/lib/gdm',
    '/usr/lib/gdm-session-worker',
    '/usr/lib/gdm-x-session',
    '/usr/lib/gnome-shell-calendar-server',
    '/usr/lib/google-cloud-sdk/platform/bundledpythonunix/bin/python3',
    '/usr/lib/ibus/ibus-dconf',
    '/usr/lib/ibus/ibus-engine-simple',
    '/usr/lib/ibus/ibus-portal',
    '/usr/lib/libreoffice/program/oosplash',
    '/usr/lib/libreoffice/program/soffice.bin',
    '/usr/lib/polkit-1/polkitd',
    '/usr/lib/polkit-gnome/polkit-gnome-authentication-agent-1',
    '/usr/lib/slack/chrome_crashpad_handler',
    '/usr/lib/slack/slack',
    '/usr/lib/snapd/snapd',
    '/usr/lib/systemd/systemd',
    '/usr/lib/systemd/systemd-homed',
    '/usr/lib/systemd/systemd-hostnamed',
    '/usr/lib/systemd/systemd-journald',
    '/usr/lib/systemd/systemd-logind',
    '/usr/lib/systemd/systemd-machined',
    '/usr/lib/systemd/systemd-oomd',
    '/usr/lib/systemd/systemd-resolved',
    '/usr/lib/systemd/systemd-timesyncd',
    '/usr/lib/systemd/systemd-userdbd',
    '/usr/lib/systemd/systemd-userwork',
    '/usr/lib/tracker-extract-3',
    '/usr/lib/upowerd',
    '/usr/lib/x86_64-linux-gnu/obs-plugins/obs-browser-page',
    '/usr/lib/xdg-desktop-portal-gtk',
    '/usr/lib/xf86-video-intel-backlight-helper',
    '/usr/local/bin/kind',
    '/usr/sbin/alsactl',
    '/usr/sbin/avahi-daemon',
    '/usr/sbin/chronyd',
    '/usr/sbin/cups-browsed',
    '/usr/sbin/cupsd',
    '/usr/sbin/irqbalance',
    '/usr/sbin/ModemManager',
    '/usr/sbin/NetworkManager',
    '/usr/sbin/rngd',
    '/usr/sbin/semodule',
    '/usr/sbin/sshd',
    '/usr/sbin/tailscaled',
    '/usr/share/code/chrome_crashpad_handler',
    '/usr/share/code/code',
    '/usr/share/spotify-client/spotify',
    '/usr/share/teams/team'
  )
  AND NOT p0.path LIKE '/home/%/bin/%'
  AND NOT p0.path LIKE '/home/%/git/%'
  AND NOT p0.path LIKE '/home/%/.local/share/JetBrains/Toolbox/apps/%'
  AND NOT p0.path LIKE '/home/%/.local/share/nvim/mason/packages/%'
  AND NOT p0.path LIKE '/home/%/.cache/JetBrains/%/GoLand/___%'
  AND NOT p0.path LIKE '/home/%/.local/share/Steam/ubuntu%'
  AND NOT p0.path LIKE '/home/%/.rustup/toolchains/%/libexec/%'
  AND NOT p0.path LIKE '/home/%/jbr/lib/jcef_helper'
  AND NOT p0.path LIKE '/home/%/jbr/bin/java'
  AND NOT p0.path LIKE '/home/%/node_modules/.bin/%'
  AND NOT p0.path LIKE '/home/%/Projects/%'
  AND NOT p0.path LIKE '/home/%/terraform-provider-%'
  AND NOT p0.path LIKE '/home/%/%.test'
  AND NOT p0.path LIKE '/nix/store/%/bin/%'
  AND NOT p0.path LIKE '/nix/store/%/libexec/%'
  AND NOT p0.path LIKE '/opt/%'
  AND NOT p0.path LIKE '/tmp/go-build%'
  AND NOT p0.path LIKE '/tmp/terraform_%/terraform'
  AND NOT p0.path LIKE '/tmp/tmp0.%/%/bin/%'
  AND NOT p0.path LIKE '/usr/local/bin/%'
  AND NOT p0.path LIKE '/usr/local/Cellar/%'
  AND NOT p0.path LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd'
  AND NOT p0.path LIKE '/usr/local/kolide-k2/bin/launcher-updates/%/launcher'
  AND NOT p0.path LIKE '%/.vscode/extensions/%'
  AND NOT p0.path LIKE '%/.local/share/spotify-launcher/install/usr/%'
  AND NOT (
    p0.name IN ('osqtool-x86_64', 'osqtool-arm64')
    AND p0.cmdline LIKE './%'
  )
  AND NOT p1.path IN ('/usr/bin/gnome-shell') -- Filter out developers working on their own code
  AND NOT p1.name = 'makepkg'
  AND NOT p2.path = '/usr/bin/yay'
  AND NOT p2.cmdline LIKE '/usr/bin/yay %'
  AND NOT (
    p0.path LIKE '/home/%'
    AND p0.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p0.uid
    AND p0.cmdline LIKE './%'
    AND p0.path NOT LIKE '%/.%'
    AND p0.path NOT LIKE '%cache%'
  )
  AND NOT (
    p0.path LIKE '/tmp/%/osqtool-%'
    AND p0.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p0.uid
    AND p0.cmdline LIKE './%'
  )
  AND NOT (
    p0.path LIKE '/home/%/.magefile/%'
    AND p0.uid > 499
    AND f.ctime = f.mtime
    AND f.uid = p0.uid
  )
GROUP BY
  p0.pid
