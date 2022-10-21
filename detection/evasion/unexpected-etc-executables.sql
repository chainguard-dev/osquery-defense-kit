-- Find unexpected executables in /etc
--
-- references:
--   * https://blog.lumen.com/chaos-is-a-go-based-swiss-army-knife-of-malware/
--
-- tags: persistent
-- platform: posix
SELECT
  file.path,
  file.directory,
  uid,
  gid,
  mode,
  file.mtime,
  file.size,
  hash.sha256,
  magic.data
FROM
  file
  LEFT JOIN hash on file.path = hash.path
  LEFT JOIN magic ON file.path = magic.path
WHERE
  (file.path LIKE '/etc/%%')
  AND file.type = 'regular'
  AND (
    file.mode LIKE '%7%'
    or file.mode LIKE '%5%'
    or file.mode LIKE '%1%'
  )
  AND file.directory NOT IN (
    '/etc/acpi',
    '/etc/alternatives',
    '/etc/apcupsd',
    '/etc/kde/shutdown',
    '/etc/apm/resume.d',
    '/etc/apm/scripts.d',
    '/etc/nix/result',
    '/etc/apm/suspend.d',
    '/etc/avahi',
    '/etc/nix/result/sw/bin',
    '/etc/bash_completion.d',
    '/etc/brltty/Contraction',
    '/etc/chromium/native-messaging-hosts',
    '/etc/cifs-utils',
    '/etc/console-setup',
    '/etc/cron.daily',
    '/etc/cron.hourly',
    '/etc/cron.monthly',
    '/etc/cron.weekly',
    '/etc/dhcp/dhclient.d',
    '/etc/dhcp/dhclient-enter-hooks.d',
    '/etc/dhcp/dhclient-exit-hooks.d',
    '/etc/dkms',
    '/etc/flatpak/remotes.d',
    '/etc/gdm',
    '/etc/gdm3',
    '/etc/gdm3/Init',
    '/etc/gdm3/PostLogin',
    '/etc/gdm3/PostSession',
    '/etc/gdm3/PreSession',
    '/etc/gdm3/Prime',
    '/etc/gdm3/PrimeOff',
    '/etc/gdm/Init',
    '/etc/gdm/PostLogin',
    '/etc/gdm/PostSession',
    '/etc/gdm/PreSession',
    '/etc/grub.d',
    '/etc/httpd/modules',
    '/etc/ifplugd',
    '/etc/ifplugd/action.d',
    '/etc/init.d',
    '/etc/kernel/header_postinst.d',
    '/etc/kernel/install.d',
    '/etc/kernel/postinst.d',
    '/etc/kernel/postrm.d',
    '/etc/kernel/preinst.d',
    '/etc/kernel/prerm.d',
    '/etc/lightdm',
    '/etc/mcelog/triggers',
    '/etc/menu-methods',
    '/etc/network/if-down.d',
    '/etc/network/if-post-down.d',
    '/etc/network/if-pre-up.d',
    '/etc/network/if-up.d',
    '/etc/NetworkManager/dispatcher.d',
    '/etc/openvpn',
    '/etc/periodic/daily',
    '/etc/periodic/monthly',
    '/etc/periodic/weekly',
    '/etc/pinentry',
    '/etc/pm/sleep.d',
    '/etc/ppp',
    '/etc/ppp/ip-down.d',
    '/etc/ppp/ip-up.d',
    '/etc/ppp/ipv6-up.d',
    '/etc/profile.d',
    '/etc/qemu-ga',
    '/etc/rc0.d',
    '/etc/rc1.d',
    '/etc/rc2.d',
    '/etc/rc3.d',
    '/etc/rc4.d',
    '/etc/rc5.d',
    '/etc/rc6.d',
    '/etc/rc.d/init.d',
    '/etc/rc.d/rc0.d',
    '/etc/rc.d/rc1.d',
    '/etc/rc.d/rc2.d',
    '/etc/rc.d/rc3.d',
    '/etc/rc.d/rc4.d',
    '/etc/rc.d/rc5.d',
    '/etc/rc.d/rc6.d',
    '/etc/rcS.d',
    '/etc/rdnssd',
    '/etc/security',
    '/etc/skel',
    '/etc/ssl/certs',
    '/etc/ssl/misc',
    '/etc/ssl/trust-source',
    '/etc/systemd/system',
    '/etc/systemd/system/graphical.target.wants',
    '/etc/systemd/system-shutdown',
    '/etc/update-motd.d',
    '/etc/vmware-tools',
    '/etc/vpnc',
    '/etc/wpa_supplicant',
    '/etc/X11',
    '/etc/X11/xinit',
    '/etc/X11/xinit/xinitrc.d',
    '/etc/xdg/Xwayland-session.d',
    '/etc/zfs-fuse',
    '/etc/zfs/zed.d',
    '/etc/zfs/zpool.d'
  )
  AND file.path NOT IN (
    '/etc/nftables.conf',
    '/etc/rmt',
    '/etc/paths.d/100-rvictl',
    '/etc/profile',
    '/etc/qemu-ifdown',
    '/etc/qemu-ifup',
    '/etc/opt/chrome/native-messaging-hosts/com.google.endpoint_verification.api_helper.json'
  )
  -- Nix (on macOS) -- actually a symbolic link
  AND file.path NOT LIKE '/etc/profiles/per-user/%/bin/%'
