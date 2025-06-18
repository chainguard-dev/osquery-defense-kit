-- Find programs processes which link against libcurl, common among cross-platform malware
--
-- References:
--  * https://objective-see.org/blog/blog_0x6C.html
--  * https://objective-see.org/blog/blog_0x72.html
--
-- platform: linux
-- tags: persistent state process seldom
SELECT
  CONCAT (
    p0.name,
    ',',
    REPLACE(
      p0.path,
      COALESCE(
        REGEX_MATCH (p0.path, "/nix/store/(.*?)/.*", 1),
        REGEX_MATCH (p0.path, "(\d[\.\d]+)/.*", 1),
        "3.11"
      ),
      "__VERSION__"
    ),
    ',',
    p0.euid,
    ',',
    CONCAT (
      SPLIT (p0.cgroup_path, "/", 0),
      ",",
      SPLIT (p0.cgroup_path, "/", 1)
    ),
    ',',
    f.mode
  ) AS exception_key,
  pmm.path AS library_path,
  -- Child
  p0.pid AS p0_pid,
  p0.start_time AS p0_start,
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
  p1.start_time AS p1_start,
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
  JOIN process_memory_map pmm ON p0.pid = pmm.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  p0.euid = 0
  AND pmm.path LIKE '%libcurl%'
  AND NOT exception_key IN (
    '0,0,/var/run/ublue-update.lock,regular,0755',
    'accounts-daemon,/usr/libexec/accounts-daemon,0,system.slice,accounts-daemon.service,0755',
    'apache2,/usr/sbin/apache2,0,system.slice,apache2.service,0755',
    'boltd,/usr/libexec/boltd,0,system.slice,bolt.service,0755',
    'osqueryd,/usr/local/kolide-k2/bin/osqueryd,0,system.slice,launcher.kolide-k2.service,0755',
    'agentbeat,/opt/Elastic/Agent/data/elastic-agent-9.0.0-9786ac/components/agentbeat,0,system.slice,elastic-agent.service,0750',
    'elastic-endpoin,/opt/Elastic/Endpoint/elastic-endpoint,0,elasticendpoint,,0500',
    'bluetoothd,/usr/libexec/bluetooth/bluetoothd,0,system.slice,bluetooth.service,0755',
    'sudo,/usr/bin/sudo,0,system.slice,sshd.service,4755',
    'dnf,/usr/bin/python__VERSION__,0,system.slice,dnf-makecache.service,0755',
    'dnf,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'dnf-automatic,/usr/bin/python3.12,0,system.slice,dnf-automatic-install.service,0755',
    'dnf-automatic,/usr/bin/python__VERSION__,0,system.slice,dnf-automatic-install.service,0755',
    'firewalld,/usr/bin/python3.13,0,system.slice,firewalld.service,0755',
    'flatpak-system-,/usr/libexec/flatpak-system-helper,0,system.slice,flatpak-system-helper.service,0755',
    'fwupd,/usr/lib/fwupd/fwupd,0,system.slice,fwupd.service,0755',
    'fwupd,/usr/libexec/fwupd/fwupd,0,system.slice,fwupd.service,0755',
    'agentbeat,/opt/Elastic/Agent/data/elastic-agent-9.0.1-68f3ed/components/agentbeat,0,system.slice,elastic-agent.service,0750',
    'implicitclass,/usr/lib/cups/backend/implicitclass,0,system.slice,cups.service,0744',
    'sddm-helper,/usr/lib/x86_64-linux-gnu/sddm/sddm-helper,0,user.slice,user-1000.slice,0755',
    'libvirtd,/usr/bin/libvirtd,0,system.slice,libvirtd.service,0755',
    'libvirtd,/usr/sbin/libvirtd,0,system.slice,libvirtd.service,0755',
    'sshd-session,/usr/lib/ssh/sshd-session,0,system.slice,sshd.service,0755', -- nss_oslogin
    'ModemManager,/usr/sbin/ModemManager,0,system.slice,ModemManager.service,0755',
    'NetworkManager,/usr/bin/NetworkManager,0,system.slice,NetworkManager.service,0755',
    'NetworkManager,/usr/sbin/NetworkManager,0,system.slice,NetworkManager.service,0755',
    'nix-daemon,/nix/store/__VERSION__/bin/nix,0,system.slice,nix-daemon.service,0555',
    'ostree,/usr/bin/ostree,0,system.slice,ostree-finalize-staged-hold.service,0755',
    'packagekitd,/usr/libexec/packagekitd,0,system.slice,packagekit.service,0755',
    'pacman,/usr/bin/pacman,0,user.slice,user-1000.slice,0755',
    'realmd,/usr/libexec/realmd,0,system.slice,realmd.service,0755',
    'rpm-ostree,/usr/bin/rpm-ostree,0,system.slice,rpm-ostreed.service,0755',
    'rpm-ostree,/usr/bin/rpm-ostree,0,system.slice,ublue-update.service,0755',
    'sddm,/usr/bin/sddm,0,system.slice,sddm.service,0755',
    'sddm-helper,/usr/lib/sddm/sddm-helper,0,user.slice,user-1000.slice,0755',
    'sddm-helper,/usr/libexec/sddm-helper,0,user.slice,user-1000.slice,0755',
    'udisksd,/usr/libexec/udisks2/udisksd,0,system.slice,udisks2.service,0755',
    'virtlockd,/usr/sbin/virtlockd,0,system.slice,virtlockd.service,0755',
    'virtlogd,/usr/bin/virtlogd,0,system.slice,virtlogd.service,0755',
    'virtlogd,/usr/sbin/virtlogd,0,system.slice,virtlogd.service,0755',
    'virt-manager,/usr/bin/python3.12,0,user.slice,user-1000.slice,0755',
    'virtqemud,/usr/sbin/virtqemud,0,system.slice,virtqemud.service,0755',
    'yum,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'xdg-desktop-por,/usr/libexec/xdg-desktop-portal,0,user.slice,user-1000.slice,0755',
    'dnf,/usr/bin/dnf5,0,user.slice,user-0.slice,0755',
    'zed,/nix/store/__VERSION__/bin/zed,0,system.slice,zfs-zed.service,0555',
    'zfs,/nix/store/__VERSION__/bin/zfs,0,system.slice,zfs-snapshot-frequent.service,0555'
  )
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p0.pid
