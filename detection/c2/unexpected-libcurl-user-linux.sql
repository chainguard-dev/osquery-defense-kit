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
    'dnf-automatic,/usr/bin/python__VERSION__,0,system.slice,dnf-automatic-install.service,0755',
    'dnf,/usr/bin/python__VERSION__,0,system.slice,dnf-makecache.service,0755',
    'dnf,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'flatpak-system-,/usr/libexec/flatpak-system-helper,0,system.slice,flatpak-system-helper.service,0755',
    'fwupd,/usr/libexec/fwupd/fwupd,0,system.slice,fwupd.service,0755',
    'fwupd,/usr/lib/fwupd/fwupd,0,system.slice,fwupd.service,0755',
    'libvirtd,/usr/bin/libvirtd,0,system.slice,libvirtd.service,0755',
    'NetworkManager,/usr/bin/NetworkManager,0,system.slice,NetworkManager.service,0755',
    'NetworkManager,/usr/sbin/NetworkManager,0,system.slice,NetworkManager.service,0755',
    'nix-daemon,/nix/store/__VERSION__/bin/nix,0,system.slice,nix-daemon.service,0555',
    'packagekitd,/usr/libexec/packagekitd,0,system.slice,packagekit.service,0755',
    'pacman,/usr/bin/pacman,0,user.slice,user-1000.slice,0755',
    'sddm-helper,/usr/lib/sddm/sddm-helper,0,user.slice,user-1000.slice,0755',
    'sddm,/usr/bin/sddm,0,system.slice,sddm.service,0755',
    'virtlogd,/usr/bin/virtlogd,0,system.slice,virtlogd.service,0755',
    'virtqemud,/usr/sbin/virtqemud,0,system.slice,virtqemud.service,0755',
    'yum,/usr/bin/python__VERSION__,0,user.slice,user-1000.slice,0755',
    'zed,/nix/store/__VERSION__/bin/zed,0,system.slice,zfs-zed.service,0555',
    'zfs,/nix/store/__VERSION__/bin/zfs,0,system.slice,zfs-snapshot-frequent.service,0555'
  )
  AND NOT p0.cgroup_path LIKE '/system.slice/docker-%'
GROUP BY
  p0.pid
