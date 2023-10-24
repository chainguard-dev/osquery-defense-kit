-- Detects unexpected programs opening files in /dev on Linux
--
-- references:
--   * https://attack.mitre.org/techniques/T1056/001/ (Input Capture: Keylogging)
--
-- false positives:
--   * any program which needs access to device drivers
--
-- platform: linux
-- tags: persistent state sniffer
SELECT
  pof.path AS device,
  CONCAT (
    IIF(
      REGEX_MATCH (
        TRIM(REPLACE(pof.path, ' (deleted)', '')),
        '(/dev/.*)[\d ]+$',
        1
      ) != '',
      REGEX_MATCH (
        TRIM(REPLACE(pof.path, ' (deleted)', '')),
        '(/dev/.*)[\d ]+$',
        1
      ),
      TRIM(REPLACE(pof.path, ' (deleted)', ''))
    ),
    ',',
    REPLACE(
      p0.path,
      RTRIM(p0.path, REPLACE(p0.path, '/', '')),
      ''
    )
  ) AS path_exception,
  CONCAT (
    TRIM(
      REPLACE(
        pof.path,
        CONCAT (
          '/',
          REPLACE(
            pof.path,
            RTRIM(pof.path, REPLACE(pof.path, '/', '')),
            ''
          )
        ),
        ''
      )
    ),
    ',',
    REPLACE(
      p0.path,
      RTRIM(p0.path, REPLACE(p0.path, '/', '')),
      ''
    )
  ) AS dir_exception,
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
  p1.name AS p1_name,
  p1_f.mode AS p1_mode,
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
  process_open_files pof
  LEFT JOIN processes p0 ON pof.pid = p0.pid
  LEFT JOIN hash p0_hash ON p0.path = p0_hash.path
  LEFT JOIN processes p1 ON p0.parent = p1.pid
  LEFT JOIN file p1_f ON p1.path = p1_f.path
  LEFT JOIN hash p1_hash ON p1.path = p1_hash.path
  LEFT JOIN processes p2 ON p1.parent = p2.pid
  LEFT JOIN hash p2_hash ON p2.path = p2_hash.path
WHERE
  pof.path LIKE '/dev/%'
  AND pof.path NOT IN (
    '/dev/dri/card0',
    '/dev/dri/card1',
    '/dev/dri/renderD128',
    '/dev/dri/renderD129',
    '/dev/fuse',
    '/dev/io8log',
    '/dev/io8logmt',
    '/dev/io8logtemp',
    '/dev/null',
    '/dev/nvidia-modeset',
    '/dev/nvidia-uvm',
    '/dev/nvidia0',
    '/dev/nvidiactl',
    '/dev/ptmx',
    '/dev/pts/ptmx',
    '/dev/shm/u1000-ValveIPCSharedObj-Steam',
    '/dev/random',
    '/dev/rfkill',
    '/dev/snd/seq',
    '/dev/urandom',
    '/dev/vga_arbiter',
    '/dev/video10' -- workaround for poor regex management (ffmpeg)
  )
  AND pof.path NOT LIKE '/dev/pts/%'
  AND pof.path NOT LIKE '/dev/snd/%'
  AND pof.path NOT LIKE '/dev/tty%'
  AND pof.path NOT LIKE '/dev/hidraw%'
  AND pof.path NOT LIKE '/dev/shm/.com.google.Chrome.%'
  AND pof.path NOT LIKE '/dev/shm/.org.chromium.Chromium.%'
  -- Zoom
  AND pof.path NOT LIKE '/dev/shm/aomshm.%'
  AND pof.path NOT LIKE '/dev/shm/authentik_%'
  AND NOT dir_exception IN (
    '/dev/bus/usb,pcscd',
    '/dev/input,acpid',
    '/dev/input,gnome-shell',
    '/dev/input,Hyprland',
    '/dev/input,systemd',
    '/dev/input,systemd-logind',
    '/dev/input,thermald',
    '/dev/input,upowerd',
    '/dev/input,Xorg',
    '/dev/net,tailscaled',
    '/dev/net,.tailscaled-wrapped',
    '/dev/net/tun,qemu-system-x86_64',
    '/dev/shm,1password',
    '/dev/shm,Brackets',
    '/dev/shm,chrome',
    '/dev/shm,code',
    '/dev/shm,electron',
    '/dev/shm,firefox',
    '/dev/shm,gameoverlayui',
    '/dev/shm,gopls',
    '/dev/shm,hl2_linux',
    '/dev/shm,Hyprland',
    '/dev/shm,java',
    '/dev/shm,jcef_helper',
    '/dev/shm,Melvor Idle',
    '/dev/shm,osqueryd',
    '/dev/shm,reaper',
    '/dev/shm,slack',
    '/dev/shm,spotify',
    '/dev/shm,steam',
    '/dev/shm,steamwebhelper',
    '/dev/shm,Tabletop Simulator.x86_64',
    '/dev/shm,wine64-preloader',
    '/dev/shm,winedevice.exe',
    '/dev/shm,xdg-desktop-portal-hyprland',
    '/dev/snd,alsactl',
    '/dev/snd,pipewire',
    '/dev/snd,pulseaudio',
    '/dev/snd,.pulseaudio-wrapped',
    '/dev/snd,wireplumber',
    '/dev/usb,apcupsd',
    '/dev/usb,upowerd'
  )
  AND NOT path_exception IN (
    '/dev/autofs,systemd',
    '/dev/cpu/0/msr,nvidia-powerd',
    '/dev/drm_dp_aux,fwupd',
    '/dev/fb,Xorg',
    '/dev/hidraw,chrome',
    '/dev/hwrng,rngd',
    '/dev/hvc,agetty',
    '/dev/input/event,thermald',
    '/dev/input/event,touchegg',
    '/dev/input/event,Xorg',
    '/dev/kmsg,bpfilter_umh',
    '/dev/kmsg,dmesg',
    '/dev/kmsg,k3s',
    '/dev/kmsg,kubelet',
    '/dev/kmsg,systemd',
    '/dev/kmsg,systemd-coredump',
    '/dev/kmsg,systemd-journald',
    '/dev/kvm,qemu-system-x86_64',
    '/dev/mapper/control,dockerd',
    '/dev/mapper/control,gpartedbin',
    '/dev/mapper/control,multipathd',
    '/dev/mcelog,mcelog',
    '/dev/media0,pipewire',
    '/dev/media0,wireplumber',
    '/dev/media,pipewire',
    '/dev/media,wireplumber',
    '/dev/net/tun,openvpn',
    '/dev/net/tun,qemu-system-x86_64',
    '/dev/net/tun,slirp4netns',
    '/dev/shm/envoy_shared_memory_1,envoy',
    '/dev/tpmrm,launcher',
    '/dev/tty,agetty',
    '/dev/tty,gdm-wayland-session',
    '/dev/tty,gdm-x-session',
    '/dev/tty,systemd-logind',
    '/dev/tty,Xorg',
    '/dev/uhid,bluetoothd',
    '/dev/uinput,bluetoothd',
    '/dev/usb/hiddev,apcupsd',
    '/dev/usb/hiddev,upowerd',
    '/dev/video0,chrome',
    '/dev/video,brave',
    '/dev/video,cheese',
    '/dev/video,chrome',
    '/dev/video,ffmpeg',
    '/dev/video,firefox',
    '/dev/video,guvcview',
    '/dev/video,obs',
    '/dev/video,obs-ffmpeg-mux',
    '/dev/video,pipewire',
    '/dev/video,signal-desktop',
    '/dev/video,slack',
    '/dev/video,vlc',
    '/dev/video,wireplumber',
    '/dev/video,zoom',
    '/dev/video,zoom.real',
    '/dev/zfs,',
    '/dev/zfs,zed',
    '/dev/zfs,zfs',
    '/dev/zfs,zpool'
  )
  -- Halflife
  AND path_exception NOT LIKE '/dev/shm/u1000-Shm_%,bash'
  -- lvmdbusd
  AND path_exception NOT LIKE '/dev/shm/pym-%python3.%'
  -- celery
  AND path_exception NOT LIKE '/dev/shm/pymp-%,python3.%'
  AND dir_exception NOT LIKE '/dev/shm/byobu-%/status.tmux,'
  AND NOT (
    pof.path LIKE '/dev/bus/usb/%'
    AND p0.name IN (
      'adb',
      'fprintd',
      'fwupd',
      'gphoto2',
      'gvfsd-gphoto2',
      'gvfsd-mtp',
      'gvfs-gphoto2-vo',
      'gvfs-gphoto2-volume-monitor',
      'pcscd',
      'streamdeck',
      'usbmuxd'
    )
  )
GROUP BY
  pof.pid
