SELECT pof.pid,
    pof.path AS device,
    p.path AS program,
    p.name AS program_name,
    p.cmdline AS cmdline,
    hash.sha256,
    CONCAT(
        IIF(REGEX_MATCH(pof.path, "(/dev/.*)\d+$", 1) != "", REGEX_MATCH(pof.path, "(/dev/.*)\d+$", 1), pof.path),
        ",",
        REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, '/', '')), '')) AS path_exception,
    CONCAT(TRIM(REPLACE(pof.path, CONCAT('/', REPLACE(pof.path, RTRIM(pof.path, REPLACE(pof.path, '/', '')), '')) , '')), ",", REPLACE(p.path, RTRIM(p.path, REPLACE(p.path, '/', '')), '')) AS dir_exception
FROM process_open_files pof
    LEFT JOIN processes p ON pof.pid = p.pid
    LEFT JOIN hash ON hash.path = p.path
WHERE pof.path LIKE '/dev/%'
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
        '/dev/random',
        '/dev/rfkill',
        '/dev/snd/seq',
        '/dev/tty',
        '/dev/urandom',
        '/dev/vga_arbiter'
    )
    AND pof.path NOT LIKE "/dev/pts/%"
    AND pof.path NOT LIKE "/dev/snd/%"
    AND pof.path NOT LIKE "/dev/hidraw%"
    AND NOT dir_exception IN (
        '/dev/bus/usb,pcscd',
        '/dev/bus/usb/001,pcscd',
        '/dev/bus/usb/005,python3.10',
        '/dev/input,acpid',
        '/dev/input,gnome-shell',
        '/dev/input,systemd-logind',
        '/dev/input,systemd',
        '/dev/input,upowerd',
        '/dev/input,Xorg',
        '/dev/net,.tailscaled-wrapped',
        '/dev/net,tailscaled',
        '/dev/shm,1password',
        '/dev/shm,chrome',
        '/dev/shm,code',
        '/dev/shm,electron',
        '/dev/shm,firefox',
        '/dev/shm,gopls',
        '/dev/shm,java',
        '/dev/shm,jcef_helper',
        '/dev/shm,slack',
        '/dev/shm,spotify',
        '/dev/shm,steam',
        '/dev/shm,steamwebhelper',
        '/dev/shm,wine64-preloader',
        '/dev/shm,winedevice.exe',
        '/dev/snd,.pulseaudio-wrapped',
        '/dev/snd,alsactl',
        '/dev/snd,pipewire',
        '/dev/snd,pulseaudio',
        '/dev/snd,wireplumber'
    )

    AND NOT path_exception IN (
        '/dev/autofs,systemd',
        '/dev/hidraw,chrome',
        '/dev/input/event,Xorg',
        '/dev/kmsg,kubelet',
        '/dev/kmsg,systemd-journald',
        '/dev/kmsg,systemd',
        '/dev/tty,agetty',
        '/dev/tty,gdm-wayland-session',
        '/dev/tty,gdm-x-session',
        '/dev/tty,systemd-logind',
        '/dev/tty,Xorg',
        '/dev/uinput,bluetoothd',
        '/dev/video,chrome',
        '/dev/video,ffmpeg',
        '/dev/video,firefox',
        '/dev/video,obs-ffmpeg-mux',
        '/dev/video,obs',
        '/dev/video,vlc',
        '/dev/zfs,zed',
        "/dev/zfs,zfs"
    )
    -- shows up as python
    AND NOT (program_name IN ('streamdeck') AND device LIKE "/dev/bus/usb/%")
GROUP BY pof.pid