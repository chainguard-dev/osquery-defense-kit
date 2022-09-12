SELECT pof.pid,
    pof.path AS device,
    p.path AS program,
    p.name AS program_name,
    p.cmdline AS cmdline
FROM process_open_files pof
    JOIN processes p ON pof.pid = p.pid
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
    AND NOT pof.path LIKE '/dev/hidraw%'
    AND NOT pof.path LIKE '/dev/ttys%'
    AND NOT pof.path LIKE '/dev/pts/%'
    AND NOT pof.path LIKE '/dev/snd/pcm%'
    AND NOT pof.path LIKE '/dev/snd/control%'
    AND NOT pof.path LIKE '/dev/shm/.com.google.%'
    AND NOT pof.path LIKE '/dev/shm/.org.chromium.%'
    AND NOT pof.path LIKE '/dev/shm/wayland.mozilla.%'
    AND NOT (device LIKE '/dev/shm/.%' AND p.name = 'firefox')
    AND NOT (device LIKE "/dev/video%" AND p.name IN ('chrome', 'firefox', 'obs', 'ffmpeg', 'obs-ffmpeg-mux', 'ffmpeg-mux', 'vlc'))
    AND NOT (
        device LIKE '/dev/afsc_type%'
        AND program = '/System/Library/PrivateFrameworks/GenerationalStorage.framework/Versions/A/Support/revisiond'
    )
    AND NOT (
        device LIKE '/dev/bpf%'
        AND program IN ('/usr/libexec/airportd', '/usr/libexec/configd')
    )
    AND NOT (
        device LIKE '/dev/bus/usb/%'
        AND (program IN ('/usr/bin/gphoto2', '/usr/sbin/pcscd', '/usr/lib/gvfsd-mtp'))
        OR cmdline LIKE "%/bin/streamdeck"
    )
    AND NOT (
        device LIKE '/dev/input/event%'
        AND program LIKE '/nix/store/%/bin/Xorg'
    )
    AND NOT (
        device LIKE '/dev/input/event%'
        AND program LIKE '/nix/store/%/lib/systemd/systemd-logind'
    )
    AND NOT (
        device LIKE '/dev/input/event%'
        AND program IN (
            '/usr/bin/gnome-shell',
            '/usr/lib/systemd/systemd-logind',
            '/usr/lib/systemd/systemd',
            '/usr/lib/upowerd',
            '/usr/lib/Xorg',
            '/usr/lib/xorg/Xorg',
            '/usr/libexec/upowerd',
            '/usr/libexec/Xorg',
            '/usr/sbin/acpid',
            '/usr/sbin/thermald'
        )
    )
    AND NOT (
        device LIKE '/dev/nsmb%'
        AND program = '/usr/sbin/netbiosd'
    )
    AND NOT (
        device LIKE '/dev/shm/%'
        AND program LIKE '/home/%/.local/share/Steam/%'
    )
    AND NOT (
        device LIKE '/dev/snd/%'
        AND program = '/usr/bin/pipewire'
    )
    AND NOT (
        device LIKE '/dev/tty%'
        AND p.name IN (
            'systemd-logind',
            'Xorg',
            'gdm-wayland-session',
            'gdm-wayland-ses',
            'gdm-x-session',
            'X'
        )
    )
    AND NOT (
        device LIKE '/dev/usb/hiddev%'
        AND program IN ('/usr/bin/apcupsd', '/usr/lib/upowerd')
    )
    AND NOT (
        device = '/dev/auditpipe'
        AND program_name = 'osqueryd'
    )
    AND NOT (
        device = '/dev/auditsessions'
        AND program IN (
            '/System/Library/Frameworks/GSS.framework/Helpers/GSSCred',
            '/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/authd',
            '/usr/libexec/TouchBarServer',
            '/System/Library/PrivateFrameworks/Heimdal.framework/Helpers/kcm',
            '/usr/sbin/securityd'
        )
    )
    AND NOT (
        device = '/dev/autofs'
        AND program IN (
            '/usr/lib/systemd/systemd',
            '/usr/libexec/automountd'
        )
    )
    AND NOT (
        device = '/dev/console'
        AND program IN ('/sbin/launchd', '/usr/libexec/kernelmanagerd')
    )
    AND NOT (
        device = '/dev/cu.BLTH'
        AND program = '/usr/sbin/bluetoothd'
    )
    AND NOT (
        device = '/dev/input/event%'
        AND program = '/usr/libexec/upowerd'
    )
    AND NOT (
        device = '/dev/io8logmt'
        AND program = '/usr/libexec/airportd'
    )
    AND NOT (
        device = '/dev/klog'
        AND program = '/usr/sbin/syslogd'
    )
    AND NOT (
        device = '/dev/kmsg'
        AND p.name IN ('systemd-journald', 'systemd-journal', 'systemd', 'kubelet')
    )
    AND NOT (
        device = '/dev/mcelog'
        AND program = '/usr/sbin/mcelog'
    )
    AND NOT (
        device = '/dev/net/tun'
        AND p.name LIKE '%tailscaled%'
    )
    AND NOT (
        device = '/dev/oslog'
        AND program = '/usr/libexec/logd'
    )
    AND NOT (
        device = '/dev/uinput'
        AND program = '/usr/lib/bluetooth/bluetoothd'
    )
    AND NOT (
        device = '/dev/xcpm'
        AND program IN (
            '/usr/libexec/PerfPowerServices',
            '/usr/libexec/thermald',
            '/usr/sbin/systemstats'
        )
    )
    AND NOT (
        device = '/dev/zfs'
        AND p.name IN ('zed', 'zfs')
    )