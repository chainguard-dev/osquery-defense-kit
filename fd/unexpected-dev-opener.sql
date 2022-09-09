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
        '/dev/urandom',
        '/dev/vga_arbiter',
        '/dev/tty'
    )
AND NOT pof.path LIKE '/dev/ttys%'
AND NOT pof.path LIKE '/dev/pts/%'
AND NOT pof.path LIKE '/dev/snd/pcm%'
AND NOT pof.path LIKE '/dev/snd/control%'
AND NOT pof.path LIKE '/dev/shm/.com.google.%'
AND NOT pof.path LIKE '/dev/shm/.org.chromium.%'
AND NOT pof.path LIKE '/dev/shm/wayland.mozilla.%'
AND NOT (program LIKE '/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd' AND device='/dev/auditpipe')
AND NOT (program LIKE '/home/%/.local/share/Steam/%' AND device LIKE '/dev/shm/%')
AND NOT (program LIKE '/nix/store/%/bin/.tailscaled-wrapped' AND device='/dev/net/tun')
AND NOT (program LIKE '/nix/store/%/bin/agetty' AND device LIKE '/dev/tty%')
AND NOT (program LIKE '/nix/store/%/bin/Xorg' AND device LIKE '/dev/input/event%')
AND NOT (program LIKE '/nix/store/%/bin/Xorg' AND device LIKE '/dev/tty%')
AND NOT (program LIKE '/nix/store/%/bin/zed' AND device='/dev/zfs')
AND NOT (program LIKE '/nix/store/%/bin/zfs' AND device='/dev/zfs')
AND NOT (program LIKE '/nix/store/%/lib/systemd/systemd-journald' AND device='/dev/kmsg')
AND NOT (program LIKE '/nix/store/%/lib/systemd/systemd-logind' AND device LIKE '/dev/input/event%')
AND NOT (program LIKE '/nix/store/%/lib/systemd/systemd' AND device='/dev/kmsg')
AND NOT (program LIKE '/nix/store/%/lib/systemd/systemd-logind' AND device LIKE '/dev/tty%')
AND NOT (p.name='chrome' AND device LIKE '/dev/video%')
AND NOT (p.name='chrome' AND device LIKE '/dev/hidraw%')
AND NOT (p.name='firefox' AND device LIKE '/dev/shm/.%')
AND NOT (p.name='firefox' AND device LIKE '/dev/video%')
AND NOT (p.name='obs' AND device LIKE '/dev/video%')
AND NOT (program='/sbin/launchd' AND device='/dev/console')
AND NOT (program='/System/Library/Frameworks/GSS.framework/Helpers/GSSCred' AND device='/dev/auditsessions')
AND NOT (program='/System/Library/Frameworks/Security.framework/Versions/A/XPCServices/authd.xpc/Contents/MacOS/authd' AND device='/dev/auditsessions')
AND NOT (program='/System/Library/PrivateFrameworks/GenerationalStorage.framework/Versions/A/Support/revisiond' AND device LIKE '/dev/afsc_type%')
AND NOT (program='/usr/bin/apcupsd' AND device LIKE '/dev/usb/hiddev%')
AND NOT (program='/usr/bin/bash' AND device LIKE '/dev/shm/%')
AND NOT (program='/usr/bin/cat' AND device LIKE '/dev/shm/%')
AND NOT (program='/usr/bin/ffmpeg' AND device='/dev/nvidia-uvm')
AND NOT (program='/usr/bin/ffmpeg' AND device LIKE '/dev/video%')
AND NOT (program='/usr/sbin/netbiosd' AND device LIKE '/dev/nsmb%')
AND NOT (program='/usr/bin/gnome-calendar' AND device='/dev/nvidiactl')
AND NOT (program='/usr/bin/gnome-shell' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/bin/gphoto2' AND device LIKE '/dev/bus/usb/%')
AND NOT (program='/usr/bin/kubelet' AND device='/dev/kmsg')
AND NOT (program='/usr/bin/pipewire' AND device LIKE '/dev/snd/%')
AND NOT (program='/usr/bin/tailscaled' AND device='/dev/net/tun')
AND NOT (program='/usr/lib/gdm-x-session' AND device='/dev/tty2')
AND NOT (program='/usr/lib/systemd/systemd-journald' AND device='/dev/kmsg')
AND NOT (program='/usr/lib/systemd/systemd-logind' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/lib/systemd/systemd-logind' AND device LIKE '/dev/tty%')
AND NOT (program='/usr/lib/systemd/systemd' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/lib/systemd/systemd' AND device='/dev/autofs')
AND NOT (program='/usr/lib/systemd/systemd' AND device='/dev/kmsg')
AND NOT (program='/usr/lib/upowerd' AND device LIKE '/dev/usb/hiddev%')
AND NOT (program='/usr/lib/upowerd' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/lib/Xorg' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/lib/Xorg' AND device LIKE '/dev/tty%')
AND NOT (program='/usr/lib/xorg/Xorg' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/lib/xorg/Xorg' AND device LIKE '/dev/tty%')
AND NOT (program='/usr/libexec/airportd' AND device LIKE '/dev/bpf%')
AND NOT (program='/usr/libexec/airportd' AND device='/dev/io8logmt')
AND NOT (program='/usr/libexec/automountd' AND device='/dev/autofs')
AND NOT (program='/usr/libexec/gdm-wayland-session' AND device LIKE '/dev/tty%')
AND NOT (program='/usr/libexec/gdm-x-session' AND device LIKE '/dev/tty%')
AND NOT (program='/usr/libexec/kernelmanagerd' AND device='/dev/console')
AND NOT (program='/usr/libexec/logd' AND device='/dev/oslog')
AND NOT (program='/usr/libexec/PerfPowerServices' AND device='/dev/xcpm')
AND NOT (program='/usr/libexec/thermald' AND device='/dev/xcpm')
AND NOT (program='/usr/libexec/TouchBarServer' AND device='/dev/auditsessions')
AND NOT (program='/usr/libexec/upowerd' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/libexec/upowerd' AND device='/dev/input/event%')
AND NOT (program='/usr/libexec/Xorg' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/libexec/Xorg' AND device LIKE '/dev/tty%')
AND NOT (program='/usr/local/kolide-k2/bin/osqueryd-updates/%/osqueryd' AND device='/dev/auditpipe')
AND NOT (program='/usr/sbin/acpid' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/sbin/bluetoothd' AND device='/dev/cu.BLTH')
AND NOT (program='/usr/sbin/mcelog' AND device='/dev/mcelog')
AND NOT (program='/usr/sbin/pcscd' AND device LIKE '/dev/bus/usb/%')
AND NOT (program='/usr/sbin/securityd' AND device='/dev/auditsessions')
AND NOT (program='/usr/sbin/syslogd' AND device='/dev/klog')
AND NOT (program='/usr/sbin/systemstats' AND device='/dev/xcpm')
AND NOT (program='/usr/sbin/tailscaled' AND device='/dev/net/tun')
AND NOT (program='/usr/sbin/thermald' AND device LIKE '/dev/input/event%')
AND NOT (program='/usr/sbin/zed' AND device='/dev/zfs')
AND NOT (cmdline LIKE "%/bin/streamdeck" AND device LIKE '/dev/bus/usb/%')