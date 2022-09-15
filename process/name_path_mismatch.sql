SELECT p.name,
    SUBSTR(SPLIT(p.name, ":./-", 0), 0, 8) AS short_name,
    SUBSTR(SPLIT(p.name, ":./-", 0), 0, 8) AS short_filename,
    f.filename,
    p.path,
    p.cmdline
FROM processes p
    JOIN file f ON p.path = f.path
WHERE short_filename != short_name
AND NOT (p.name='gnome-character' AND filename='gjs-console')
AND NOT (p.name='mysqld' AND filename='mariadbd')
AND NOT (p.name='systemd-udevd' AND filename='udevadm')
AND NOT (p.short_name = 'npm' AND filename='node')
AND NOT (p.name='GUI Thread' AND filename='resolve')
AND NOT (p.name='X' AND filename='Xorg')
AND NOT p.path LIKE '/nix/store/%/bin/bash'
AND NOT p.path LIKE '/usr/bin/python3%'
AND NOT filename IN (
    'bash',
    'chrome',
    'dash',
    'electron',
    'firefox',
    'ruby',
    'sh',
    'slack',
    'systemd',
    'busybox',
    'thunderbird'
)
