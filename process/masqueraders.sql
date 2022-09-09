SELECT p.name,
    f.filename,
    p.path,
    p.cmdline
FROM processes p
    JOIN file f ON p.path = f.path
WHERE SUBSTR(f.filename, 0, 8) != SUBSTR(p.name, 0, 8)
AND NOT (p.name='.firefox-wrappe' AND filename='firefox')
AND NOT (p.name='(sd-pam)' AND filename='systemd')
AND NOT (p.name='code-oss' AND filename='electron')
AND NOT (p.name='gjs' AND filename='gjs-console')
AND NOT (p.name='Isolated Web Co' AND filename='firefox')
AND NOT (p.name='mysqld' AND filename='mariadbd')
AND NOT (p.name='tmux:client' AND filename='tmux')
AND NOT (p.name='tmux:server' AND filename='tmux')
AND NOT (p.name='nix-daemon' AND filename='nix')
AND NOT (p.name='Privileged Cont' AND filename='firefox')
AND NOT (p.name='RDD Process' AND filename='firefox')
AND NOT (p.name='sh' AND filename='dash')
AND NOT (p.name='Socket Process' AND filename='firefox')
AND NOT (p.name='systemd-udevd' AND filename='udevadm')
AND NOT (p.name='update-notifier' AND filename='dash')
AND NOT (p.name='Utility Process' AND filename='firefox')
AND NOT (p.name='Web Content' AND filename='firefox')
AND NOT (p.name='Web Content' AND filename='thunderbird')
AND NOT (p.name='WebExtensions' AND filename='firefox')
AND NOT (p.name='X' AND filename='Xorg')
AND NOT p.path LIKE '/nix/store/%/bin/bash'
AND NOT p.path LIKE '/usr/bin/python3%'
AND NOT (p.name LIKE '%.sh' AND filename='dash')
