SELECT p.pid,
    p.name,
    p.path,
    f.mode
FROM processes p
    JOIN file f ON p.path = f.path
WHERE f.mode NOT LIKE '0%'
    AND f.path NOT IN (
        '/Library/DropboxHelperTools/Dropbox_u501/dbkextd',
        '/opt/1Password/1Password-BrowserSupport',
        '/opt/1Password/1Password-KeyringHelper',
        '/usr/bin/fusermount',
        '/usr/bin/fusermount3',
        '/usr/bin/login',
        '/usr/bin/sudo',
        '/usr/bin/doas',
        '/bin/ps',
        '/usr/bin/ssh-agent'
    );