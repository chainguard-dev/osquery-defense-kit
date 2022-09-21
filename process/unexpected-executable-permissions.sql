SELECT p.pid,
    p.name,
    p.path,
    f.mode,
    f.uid,
    f.gid,
    hash.sha256
FROM processes p
    JOIN file f ON p.path = f.path
    LEFT JOIN hash ON p.path = hash.path
WHERE f.mode NOT IN (
    '0500',
    '0544',
    '0555',
    '0711',
    '0755',
    '0775',
    '2755',
    '4511',
    '4555',
    '4755'
)
AND NOT (f.path = '/Library/Application Support/Logitech/com.logitech.vc.LogiVCCoreService/LogiVCCoreService.app/Contents/MacOS/LogiVCCoreService' AND f.mode = '0777' AND f.uid>500)
AND NOT (f.path = '/opt/1Password/1Password-KeyringHelper' AND f.mode='6755')
AND NOT (f.path = '/usr/bin/fusermount3' AND f.mode='4755')
AND NOT (f.path LIKE '/usr/libexec/cups/backend/%' AND f.mode='0700')
