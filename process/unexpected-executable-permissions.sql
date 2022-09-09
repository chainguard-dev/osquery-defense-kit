SELECT p.pid,
    p.name,
    p.path,
    f.mode,
    f.uid,
    f.gid
FROM processes p
    JOIN file f ON p.path = f.path
WHERE f.mode NOT IN (
    '0755',
    '4555',
    '0555',
    '0775',
    '0500',
    '4511',
    '0544',
)
AND NOT (f.path = '/opt/1Password/1Password-BrowserSupport' AND f.mode = '2755' AND uid>500)
AND NOT (f.path = '/Library/Application Support/Logitech/com.logitech.vc.LogiVCCoreService/LogiVCCoreService.app/Contents/MacOS/LogiVCCoreService' AND f.mode = '0777' AND uid>500)
AND NOT (f.path = '/usr/bin/fusermount3' AND f.mode='4755')
