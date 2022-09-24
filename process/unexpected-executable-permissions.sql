SELECT
  p.pid,
  p.name,
  p.path,
  f.mode,
  f.uid,
  f.gid,
  hash.sha256,
  pp.name AS parent_name,
  pp.path AS parent_path,
  pp.cmdline AS parent_cmd,
  hash.sha256 AS parent_sha256
FROM
  processes p
  JOIN file f ON p.path = f.path
  LEFT JOIN hash ON p.path = hash.path
  LEFT JOIN processes pp ON pp.pid = p.parent
WHERE
  f.mode NOT IN (
    '0500',
    '0544',
    '0555',
    '0711',
    '0755',
    '0775',
    '6755',
    '0700',
    '2755',
    '4511',
    '4555',
    '4755'
  )
  AND NOT (
    f.path = '/Library/Application Support/Logitech/com.logitech.vc.LogiVCCoreService/LogiVCCoreService.app/Contents/MacOS/LogiVCCoreService'
    AND f.mode = '0777'
    AND f.uid > 500
  )
