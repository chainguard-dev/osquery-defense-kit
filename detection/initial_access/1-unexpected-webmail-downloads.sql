-- Surface webmail downloads of an unexpected sort
--
-- false positives:
--   * Files without an extension or extensions not explicitly added to the allow list
--
-- references:
--   * https://attack.mitre.org/techniques/T1566/001/ (Phishing: Spearphishing Attachment)
--
-- platform: darwin
-- tags: persistent filesystem spotlight
SELECT
  file.path,
  file.size,
  datetime(file.btime, 'unixepoch') AS file_created,
  magic.data,
  hash.sha256,
  s.authority,
  s.identifier,
  LOWER(
    REGEX_MATCH (RTRIM(file.path, '/'), '.*\.(.*?)$', 1)
  ) AS extension
FROM
  mdfind
  LEFT JOIN file ON mdfind.path = file.path
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN signature s ON file.path = s.path
WHERE
  mdfind.query = 'kMDItemWhereFroms == ''*https://mail.google.com/*'''
  AND file.btime > (strftime('%s', 'now') -86400)
  -- Extensions that would not normally raise suspicion if sent by e-mail (excludes dmg, iso, lnk, exe)
  AND extension NOT IN (
    'ai',
    'avi',
    'cer',
    'csv',
    'doc',
    'Dockerfile',
    'docx',
    'dwg',
    'eml',
    'eps',
    'gif',
    'heic',
    'htm',
    'html',
    'icloud',
    'itermexport',
    'jfif',
    'jpeg',
    'jpg',
    'json',
    'key',
    'loaded_0',
    'loaded_1',
    'md',
    'mov',
    'mp3',
    'mp4',
    'mpeg',
    'mpg',
    'msg',
    'numbers',
    'ods',
    'odt',
    'pages',
    'pdf',
    'pem',
    'pgp',
    'pkpass',
    'png',
    'potx',
    'ppt',
    'pptx',
    'pub',
    'rtf',
    'svg',
    'tf',
    'tif',
    'tiff',
    'txt',
    'wav',
    'webp',
    'xls',
    'xlsb',
    'xlsm',
    'xlsx',
    'xml',
    'yaml',
    'yml',
    'zip'
  )
  AND file.path NOT LIKE '%/Dockerfile'
GROUP BY
  file.path
