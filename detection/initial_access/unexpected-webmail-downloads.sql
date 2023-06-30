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
    'cer',
    'csv',
    'doc',
    'docx',
    'dwg',
    'eml',
    'eps',
    'gif',
    'htm',
    'html',
    'icloud',
    'jfif',
    'jpeg',
    'jpg',
    'key',
    'mov',
    'mp3',
    'mp4',
    'Dockerfile',
    'mpeg',
    'mpg',
    'ods',
    'odt',
    'pages',
    'pdf',
    'pem',
    'pgp',
    'png',
    'potx',
    'ppt',
    'pptx',
    'pub',
    'svg',
    'tif',
    'tiff',
    'txt',
    'yaml',
    'wav',
    'xls',
    'xlsm',
    'xlsx',
    'xml',
    'zip'
  )
