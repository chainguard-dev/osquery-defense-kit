-- Highlight potentially shady chrome extensions from documented spam authors
--
-- references:
--   * arstechnica.com/security/2025/01/googles-chrome-web-store-has-a-serious-spam-problem-promoting-shady-extensions
--
-- false positives:
--   * Legitimate extensions from the documented authors
--
-- tags: persistent seldom browser
SELECT
  name,
  profile,
  chrome_extensions.description AS 'descr',
  persistent AS persists,
  CONCAT (
    "https://chromewebstore.google.com/detail/extension/",
    identifier
  ) AS ext_url,
  author,
  chrome_extensions.path,
  referenced AS in_config,
  file.ctime,
  file.btime,
  file.mtime,
  from_webstore AS in_store,
  TRIM(CAST(permissions AS text)) AS perms,
  state AS 'enabled',
  CONCAT (
    from_webstore,
    ',',
    author,
    ',',
    name,
    ',',
    identifier
  ) AS exception_key,
  hash.sha256
FROM
  users
  CROSS JOIN chrome_extensions USING (uid)
  LEFT JOIN file ON chrome_extensions.path = file.path
  LEFT JOIN hash ON chrome_extensions.path = hash.path
WHERE
  state = 1
  AND (
    (
      author LIKE '%BigMData%'
      OR author LIKE '%BroCode LTD%'
      OR author LIKE '%Chrome Extension Hub%'
      OR author LIKE '%ExtensionsBox%'
      OR author LIKE '%Free Business Apps%'
      OR author LIKE '%Infwiz%'
      OR author LIKE '%Karbon Project LP%'
      OR author LIKE '%Kodice LLC%'
      OR author LIKE '%Lazytech%'
      OR author LIKE '%NioMaker%'
      OR author LIKE '%PDF Toolbox cluster%'
      OR author LIKE '%Yue Apps%'
      OR author LIKE '%ZingDeck%'
      OR author LIKE '%ZingFront Software%'
    )
  )
GROUP BY
  exception_key
