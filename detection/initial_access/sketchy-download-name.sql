-- Look for sketchy download files based on keywords
--
-- references:
--   - https://www.sentinelone.com/blog/macos-metastealer-new-family-of-obfuscated-go-infostealers-spread-in-targeted-attacks/
--
-- tags: persistent filesystem
-- platform: darwin
SELECT
  file.filename,
  REGEX_MATCH (file.filename, '.*\.(.*?)$', 1) AS extension,
  magic.data,
  hash.sha256,
  ea.value AS download_url,
  signature.authority AS s_auth,
  signature.identifier AS s_id
FROM
  file
  LEFT JOIN magic ON file.path = magic.path
  LEFT JOIN hash ON file.path = hash.path
  LEFT JOIN extended_attributes ea ON file.path = ea.path
  AND ea.key = "where_from"
  LEFT JOIN signature ON file.path = signature.path
WHERE
  file.path LIKE "/Users/%/Downloads/%"
  -- Frequently targetted extension for InfoStealer attacks
  AND extension IN ('dmg', 'exe', 'rar', 'pkg')
  AND (
    file.filename LIKE "%Adobe Photoshop%"
    OR file.filename LIKE "%.app%"
    OR file.filename LIKE "%Advertising%"
    OR file.filename LIKE "%agreement%"
    OR file.filename LIKE "%animated%"
    OR file.filename LIKE "%Brief%"
    OR file.filename LIKE "%confidentiality%"
    OR file.filename LIKE "%conract%"
    OR file.filename LIKE "%contract%"
    OR file.filename LIKE "%cover%"
    OR file.filename LIKE "%crack%"
    OR file.filename LIKE "%description%"
    OR file.filename LIKE "%Flash%"
    OR file.filename LIKE "%resume%"
    OR file.filename LIKE "cv%"
    OR file.filename LIKE "%cv"
    OR file.filename LIKE "%curriculum%"
    OR file.filename LIKE "%freyavr%"
    OR file.filename LIKE "%game%"
    OR file.filename LIKE "%immediate%"
    OR file.filename LIKE "%logos%"
    OR file.filename LIKE "%official%"
    OR file.filename LIKE "%pdf%"
    OR file.filename LIKE "%Player%"
    OR file.filename LIKE "%poster%"
    OR file.filename LIKE "%presentation%"
    OR file.filename LIKE "%receipt%"
    OR file.filename LIKE "%reference%"
    OR file.filename LIKE "%terms%"
    OR file.filename LIKE "%secret%"
    OR file.filename LIKE "%confidential%"
    OR file.filename LIKE "%trading%"
    OR file.filename LIKE "%Update%"
    OR file.filename LIKE "%weed%"
  )
  -- False positives
  AND NOT (
    file.filename LIKE "LogiPresentation%.dmg"
    OR file.filename LIKE "pdftk_server-%-win-setup.exe"
    OR file.filename LIKE "PioneerDriveUpdaterBDR%.dmg"
    OR file.filename LIKE "%MacVim%.dmg"
    OR file.filename LIKE 'PA Lottery Player Location Check%.dmg'
  )
