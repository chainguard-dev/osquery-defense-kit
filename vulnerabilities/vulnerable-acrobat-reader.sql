-- Vulnerable version of Adobe Acrobat Reader is installed
--
-- References:
--   * https://helpx.adobe.com/security/products/acrobat/apsb23-34.html
--
-- tags: persistent state filesystem
-- platform: darwin
SELECT
  name,
  path,
  bundle_version,
  TRIM(REGEX_MATCH (bundle_version, "^(\d+)\.", 1)) AS major,
  TRIM(REGEX_MATCH (bundle_version, "\.(\d+)$", 1)) AS patch
FROM
  apps
WHERE
  name LIKE "%Acrobat%"
  AND (
    (
      major = "23"
      AND CAST(patch AS integer) < 20285
    )
    OR (
      major = "20"
      AND CAST(patch AS integer) < 30517
    )
  )
