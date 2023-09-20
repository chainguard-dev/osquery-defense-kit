-- Gatekeeper exceptions are exceptions for downloaded binaries
--
-- references:
--   * https://posts.specterops.io/hunting-for-bad-apples-part-2-6f2d01b1f7d3
--
-- false positives:
--   * developers downloading binaries from Github
--
-- platform: darwin
-- tags: persistent filesystem state gatekeeper
SELECT
  gap.ctime,
  gap.mtime,
  gap.path,
  file.mtime,
  file.uid,
  file.ctime,
  file.gid,
  hash.sha256,
  signature.identifier,
  signature.authority
FROM
  gatekeeper_approved_apps AS gap
  LEFT JOIN file ON gap.path = file.path
  LEFT JOIN hash ON gap.path = hash.path
  LEFT JOIN signature ON gap.path = signature.path
WHERE
  gap.path NOT LIKE '/Users/%/bin/%'
  AND gap.path NOT LIKE '/Users/%/%-darwin-a%64'
  AND gap.path NOT LIKE '/Users/%/%_darwin_a%64%'
  AND gap.path NOT LIKE '/Users/%/Downloads/cosign'
  AND gap.path NOT LIKE '/Users/%/Downloads/missp'
  AND gap.path NOT LIKE '/Users/%/bom'
  AND gap.path NOT LIKE '/Users/%/configure'
  AND gap.path NOT LIKE '/Users/%/cosign-%'
  AND gap.path NOT LIKE '/Users/%/crane'
  AND gap.path NOT LIKE '/Users/%/rekor-cli'
  AND gap.path NOT LIKE '/Users/%/trivy'
  AND gap.path NOT LIKE '/usr/local/bin/%'
  AND signature.authority != 'Developer ID Application: Jamie Zawinski (4627ATJELP)'
GROUP BY
  gap.requirement
