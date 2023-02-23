-- Retrieves all the gatekeeper exceptions on a macOS host
--
-- tags: postmortem
-- platform: darwin
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
GROUP BY
  gap.requirement
