-- Retrieves launchd override keys per user
--
-- tags: postmortem
-- platform: darwin
SELECT
  *
FROM
  launchd_overrides;
