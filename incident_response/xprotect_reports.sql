-- Returns a list of malware matches from macOS XProtect
--
-- tags: postmortem
-- platform: darwin
SELECT
  *
FROM
  xprotect_reports;
