-- Returns a list of malware matches from macOS XProtect
--
-- tags: persistent often malware xprotect
-- platform: darwin
SELECT
  *
FROM
  xprotect_reports;
