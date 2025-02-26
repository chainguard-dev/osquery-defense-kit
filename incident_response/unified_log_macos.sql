-- Retrieves recent entries from the macOS unified log
--
-- tags: postmortem extra disabled
-- platform: darwin
-- interval: 1800
SELECT
  timestamp,
  pid,
  process,
  category,
  subsystem,
  message
FROM
  unified_log
WHERE
  timestamp > (strftime('%s', 'now') - 1800)
