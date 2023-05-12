-- Return the list of watched file events (must be configured)
--
-- tags: postmortem
-- platform: posix
-- interval: 900
SELECT *
FROM file_events
WHERE time > (strftime('%s', 'now') -900)