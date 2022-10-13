-- Find launchd entries which purport to be by Apple, but are not signed by Apple.
--
-- Inspired by https://posts.specterops.io/hunting-for-bad-apples-part-1-22ef2b44c0aa
--
-- platform: darwin
select
  *
FROM
  signature s
  JOIN launchd d ON d.program_arguments = s.path
WHERE
  d.name LIKE 'com.apple.%'
  AND (
    signed = 0
    OR authority != 'Software Signing'
  )
  AND d.run_at_load = 1;