-- Retrieves all the values for the loginwindow process in the target OSX system.
--
--
-- tags: postmortem
-- platform: darwin
select
  username,
  key,
  subkey,
  value
from
  plist p,
  (
    select
      *
    from
      users
    where
      directory like '/Users/%'
  ) u
where
  p.path = u.directory || '/Library/Preferences/com.apple.loginwindow.plist';
