-- Retrieves all the values for the loginwindow process in the target OSX system.
--
--
-- tags: postmortem
-- platform: darwin
select
  key,
  subkey,
  value
from
  plist
where
  path = '/Library/Preferences/loginwindow.plist';
