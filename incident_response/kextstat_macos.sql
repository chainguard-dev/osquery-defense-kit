-- Retrieves all the information about the current kernel extensions for the target OSX system.
--
-- tags: postmortem
-- platform: darwin
SELECT
  *
FROM
  kernel_extensions;
