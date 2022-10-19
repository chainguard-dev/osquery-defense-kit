-- Retrieves all the information for the current kernel modules in the target Linux system.
--
-- tags: postmortem
-- platform: linux
SELECT
  *
FROM
  kernel_modules;
