-- Retrieves the list of processes with explicit authorization for the Application Layer Firewall.
--
-- tags: postmortem
-- platform: darwin
SELECT
  *
FROM
  alf_explicit_auths;
