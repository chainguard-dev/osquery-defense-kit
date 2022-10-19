-- Return the list of running Docker containers on this machine
--
-- tags: postmortem
-- platform: linux
SELECT
  *
FROM
  docker_containers
