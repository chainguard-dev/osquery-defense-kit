-- Return the list of mounts for Docker containers
--
-- tags: postmortem
-- platform: linux
SELECT
  *
FROM
  docker_container_mounts;
