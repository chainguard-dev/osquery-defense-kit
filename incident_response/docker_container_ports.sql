-- Return the list of ports for Docker containers
--
-- tags: postmortem
-- platform: linux
SELECT
  *
FROM
  docker_container_ports;
