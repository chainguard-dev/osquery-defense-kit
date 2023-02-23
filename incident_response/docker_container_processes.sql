-- Return the list of processes for Docker containers
--
-- tags: postmortem
-- platform: linux
SELECT docker_container_processes.*,
    docker_containers.name
FROM docker_containers
    JOIN docker_container_processes ON docker_containers.id = docker_container_processes.id;