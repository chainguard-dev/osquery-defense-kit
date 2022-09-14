SELECT *
FROM docker_containers
WHERE privileged=1
AND image NOT LIKE "kindest/node:%";