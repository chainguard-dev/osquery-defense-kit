-- Retrieves all the open sockets per process in the target system.
--
-- interval: 86400
-- platform: posix
-- value: Identify malware via connections to known bad IP addresses as well as odd local or remote port bindings
-- version: 1.4.5

select distinct pid, family, protocol, local_address, local_port, remote_address, remote_port, path from process_open_sockets where path <> '' or remote_address <> '';
