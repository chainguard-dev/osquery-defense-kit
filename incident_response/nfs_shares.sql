-- Retrieves the current list of Network File System mounted shares.
--
-- interval: 3600
-- platform: darwin
-- value: Scope for lateral movement. Potential exfiltration locations. Potential dormant backdoors.
-- version: 1.4.5

select * from nfs_shares;
