-- Retrieves all the remembered wireless network that the target machine has connected to.
--
-- interval: 3600
-- platform: darwin
-- value: Identifies connections to rogue access points.
-- version: 1.6.0

select ssid, network_name, security_type, last_connected, captive_portal, possibly_hidden, roaming, roaming_profile from wifi_networks;
