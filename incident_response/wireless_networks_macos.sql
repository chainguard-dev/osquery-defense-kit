-- Retrieves all the remembered wireless network that the target machine has connected to.
SELECT
  ssid,
  network_name,
  security_type,
  last_connected,
  captive_portal,
  possibly_hidden,
  roaming,
  roaming_profile
FROM
  wifi_networks;
