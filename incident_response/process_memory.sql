-- Retrieves the memory map per process in the target Linux system.
--
-- interval: 86400
-- platform: linux
-- value: Ability to compare with known good. Identify mapped regions corresponding with or containing injected code.
-- version: 1.4.5

select * from process_memory_map;
