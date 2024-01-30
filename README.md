# Wazuh-MISP
A new version of the MISP integration that I've enhanced to have a more robust script and that supports sending logs from Stormshield.

This script is easy to modify.

Work is in progress on this script. It's not finished yet!

## Install :
Add this config to your ossec.conf file (manager)
```
<integration>
    <name>custom-misp.py</name>
    <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck,stormshield</group>
    <alert_format>json</alert_format>
</integration>
```
