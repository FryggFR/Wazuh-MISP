# MISP Integration
My version of the MISP integration that I've enhanced to have a more robust script and that supports sending logs from Stormshield Firewall.

**Warning**: The script is not finished yet, and may not work completely. 
It sometimes generates errors on the MISP response and on some MISP requests.

# How to install 🛠️
1. Copy the script in **/var/ossec/integrations**
2. Configure the script line 60 and 61 with your misp instance and api key:
```
misp_base_url = "https://YOUR-MISP-INSTANCE/attributes/restSearch/"
misp_api_auth_key = "YOUR-API-KEY"
```
3. Configure the permissions
```
chmod 750 custom-misp.py
```
```
chown root:wazuh custom-misp.py
```
4. Add this block to ossec.conf
```
<integration>
    <name>custom-misp.py</name>
    <group>sysmon_event1,sysmon_event3,sysmon_event6,sysmon_event7,sysmon_event_15,sysmon_event_22,syscheck,stormshield</group>
    <alert_format>json</alert_format>
</integration>
```
5. Copy the file **misp.xml** in **/var/ossec/etc/rules** and give him the right permissions.
6. Restart wazuh-manager

# Stormshield
You can use [this](https://github.com/FryggFR/Wazuh-Stormshield/tree/master) ruleset and decoders with this script.
The script will send a request to the MISP API with the destination ip.

# Know issues & Work in progress...

1) The script sends a duplicate alert to the Stormshield alerts, generating 2 lines in the Wazuh dashboard.
2) Sometimes, it send this error (*wazuh-integratord ERROR  While running custom-misp.py -> integrations. Output:*) in wazuh dashboard. But it still sends the request and still generates the alert in Wazuh.
