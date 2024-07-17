#!/var/ossec/framework/python/bin/python3
#
# MISP Integration, work with Wazuh 4.7.5.
# By Frygg
#
# This version can send Stormshield Event to MISP.
#
# Inspired by OpenSecure integration
# https://opensecure.medium.com/wazuh-and-misp-integration-242dfa2f2e19
#
# Work in progress.
#
import sys
import os
import json
import re
from socket import socket, AF_UNIX, SOCK_DGRAM
import requests
from requests.exceptions import ConnectionError
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
regex_file_hash = re.compile('\w{64}')

# Send alerte to Wazuh queue module.
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
socket_addr = '{0}/queue/sockets/queue'.format(pwd)
def send_event(msg, agent = None):
    print(f"Result: {msg}")
    if not agent or agent["id"] == "000":
        string = '1:misp:{0}'.format(json.dumps(msg))
    else:
        string = '1:[{0}] ({1}) {2}->misp:{3}'.format(agent["id"], agent["name"], agent["ip"] if "ip" in agent else "any", json.dumps(msg))
    sock = socket(AF_UNIX, SOCK_DGRAM)
    sock.connect(socket_addr)
    sock.send(string.encode())
    sock.close()

# Reading alerte file.
try:
    alert_file_path = sys.argv[1]
except IndexError:
    print("Manual usage: python custom-misp.py <alert_file_path>")
    sys.exit(1)

try:
    with open(alert_file_path, encoding='latin-1') as alert_file:
        alert_content = alert_file.read()
        if not alert_content:
            print("Error: Alert file is empty.")
            sys.exit(1)
        alert = json.loads(alert_content)
except FileNotFoundError:
    print(f"Error: File '{alert_file_path}' not found.")
    sys.exit(1)
except json.decoder.JSONDecodeError as e:
    print(f"Error decoding JSON: {e}")
    sys.exit(1)

# MISP API
misp_base_url = "https://<MISP-INSTANCE>/attributes/restSearch/"
misp_api_auth_key = "<KEY>"
misp_apicall_headers = {"Content-Type": "application/json", "Authorization": f"{misp_api_auth_key}", "Accept": "application/json"}

# Extracting data from Wazuh alerte.
event_source = alert["rule"]["groups"][0]
event_type = alert["rule"]["groups"][2]
alert_output = {}

# Source: windows
if event_source == 'windows':
    print("Source: Windows")
    if event_type == 'sysmon_event1':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["win"]["eventdata"]["destinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event3' and alert_output["data"]["win"]["eventdata"]["destinationIsIpv6"] == 'true':
        sys.exit()
    elif event_type == 'sysmon_event6':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event7':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_15':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_22':
        try:
            wazuh_event_param = alert["data"]["win"]["eventdata"]["queryName"]
        except KeyError:
            sys.exit(1)
    elif event_type == 'sysmon_event_23':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_24':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    elif event_type == 'sysmon_event_25':
        try:
            wazuh_event_param = regex_file_hash.search(alert["data"]["win"]["eventdata"]["hashes"]).group(0)
        except IndexError:
            sys.exit()
    else:
        sys.exit()

    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    print("MISP URL:", misp_search_url)

    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        if (misp_api_response["response"]["Attribute"]):
            alert_output["misp"] = {}
            alert_output["misp"]["source"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            alert_output["misp"]["comment"] = misp_api_response["response"]["Attribute"][0]["comment"]
            alert_output["misp"]["source"]["description"] = alert["rule"]["description"]
            send_event(alert_output, alert["agent"])

# Source: Linux
elif event_source == 'linux':
    print("Source: Linux")
    if event_type == 'sysmon_event3' and alert["data"]["eventdata"]["destinationIsIpv6"] == 'false':
        try:
            dst_ip = alert["data"]["eventdata"]["DestinationIp"]
            if ipaddress.ip_address(dst_ip).is_global:
                wazuh_event_param = dst_ip
                misp_search_value = "value:"f"{wazuh_event_param}"
                misp_search_url = ''.join([misp_base_url, misp_search_value])
                print("MISP URL:", misp_search_url)
                try:
                    misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
                except ConnectionError:
                    alert_output["misp"] = {}
                    alert_output["integration"] = "misp"
                    alert_output["misp"]["error"] = 'Connection Error to MISP API'
                    send_event(alert_output, alert["agent"])
                else:
                    misp_api_response = misp_api_response.json()
                    if (misp_api_response["response"]["Attribute"]):
                        alert_output["misp"] = {}
                        alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
                        alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
                        alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
                        alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
                        alert_output["misp"]["comment"] = misp_api_response["response"]["Attribute"][0]["comment"]
                        send_event(alert_output, alert["agent"])
            else:
                sys.exit()
        except IndexError:
            sys.exit()
    else:
        sys.exit()

# Source: ossec
elif event_source == 'ossec':
    print("Source: ossec")
    if "sha256_after" in alert["syscheck"]:
        wazuh_event_param = alert["syscheck"]["sha256_after"]
    else:
        sys.exit()

    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    print("MISP URL:", misp_search_url)
    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
        if (misp_api_response["response"]["Attribute"]):
            alert_output["misp"] = {}
            alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
            alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
            alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
            alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
            alert_output["misp"]["comment"] = misp_api_response["response"]["Attribute"][0]["comment"]
            send_event(alert_output, alert["agent"])

# Stormshield events.
# => You need to add rules to the group "fw-pass-event"
elif event_source == 'stormshield':
    print("Source: Stormshield")
    if event_type == 'fw-pass-event':
        try:
            wazuh_event_param = alert["data"]["dst"]
        except IndexError:
            sys.exit()

    # Keep the possibility to add another event type.

    #elif event_type == 'fw-dns-event':
    #    try:
    #        wazuh_event_param = alert["data"]["dstname"]
    #    except IndexError:
    #        sys.exit()

    else:
        sys.exit()

    misp_search_value = "value:"f"{wazuh_event_param}"
    misp_search_url = ''.join([misp_base_url, misp_search_value])
    print("MISP URL:", misp_search_url)

    try:
        misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
    except ConnectionError:
        alert_output["misp"] = {}
        alert_output["integration"] = "misp"
        alert_output["misp"]["error"] = 'Connection Error to MISP API'
        send_event(alert_output, alert["agent"])
    else:
        misp_api_response = misp_api_response.json()
    if misp_api_response["response"]["Attribute"]:
        alert_output["misp"] = {}
        alert_output["misp"]["source"] = {}
        alert_output["misp"]["event_id"] = misp_api_response["response"]["Attribute"][0]["event_id"]
        alert_output["misp"]["category"] = misp_api_response["response"]["Attribute"][0]["category"]
        alert_output["misp"]["value"] = misp_api_response["response"]["Attribute"][0]["value"]
        alert_output["misp"]["type"] = misp_api_response["response"]["Attribute"][0]["type"]
        alert_output["misp"]["comment"] = misp_api_response["response"]["Attribute"][0]["comment"]
        alert_output["misp"]["source"]["description"] = alert["rule"]["description"]
        send_event(alert_output, alert["agent"])
    else:
        sys.exit(1)
else:
    sys.exit(1)

# MISP Search
misp_search_value = "value:"f"{wazuh_event_param}"
misp_search_url = f"{misp_base_url}{misp_search_value}"
#print("MISP URL:", misp_search_url)

try:
    misp_api_response = requests.get(misp_search_url, headers=misp_apicall_headers, verify=False)
except ConnectionError:
    print("Connection Error to MISP API")
    sys.exit(1)

# MISP Response
try:
    misp_api_response_json = misp_api_response.json()
except ValueError:
    sys.exit(1)

# If MISP response have valide value
if "Attribute" in misp_api_response_json.get("response", {}):
    attributes = misp_api_response_json["response"]["Attribute"]
    if attributes:
        alert_output = {
            "misp": {
                "source": {},
                "event_id": attributes[0]["event_id"],
                "category": attributes[0]["category"],
                "value": attributes[0]["value"],
                "type": attributes[0]["type"],
                "comment": attributes[0]["comment"]
            }
        }
        alert_output["misp"]["source"]["description"] = alert.get("rule", {}).get("description", "")
        send_event(alert_output, alert.get("agent"))
    else:
        sys.exit(1)
else:
    sys.exit(1)
