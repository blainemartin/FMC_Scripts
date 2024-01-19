#requires
import requests
import pandas as pd
import json
import getpass
import time

# Constants
USERNAME = input("Enter your username: ")
PASSWORD = getpass.getpass("Enter your password: ")
HOST = '10.0.0.0'
DOMAIN_UUID = 'Enter_UUID_of_Domain_Here'

# Ignore SSL warnings
requests.packages.urllib3.disable_warnings()

# Function to get X-auth-access-token
def get_auth_token():
    login_url = f"https://{HOST}/api/fmc_platform/v1/auth/generatetoken"
    response = requests.post(login_url, auth=requests.auth.HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
    return response.headers.get('X-auth-access-token')

# Function to get all access policies
def get_all_accesspolicies(x_auth_access_token):
    accesspolicies_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/policy/accesspolicies"
    headers = {'X-auth-access-token': x_auth_access_token}
    response = requests.get(accesspolicies_url, headers=headers, verify=False)
    return response.json().get('items', [])

# Function to get the most recently updated access policy
def get_most_recently_updated_policy(x_auth_access_token):
    accesspolicies = get_all_accesspolicies(x_auth_access_token)
    # Sort the policies by lastUpdatedTime in descending order
    sorted_policies = sorted(accesspolicies, key=lambda k: k.get('metadata', {}).get('lastUpdatedTime', ''), reverse=True)
    # Return the UUID of the most recently updated policy
    return sorted_policies[0]['id']

#Login to FMC & generate auth token
x_auth_access_token = get_auth_token() #Generate auth token
print(f"FMC Authentication Successful. API Token Generated.")

# Replace the user input for ACCESSPOLICY_UUID (deprecated) with the new function call
ACCESSPOLICY_UUID = get_most_recently_updated_policy(x_auth_access_token)

# Function to get accesspolicy
def get_accesspolicy(x_auth_access_token):
    accesspolicy_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/policy/accesspolicies/{ACCESSPOLICY_UUID}"
    headers = {'X-auth-access-token': x_auth_access_token}
    response = requests.get(accesspolicy_url, headers=headers, verify=False)
    return response.json()

# Function to get accessrules
def get_accessrules(x_auth_access_token, offset, limit):
    accessrules_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/policy/accesspolicies/{ACCESSPOLICY_UUID}/accessrules?offset={offset}&limit={limit}"
    headers = {'X-auth-access-token': x_auth_access_token}
    response = requests.get(accessrules_url, headers=headers, verify=False)
    return response.json().get('items', [])

# Function to get rule details
def get_rule_details(x_auth_access_token, rule_id):
    rule_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/policy/accesspolicies/{ACCESSPOLICY_UUID}/accessrules/{rule_id}"
    headers = {'X-auth-access-token': x_auth_access_token}
    response = requests.get(rule_url, headers=headers, verify=False)
    if response.status_code == 429:
        return None
    elif response.status_code != 200:
        print(f"Failed to retrieve details for rule {rule_id} due to an error. Error code: {response.status_code}")
        return None
    elif response.text:  # check if the response is not empty
        return response.json()
    else:
        print(f"Empty response for rule {rule_id}.")
        return None

# Function to process rule details
def process_rule_details(rule_details):
    name = rule_details.get('name', '')
    action = rule_details.get('action', '')
    enabled = rule_details.get('enabled', '')
    sourceZones = ', '.join([item.get('name', '') for item in rule_details.get('sourceZones', {}).get('objects', [])])
    sourceNetworks = ', '.join([item.get('name', '') for item in rule_details.get('sourceNetworks', {}).get('objects', [])])
    sourcePorts = ', '.join([item.get('name', '') for item in rule_details.get('sourcePorts', {}).get('objects', [])])
    destinationZones = ', '.join([item.get('name', '') for item in rule_details.get('destinationZones', {}).get('objects', [])])
    destinationNetworks = ', '.join([item.get('name', '') for item in rule_details.get('destinationNetworks', {}).get('objects', [])])
    destinationPorts = ', '.join([item.get('name', '') for item in rule_details.get('destinationPorts', {}).get('objects', [])])

    return [name, action, enabled, sourceZones, sourceNetworks, sourcePorts, destinationZones, destinationNetworks, destinationPorts]
    
# Function to get all network objects with pagination and backoff strategy
def get_all_network_objects(x_auth_access_token):
    offset = 0
    limit = 25  # adjust this value based on how many objects you want to retrieve per request
    all_network_objects = []
    delay = 1  # initial delay
    max_delay = 120  # maximum delay

    while True:
        network_objects_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networks?offset={offset}&limit={limit}"
        headers = {'X-auth-access-token': x_auth_access_token}
        response = requests.get(network_objects_url, headers=headers, verify=False)
        if response.status_code == 429:
            print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # double the delay, up to a maximum
            continue
        network_objects = response.json().get('items', [])
        if not network_objects:  # if no more objects, break the loop
            break
        all_network_objects.extend(network_objects)
        offset += limit  # update the offset for the next request
        delay = 1  # reset delay

    return all_network_objects

# Function to get all networkgroup objects with pagination and backoff strategy
def get_all_networkgroup_objects(x_auth_access_token):
    offset = 0
    limit = 25  # adjust this value based on how many objects you want to retrieve per request
    all_networkgroup_objects = []
    delay = 1  # initial delay
    max_delay = 120  # maximum delay

    while True:
        networkgroup_objects_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/networkgroups?offset={offset}&limit={limit}"
        headers = {'X-auth-access-token': x_auth_access_token}
        response = requests.get(networkgroup_objects_url, headers=headers, verify=False)
        if response.status_code == 429:
            print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # double the delay, up to a maximum
            continue
        networkgroup_objects = response.json().get('items', [])
        if not networkgroup_objects:  # if no more objects, break the loop
            break
        all_networkgroup_objects.extend(networkgroup_objects)
        offset += limit  # update the offset for the next request
        delay = 1  # reset delay

    return all_networkgroup_objects
    
# Function to get object details with backoff strategy
def get_object_details(x_auth_access_token, object_id, object_type):
    delay = 1  # initial delay
    max_delay = 120  # maximum delay

    while True:
        object_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/{object_type}/{object_id}"
        headers = {'X-auth-access-token': x_auth_access_token}
        response = requests.get(object_url, headers=headers, verify=False)
        if response.status_code == 429:
            print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # double the delay, up to a maximum
            continue
        elif response.status_code != 200:
            print(f"Failed to retrieve details for {object_type} {object_id} due to an error. Error code: {response.status_code}")
            return None
        elif response.text:  # check if the response is not empty
            return response.json()
        else:
            print(f"Empty response for {object_type} {object_id}.")
            return None

# Function to process network or networkgroup details
def process_network_details(network_details):
    type = network_details.get('type', '')
    name = network_details.get('name', '')
    id = network_details.get('id', '')
    if type == 'Network':
        value = network_details.get('value', '')
    elif type == 'NetworkGroup':
        value = ', '.join([obj.get('name', '') for obj in network_details.get('objects', [])])
    output = [type, name, value, id]
    return output
    
# Function to get all port objects with pagination and backoff strategy
def get_all_port_objects(x_auth_access_token):
    offset = 0
    limit = 25  # adjust this value based on how many objects you want to retrieve per request
    all_port_objects = []
    delay = 1  # initial delay
    max_delay = 120  # maximum delay

    while True:
        port_objects_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/ports?offset={offset}&limit={limit}"
        headers = {'X-auth-access-token': x_auth_access_token}
        response = requests.get(port_objects_url, headers=headers, verify=False)
        if response.status_code == 429:
            print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # double the delay, up to a maximum
            continue
        port_objects = response.json().get('items', [])
        if not port_objects:  # if no more objects, break the loop
            break
        all_port_objects.extend(port_objects)
        offset += limit  # update the offset for the next request
        delay = 1  # reset delay

    return all_port_objects

# Function to get all portgroup objects with pagination and backoff strategy
def get_all_portgroup_objects(x_auth_access_token):
    offset = 0
    limit = 25  # adjust this value based on how many objects you want to retrieve per request
    all_portgroup_objects = []
    delay = 1  # initial delay
    max_delay = 120  # maximum delay

    while True:
        portgroup_objects_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/portobjectgroups?offset={offset}&limit={limit}"
        headers = {'X-auth-access-token': x_auth_access_token}
        response = requests.get(portgroup_objects_url, headers=headers, verify=False)
        if response.status_code == 429:
            print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # double the delay, up to a maximum
            continue
        portgroup_objects = response.json().get('items', [])
        if not portgroup_objects:  # if no more objects, break the loop
            break
        all_portgroup_objects.extend(portgroup_objects)
        offset += limit  # update the offset for the next request
        delay = 1  # reset delay

    return all_portgroup_objects

# Function to process port details
def process_port_details(x_auth_access_token, port):
    type = port.get('type', '')
    name = port.get('name', '')
    id = port.get('id', '')
    
    delay = 1  # initial delay
    max_delay = 120  # maximum delay

    while True:
        # Make a separate call to get the port and protocol values
        port_object_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/protocolportobjects/{id}"
        headers = {'X-auth-access-token': x_auth_access_token}
        response = requests.get(port_object_url, headers=headers, verify=False)
        if response.status_code == 429:
            print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)
            delay = min(delay * 2, max_delay)  # double the delay, up to a maximum
            continue
        elif response.status_code == 404:
            print(f"Port object {id} not found. It might not be a port object.")
            return [type, name, '', '', id]  # return the basic details without the port and protocol values
        elif response.status_code != 200:
            print(f"Failed to retrieve details for port object {id}. This is expected for ICMP objects. Error code: {response.status_code}")
            return None
        port_object = response.json()
        port_value = port_object.get('port', '')
        protocol = port_object.get('protocol', '')
        break  # break the loop if the request is successful

    output = [type, name, port_value, protocol, id]
    return output
    
    # Make a separate call to get the port and protocol values
    port_object_url = f"https://{HOST}/api/fmc_config/v1/domain/{DOMAIN_UUID}/object/protocolportobjects/{id}"
    headers = {'X-auth-access-token': x_auth_access_token}
    response = requests.get(port_object_url, headers=headers, verify=False)
    if response.status_code != 200:
        print(f"Failed to retrieve details for port object {id} due to an error. Error code: {response.status_code}")
        return None
    port_object = response.json()
    port_value = port_object.get('port', '')
    protocol = port_object.get('protocol', '')
    
    output = [type, name, port_value, protocol, id]
    return output

# Function to process portgroup details
def process_portgroup_details(portgroup):
    type = portgroup.get('type', '')
    name = portgroup.get('name', '')
    id = portgroup.get('id', '')
    value = ', '.join([obj.get('name', '') for obj in portgroup.get('objects', [])])
    output = [type, name, value, id]
    return output

# Prepare data for DataFrame
data = []
data_networks = []
data_networkgroups = []
data_ports = []
data_portgroups = []

# Get all port objects
all_port_objects = get_all_port_objects(x_auth_access_token)
for port in all_port_objects:
    port_data = process_port_details(x_auth_access_token, port)
    if port_data:  # check if the response is successful
        data_ports.append(port_data)

print(f"All port objects retrieved.")

# Get all portgroup objects
all_portgroup_objects = get_all_portgroup_objects(x_auth_access_token)
for portgroup in all_portgroup_objects:
    portgroup_details = get_object_details(x_auth_access_token, portgroup['id'], 'portobjectgroups')
    if portgroup_details:
        portgroup_data = process_portgroup_details(portgroup_details)
        data_portgroups.append(portgroup_data)

print(f"All port object groups retrieved.")

# Get all network objects
all_network_objects = get_all_network_objects(x_auth_access_token)
data_networks = []
for network in all_network_objects:
    network_details = get_object_details(x_auth_access_token, network['id'], 'networks')
    if network_details:
        network_data = process_network_details(network_details)
        data_networks.append(network_data)

print(f"All network objects retrieved.")

# Get all networkgroup objects
all_networkgroup_objects = get_all_networkgroup_objects(x_auth_access_token)
data_networkgroups = []
for networkgroup in all_networkgroup_objects:
    networkgroup_details = get_object_details(x_auth_access_token, networkgroup['id'], 'networkgroups')
    if networkgroup_details:
        networkgroup_data = process_network_details(networkgroup_details)
        data_networkgroups.append(networkgroup_data)
        
print(f"All network object groups retrieved.")

# Get all access rule details with backoff strategy and pagination
offset = 0
limit = 25  # adjust this value based on how many rules you want to retrieve per request
delay = 1  # initial delay
max_delay = 120  # maximum delay

accesspolicy = get_accesspolicy(x_auth_access_token)

while True:
    accessrules = get_accessrules(x_auth_access_token, offset, limit)
    if not accessrules:  # if no more rules, break the loop
        break
        
    for rule in accessrules:
        rule_id = rule.get('id')
        for _ in range(8):  # retry up to 8 times
            rule_details = get_rule_details(x_auth_access_token, rule_id)
            if rule_details:  # check if the response is successful
                rule_data = process_rule_details(rule_details)  # move this line inside the if block
                data.append(rule_data)  # move this line inside the if block
                delay = 1  # reset delay
                break
            else:
                if delay < max_delay:  # only print the delay message if the delay is less than the maximum
                    print(f"Rate limit exceeded. Implementing backoff strategy with delay of {delay} seconds.")
            time.sleep(delay)  # wait before retrying
            delay = min(delay * 2, max_delay)  # increase delay, up to a maximum

    print(f"Retrieved {len(data)} rules so far...")  # print progress
    offset += limit  # update the offset for the next request
    time.sleep(1)  # add delay between requests
    
print(f"All access rules retrieved.")

# Create DataFrame
df = pd.DataFrame(data, columns=["name", "action", "enabled", "sourceZones", "sourceNetworks", "sourcePorts", "destinationZones", "destinationNetworks", "destinationPorts"])
df_networks = pd.DataFrame(data_networks, columns=["type", "name", "value", "id"])
df_networkgroups = pd.DataFrame(data_networkgroups, columns=["type", "name", "value", "id"])
df_ports = pd.DataFrame(data_ports, columns=["type", "name", "port", "protocol", "id"])
df_portgroups = pd.DataFrame(data_portgroups, columns=["type", "name", "value", "id"])

# Write DataFrame to Excel file
with pd.ExcelWriter('FMC_Rules_Networks_Ports_Export.xlsx') as writer:
    df.to_excel(writer, sheet_name='Access Rules', index=False)
    df_networks.to_excel(writer, sheet_name='Networks', index=False)
    df_networkgroups.to_excel(writer, sheet_name='Network Groups', index=False)
    df_ports.to_excel(writer, sheet_name='Ports', index=False)
    df_portgroups.to_excel(writer, sheet_name='Port Groups', index=False)

print("The script has finished running. You can find the resulting Excel file in the same directory as this script, named 'FMC_Rules_Networks_Ports_Export.xlsx'.")