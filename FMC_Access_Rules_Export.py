#requires
import requests
import pandas as pd
import json
import getpass
import time

# Constants
USERNAME = input("Enter your username: ")
PASSWORD = getpass.getpass("Enter your password: ")
HOST = 'IP_of_FMC'
DOMAIN_UUID = 'UUID_of_Relevant_FMC_Domain'

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

# Replace the user input for ACCESSPOLICY_UUID with the function call
x_auth_access_token = get_auth_token()
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
        print("Failure due to rate limiting. Implementing incrementing delay.")
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

    # Get source and destination details
    sourceZones = ', '.join([item.get('name', '') for item in rule_details.get('sourceZones', {}).get('objects', [])])
    sourceNetworks = ', '.join([item.get('name', '') for item in rule_details.get('sourceNetworks', {}).get('objects', [])])
    destinationZones = ', '.join([item.get('name', '') for item in rule_details.get('destinationZones', {}).get('objects', [])])
    destinationNetworks = ', '.join([item.get('name', '') for item in rule_details.get('destinationNetworks', {}).get('objects', [])])
    destinationPorts = ', '.join([item.get('name', '') for item in rule_details.get('destinationPorts', {}).get('objects', [])])

    return [name, action, enabled, sourceZones, sourceNetworks, destinationZones, destinationNetworks, destinationPorts]

# Prepare data for DataFrame
data = []

# Pagination
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
                delay = 1  # reset delay
                break
            else:
                if delay < max_delay:  # only print the delay message if the delay is less than the maximum
                    print(f"Implementing incrementing delay of {delay} seconds.")
        time.sleep(delay)  # wait before retrying
        delay = min(delay * 1, max_delay)  # increase delay, up to a maximum

        rule_data = process_rule_details(rule_details)
        data.append(rule_data)

    print(f"Retrieved {len(data)} rules so far...")  # print progress
    offset += limit  # update the offset for the next request
    time.sleep(1)  # add delay between requests

# Create DataFrame
df = pd.DataFrame(data, columns=["name", "action", "enabled", "sourceZones", "sourceNetworks", "destinationZones", "destinationNetworks", "destinationPorts"])

# Write DataFrame to Excel file
df.to_excel('accessrules.xlsx', index=False)

print("The script has finished running. You can find the resulting Excel file in the same directory as this script, named 'accessrules.xlsx'.")
