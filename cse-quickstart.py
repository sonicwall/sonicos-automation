# Imports
import json
import time
from os import listdir, path, mkdir
from getpass import getpass
from common.banner import print_banner
from common.utils import (
    generate_timestamp,
    tprint,
    write_to_file,
)
from common.arguments import get_parser
from sonicos.api import (
    logout,
    enable_sonicos_api_ssh,
    disable_sonicos_api_ssh,
)
from sonicos.firewall import Firewall
import common.constants as constants
from rich import print

# Argument parser
arg_description = """Quickstart for SonicWall Cloud Secure Edge.
This tool automates the task of enabling and configuring the CSE connector in SonicOS.
Please refer to the README for more detailed help."""
args = get_parser(arg_set="cse-quickstart", description=arg_description, parse=False)
args.add_argument("-i", "--interface", type=str, help="Provide a comma-separated list of interfaces. Ex: 'X0,X2,X3'. If enabled, this argument configures the CSE connector with the specified interface subnets (e.g. X0, X2, X23). By default, only 'X0 Subnet' is added to the 'Default CSE Allowed CIDRs' group.")
args.add_argument("-s", "--sshport", type=str, default='22', help="If SonicOS API is disabled, the script will attempt to use SSH Management on port 22 to *temporarily* enable SonicOS API. Use this argument to specify a different SSH port. This has no effect if using a CSV file.")
a = args.parse_args()


# This function handles checking CSE status with retries.
def check_cse_status(firewall_object, retries=5):
    cse_init = False
    rcount = 0

    while not cse_init and rcount <= retries:
        print(f"{generate_timestamp()}: INFO: Checking Cloud Secure Edge status... {rcount + 1}/{retries}")
        cse_status = firewall_object.get_request("reporting/cloud-secure-edge")

        if cse_status.get("state", "") == "cse_initializing" or cse_status.get("state", "") == "cse_synchronizing":
            if rcount > retries:
                print(f"{generate_timestamp()}: ERROR: Cloud Secure Edge failed to initialize.")
                print(cse_status)
                return False

            status = f"{cse_status.get('state', '')} ({cse_status.get('error_message', '')})"
            print(f"{generate_timestamp()}: INFO: Cloud Secure Edge is {status}. Please wait...")
            rcount += 1
            time.sleep(10)
            continue

        elif cse_status.get("state", "") == "cse_initialized":
            status = f"{cse_status.get('state', '')} ({cse_status.get('error_message', '')})"
            print(f"{generate_timestamp()}: INFO: Cloud Secure Edge is {status}.")
            cse_init = True
            break

        else:
            print(cse_status)
            rcount += 1
            time.sleep(10)
            continue

    if cse_init:
        print(f"{generate_timestamp()}: INFO: Cloud Secure Edge initialized successfully.")
        return True
    else:
        return False


def routine(fw):
    # This resets the auto-enabled SonicOS API flag for each new firewall.
    if constants.get_autoenabled_sonicos_api() is True:
        constants.set_autoenabled_sonicos_api(False)

    logged_in = fw.login()
    if not logged_in:
        print(f"{generate_timestamp()}: ERROR: Could not log into the firewall.")
        return

    print()

    # Check if CSE is enabled. If not, enable it.
    cse_enabled = fw.get_request("cloud-secure-edge/base")
    if cse_enabled.get('cloud_secure_edge', {}).get("created") is True:
        print(f"{generate_timestamp()}: INFO: Cloud Secure Edge is already enabled.")

    elif cse_enabled.get('cloud_secure_edge', {}).get("created") is False:
        print(f"{generate_timestamp()}: INFO: Enabling Cloud Secure Edge...")

        data = {
            "cloud_secure_edge": {
                "created": True
            }
        }
        enabled_cse = fw.put_request("cloud-secure-edge/base", data=data)
        commit = fw.commit_pending()

        # Check if CSE is enabled.
        print(f"{generate_timestamp()}: INFO: Checking if Cloud Secure Edge is enabled...")
        cse_enabled = fw.get_request("cloud-secure-edge/base")
        if cse_enabled.get('cloud_secure_edge', {}).get("created") is False:
            print(f"{generate_timestamp()}: ERROR: Cloud Secure Edge failed to enable.")
            print(cse_enabled)
            return

        if cse_enabled.get('cloud_secure_edge', {}).get("created") is True:
            print(f"{generate_timestamp()}: INFO: Cloud Secure Edge enabled successfully.")

            cse_enabled = check_cse_status(fw)
            if not cse_enabled:
                return

    # Get CSE connector details.
    print(f"{generate_timestamp()}: INFO: Getting Cloud Secure Edge connector details...")
    cse_connector = fw.get_request("cloud-secure-edge/connectors")

    # Get the existing CSE address group members
    print(f"{generate_timestamp()}: INFO: Getting existing CSE address group members...")
    cse_address_group = cse_connector['cloud_secure_edge']['connector'][0]['allowed_ips']['address_group']
    group_members = fw.get_request(f"address-groups/ipv4/name/{cse_address_group}")
    members = group_members['address_groups'][0]['ipv4'].get('address_object', {}).get('ipv4', [])

    if len(members) == 0:
        # Configure CSE connector.
        if not a.interface:
            print(f"{generate_timestamp()}: INFO: No interfaces provided and there are no member objects in the '{cse_address_group}' address group. Adding default interface subnet: 'X0 Subnet'.")

            # Add the default 'X0 Subnet' to the address group.
            data = {
                'address_groups': [
                    {
                        'ipv4': {
                            'name': cse_address_group,
                            'address_object': {
                                'ipv4': [
                                    {'name': 'X0 Subnet'}
                                ]
                            }
                        }
                    }
                ]
            }
            fw.patch_request(f"address-groups/ipv4/name/{cse_address_group}", data=data)
            commit = fw.commit_pending()

        elif a.interface:
            print(f"{generate_timestamp()}: INFO: Adding interface subnets {a.interface} to the '{cse_address_group}' address group.")

            # Add the interface subnets to the address group.
            data = {
                'address_groups': [
                    {
                        'ipv4': {
                            'name': cse_address_group,
                            'address_object': {
                                'ipv4': [
                                    {'name': f"{i} Subnet"} for i in a.interface.split(",")
                                ]
                            }
                        }
                    }
                ]
            }
            fw.patch_request(f"address-groups/ipv4/name/{cse_address_group}", data=data)
            commit = fw.commit_pending()

    elif len(members) > 0:
        print(f"{generate_timestamp()}: INFO: The following objects are currently in the '{cse_address_group}' address group:")
        for member in members:
            print(member)
        print(f"{generate_timestamp()}: INFO: '{len(members)}' member(s) in the '{cse_address_group}' address group.")

        if a.interface:
            interfaces = a.interface.split(",")
            member_names = [m['name'] for m in members]
            interfaces_to_add = []
            for i in interfaces:
                if f"{i} Subnet" in member_names:
                    print(f"{generate_timestamp()}: INFO: The '{i}' interface subnet is already a member of the '{cse_address_group}' address group.")
                else:
                    print(f"{generate_timestamp()}: INFO: Adding interface '{i}' to the '{cse_address_group}' address group.")
                    interfaces_to_add.append(f"{i} Subnet")

            data = {
                'address_groups': [
                    {
                        'ipv4': {
                            'name': cse_address_group,
                            'address_object': {
                                'ipv4': [
                                    {'name': i} for i in interfaces_to_add
                                ]
                            }
                        }
                    }
                ]
            }
            fw.patch_request(f"address-groups/ipv4/name/{cse_address_group}", data=data)
            commit = fw.commit_pending()

    # Synchronize the CSE connector.
    sync_cse = fw.post_request("cloud-secure-edge/synchronize", data=None)
    if sync_cse.get("status", {}).get("success") is True:
        print(f"{generate_timestamp()}: INFO: CSE connector synchronized successfully.")
    else:
        print(f"{generate_timestamp()}: ERROR: CSE connector synchronization failed.")
        print(sync_cse)
        return

    # Check CSE status.
    cse_enabled = check_cse_status(fw)
    if cse_enabled:
        print(f"{generate_timestamp()}: INFO: CSE connector configured successfully.")
    else:
        print(f"{generate_timestamp()}: ERROR: Could not confirm CSE status. Please check it manually.")

    # At this point, the routine is complete. If the script auto-enabled SonicOS API, we need to disable it.
    if constants.get_autoenabled_sonicos_api():
        disable_sonicos_api_ssh(a.target, a.sshport, api_username, api_password)

    # Done with the routine.
    try:
        fw.logout()
    except KeyboardInterrupt:
        print(f"\n{generate_timestamp()}: INFO: Manually interrupted.")
        exit()
    except Exception as e:
        print(f"{generate_timestamp()}: ERROR: {e}")
        exit()


if __name__ == "__main__":
    banner_info = [
        "       --  Quickstart for SonicWall Cloud Secure Edge  --\n",
        "This tool automates the following tasks:",
        " - Enables Cloud Secure Edge and configures the CSE connector.",
        " - The -i/--interfaces argument allows you to provide a list of interfaces to add to the connector.",
        "   - The interfaces must be comma-separated, no spaces, as shown in the example below.",
        "   - Example: 'X0,X2,X4'",
        "Refer to the README for more detailed help.",
    ]
    print_banner(info=banner_info)

    api_username = None
    api_password = None
    try:
        while api_username is None or api_username == "":
            api_username = input(f"Enter the username for {a.target}: ")

        while api_password is None or api_password == "":
            api_password = getpass(f"Enter the password for {api_username}@{a.target}: ")
    except KeyboardInterrupt:
        print(f"\n{generate_timestamp()}: INFO: Manually interrupted.")
        exit()

    if "https://" not in a.target.lower() and "http://" not in a.target.lower():
        a.target = "https://" + a.target

    fw = Firewall(url=a.target,
                  username=api_username,
                  password=api_password,
                  sshport=a.sshport)

    routine(fw)
