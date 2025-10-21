import json
from getpass import getpass
from typing import Optional
from dataclasses import dataclass
from common.utils import generate_timestamp
from sonicos.utils import (
    ensure_admin_api_session,
)
from sonicos.api import (
    get_request,
    post_request,
    put_request,
    patch_request,
    commit_pending,
    logout,
    disable_sonicos_api_ssh,
    download_tsr,
    download_tracelog,
    export_preferences,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh,
    post_request_direct_cli,
)
from sonicos.api2 import Login
import common.constants as constants


@dataclass
class FirewallTarget:
    """Data class to represent a firewall target with all its configuration."""
    firewall: str
    username: Optional[str] = None
    password: Optional[str] = None
    sshport: str = '22'
    temp_password: str = ""
    randomize_temp_password: bool = False
    unbind_totp: bool = False
    force_password_change: bool = False
    export_tsr: bool = False
    export_settings: bool = False
    verbose: bool = False


def initialize_session(target: FirewallTarget, target_numbers: tuple, **kwargs):
    """Initialize API session with the firewall."""
    firewall = target.firewall
    username = kwargs.get('username', target.username)
    password = kwargs.get('password', target.password)
    sshport = kwargs.get('sshport', target.sshport)

    api_base = f"https://{firewall}" if "https://" not in firewall else firewall

    # Prompt for credentials if missing
    while username is None or username == "":
        username = input(f"Enter the username for {firewall}: ")

    while password is None or password == "":
        password = getpass(f"Enter the password for {username}@{firewall}: ")

    try:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Running session functions...")
        api_session, return_msg = ensure_admin_api_session(api_base, api_user=username, api_password=password, sshport=sshport)

        if api_session:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Session established with {api_base}.")
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Could not create session with {api_base}.")

        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Fetched session: {'yes' if api_session else 'no'} | {return_msg}")

        return api_session, return_msg, api_base, username, password

    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as err:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error creating admin session: {err}")
        return None, f"Error creating admin session: {err}", api_base, username, password


def gather_firewall_info(api_session, api_base: str, target_numbers: tuple, silent=False):
    """Gather firewall information including version, model, serial number, and HA status."""
    firewall_generation = None
    firmware_version = None
    device_model = None
    serial_number = None

    # Determine firewall generation and get basic info
    if isinstance(api_session, Login):
        try:
            info = api_session.get_firewall_info()
            if info.get('firmware_version', None):
                firmware_version = info['firmware_version']
                device_model = info['model']
                serial_number = info['serial_number']
                constants.set_fw_model(device_model)
                firewall_generation = 5
                constants.set_fw_generation(5)
        except KeyboardInterrupt:
            print(f"\nStopped!")
            exit()
        except Exception as err:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting version information: {err}")
            return None, f"Error getting version information: {err}"
    else:
        try:
            info = get_request(api_base, api_session, '/api/sonicos/version', silent=silent)

            if info.get('firmware_version', None):
                firmware_version = info['firmware_version'].split(' ')[-1]
                device_model = info['model']
                serial_number = info['serial_number'].replace("-", "")
                constants.set_fw_model(device_model)
                if firmware_version.startswith('7'):
                    firewall_generation = 7
                    constants.set_fw_generation(7)
                elif firmware_version.startswith('6'):
                    firewall_generation = 6
                    constants.set_fw_generation(6)
            else:
                raise Exception("Unable to determine the firmware version.")
        except KeyboardInterrupt:
            print(f"\nStopped!")
            exit()
        except Exception as err:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting version information: {err}")
            return None, f"Error getting version information: {err}"

    return {
        'firewall_generation': firewall_generation,
        'firmware_version': firmware_version,
        'device_model': device_model,
        'serial_number': serial_number,
    }, None


def get_local_users(api_session, api_base: str, firewall_generation: int, firewall: str, sshport: str, username: str, password: str, target_numbers: tuple, silent: bool = False):
    """Retrieve local users from the firewall.
    Arguments:
    api_session -- The established API session
    api_base -- The base URL of the firewall API
    firewall_generation -- The generation of the firewall (5, 6, or 7)
    firewall -- The firewall IP or hostname
    sshport -- The SSH port of the firewall
    username -- The username for authentication
    password -- The password for authentication
    target_numbers -- Tuple indicating the current target number and total targets
    silent -- If True, suppress output messages
    Returns:
    A dictionary containing local user information, or None if an error occurs.
    """
    users = None

    try:
        if firewall_generation == 7:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=silent)
        elif firewall_generation == 6:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=silent)
        elif firewall_generation == 5:
            users = get_users_ssh(firewall, sshport, username, password)

            if users:
                if not silent:
                    print(f"{generate_timestamp()}: Users retrieved from SSH.")
            else:
                if not silent:
                    print(f"{generate_timestamp()}: Error getting users from SSH.")
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as err:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting users from API: {err}")
        return None

    # Handle bytes response and JSON parsing for GEN6
    if isinstance(users, bytes):
        users = users.replace(b': expired', b': "expired"')
        users = json.loads(users.decode('utf-8'))

    # Validate users data
    if isinstance(users, dict):
        if users.get('user', {}).get('local', {}).get('user', None) is None:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: No local users found.")
            return None
    elif isinstance(users, bool):
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: Unable to get users.")
        return None

    return users
