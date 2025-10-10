# Imports
import json
import csv
import random
import string
from dataclasses import dataclass
from typing import Optional, List
from os import path, mkdir
from time import sleep
from getpass import getpass
from common.banner import print_banner
from common.utils import (
    generate_timestamp,
    write_to_file,
)
from common.arguments import get_parser
from sonicos.api import (
    get_request,
    post_request,
    put_request,
    patch_request,
    commit_pending,
    logout,
    enable_sonicos_api_ssh,
    disable_sonicos_api_ssh,
    check_botnet_status,
    check_totp_status,
    enable_totp_ssh,
    download_tsr,
    download_tracelog,
    export_preferences,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh,
)
from sonicos.utils import (
    ensure_admin_api_session,
)
import common.constants as constants
from sonicos.api2 import Login
try:
    from rich import print
    from rich.table import Table
    from rich.console import Console
    from rich.text import Text
except ImportError or ModuleNotFoundError:
    pass

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


def normalize_boolean(value: str) -> bool:
    """Convert string values to boolean."""
    if not value or value.lower() in ['none', 'false', '']:
        return False
    return value.lower() in ['true', 'yes', '1', 'y']


def normalize_password(password: str) -> str:
    """Normalize password, handling special comma encoding."""
    if not password or password == 'None':
        return ""
    return password.replace("<comma>", ",")


def normalize_temp_password(password: str, randomize: bool) -> str:
    """Normalize temporary password with minimum length and password complexity validation."""
    if randomize:
        password = create_random_password(length=12)
        return password

    if not password or password in ['None', 'false', '']:
        return ""

    # Make sure the password meets minimum complexity requirements.
    # Enforce minimum length of 12 characters
    if len(password) < 12:
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password too short, padding with 'x'")
        password += 'x' * (12 - len(password))

    # Make sure there is at least 1 uppercase character
    if not any(c.isupper() for c in password):
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password missing uppercase character, adding 'X'")
        password += 'X'

    # Make sure there is at least 1 lowercase character
    if not any(c.islower() for c in password):
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password missing lowercase character, adding 'x'")
        password += 'x'

    # Make sure there is at least 1 digit
    if not any(c.isdigit() for c in password):
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password missing digit, adding '1'")
        password += '1'

    # Replace any spaces with underscores
    if ' ' in password:
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password contains spaces, replacing with underscores")
        password = password.replace(' ', '_')

    # Replaces # with dashes to avoid errors setting password via API/CLI
    if '#' in password:
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password contains '#', replacing with dashes")
        password = password.replace('#', '-')

    # Replaces | with underscores to avoid errors setting password via API/CLI
    if '|' in password:
        if not a.silent:
            print(f"{generate_timestamp()}: Warning: Temporary password contains '|', replacing with underscores")
        password = password.replace('|', '_')

    # Make sure there is at least 1 special character
    special_characters = "!@$%^&*()-_=+[]{};:,.<>?/"
    if not any(c in special_characters for c in password):
        print(f"{generate_timestamp()}: Warning: Temporary password missing special character, adding '!'")
        password += '!'

    return password


def create_random_password(length: int = 12) -> str:
    """Generate a random password meeting complexity requirements. Minimum length is 12."""
    if length < 12:
        length = 12

    # Ensure the password contains at least one character from each category
    categories = {
        'uppercase': string.ascii_uppercase,
        'lowercase': string.ascii_lowercase,
        'digits': string.digits,
        'special': "!@$%^&*()-_=+[]{};:,.<>?/"
    }

    # Start with one character from each category
    password_chars = [
        random.choice(categories['uppercase']),
        random.choice(categories['lowercase']),
        random.choice(categories['digits']),
        random.choice(categories['special'])
    ]

    # Fill the rest of the password length with random choices from all categories
    all_chars = ''.join(categories.values())
    password_chars += random.choices(all_chars, k=length - len(password_chars))

    # Shuffle the resulting list to ensure randomness
    random.shuffle(password_chars)

    return ''.join(password_chars)


def parse_csv_targets(filepath: str) -> List[FirewallTarget]:
    """Parse CSV file and return list of FirewallTarget objects."""
    targets = []

    try:
        with open(filepath, 'r') as f:
            # Try to detect if there's a header by checking the first line
            first_line = f.readline().strip()
            f.seek(0)  # Reset file pointer

            # If first line contains header keywords, use DictReader
            if "target_fw" in first_line.lower() or "admin_user" in first_line.lower():
                reader = csv.DictReader(f)
                for row_num, row in enumerate(reader, start=2):  # Start at 2 since header is line 1
                    target = _parse_csv_row_dict(row, row_num)
                    if target:
                        targets.append(target)
            else:
                # No header, treat as raw CSV with expected column order
                reader = csv.reader(f)
                for row_num, row in enumerate(reader, start=1):
                    target = _parse_csv_row_list(row, row_num)
                    if target:
                        targets.append(target)

    except Exception as e:
        print(f"{generate_timestamp()}: Error opening/parsing CSV file: {e}")
        exit(1)

    return targets


def _parse_csv_row_dict(row: dict, row_num: int) -> Optional[FirewallTarget]:
    """Parse a CSV row when using DictReader (with headers)."""
    firewall = row.get('target_fw', '').strip()

    # Skip comments, empty rows, or invalid entries
    if not firewall or firewall.startswith('#'):
        return None

    if not row.get('admin_user'):
        print(f"{generate_timestamp()}: Warning: Row {row_num} missing admin_user, skipping")
        return None

    return FirewallTarget(
        firewall=firewall,
        username=row.get('admin_user', '').strip() or None,
        password=normalize_password(row.get('admin_password', '')),
        sshport=row.get('target_ssh_mgmt_port', '22').strip() or '22',
        temp_password=normalize_temp_password(password=row.get('temporary_password', ''),
                                              randomize=normalize_boolean(row.get('randomize_temp_password', 'false'))),
        randomize_temp_password=normalize_boolean(row.get('randomize_temp_password', '')),
        unbind_totp=normalize_boolean(row.get('unbind_totp', '')),
        force_password_change=normalize_boolean(row.get('force_password_change', ''))
    )


def _parse_csv_row_list(row: List[str], row_num: int) -> Optional[FirewallTarget]:
    """Parse a CSV row when using regular reader (no headers)."""
    if not row or len(row) == 0:
        return None

    # Skip comments
    if row[0].strip().startswith('#'):
        return None

    # Ensure we have at least firewall and username
    if len(row) < 2:
        print(f"{generate_timestamp()}: Warning: Row {row_num} has insufficient columns, skipping")
        return None

    # Pad row with empty strings if needed (backwards compatibility)
    while len(row) < 8:
        row.append('')

    firewall = row[0].strip()
    if not firewall:
        return None

    return FirewallTarget(
        firewall=firewall,
        username=row[1].strip() or None,
        password=normalize_password(row[2]),
        sshport=row[3].strip() or '22',
        temp_password=normalize_temp_password(password=row[4],
                                              randomize=normalize_boolean(row[7])),
        randomize_temp_password=normalize_boolean(row[7]),
        unbind_totp=normalize_boolean(row[5]),
        force_password_change=normalize_boolean(row[6])
    )


def load_targets(target_input: str) -> List[FirewallTarget]:
    """Load targets from either CSV file or single target."""
    if path.isfile(target_input):
        return parse_csv_targets(target_input)
    else:
        # Single target from command line
        return [FirewallTarget(
            firewall=target_input,
            sshport=a.sshport,
            temp_password=normalize_temp_password(password=a.temp_password,
                                                  randomize=normalize_boolean(a.randomize_password)),
            randomize_temp_password=normalize_boolean(a.randomize_password),
            unbind_totp=normalize_boolean(a.unbind_totp),
            force_password_change=normalize_boolean(a.force_password_change)
        )]


# Argument parsing
arg_description = """--- SonicWall Remediation Playbook / Essential Credential Reset Tool ---
This tool assists administrators by analyzing SonicOS configurations and producing a detailed report.
Refer to the README for more detailed help.\n"""
a = get_parser(arg_set="remediation", description=arg_description)


# This variable stores the results of the routine for each firewall.
routine_results = {}


# Helper Functions for Routine Breakdown
# =====================================

def update_routine_results(routine_results: dict, firewall: str, section: str, data: dict):
    """Centralized function to update routine results dictionary."""
    if firewall not in routine_results:
        routine_results[firewall] = {}

    if isinstance(data, dict):
        routine_results[firewall].update(data)
    else:
        routine_results[firewall][section] = data


def print_verbose_details(target: FirewallTarget, target_numbers: tuple, args, **kwargs):
    """Print verbose output details if verbose mode is enabled."""
    if not args.verbose:
        return

    firewall = target.firewall
    username = kwargs.get('username', target.username)
    password = kwargs.get('password', target.password)
    sshport = kwargs.get('sshport', target.sshport)
    temp_password = kwargs.get('temp_password', target.temp_password)
    randomize_temp_password = kwargs.get('randomize_temp_password', target.randomize_temp_password)
    unbind_totp = kwargs.get('unbind_totp', target.unbind_totp)
    force_password_change = kwargs.get('force_password_change', target.force_password_change)

    api_base = f"https://{firewall}" if "https://" not in firewall else firewall

    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: --- Routine Details ---")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Verbose output enabled.")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Firewall: {firewall}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Administrative username: {username}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Administrative password length: {len(password)}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: API Base URL: {api_base}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: SSH Management Port: {sshport}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Temporary Password for users: {temp_password}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Randomize Temporary Passwords: {randomize_temp_password}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unbind TOTP from all users: {unbind_totp}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Force password change for all local users: {force_password_change}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: ----------------------")


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
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error creating admin session: {e}")
        return None, f"Error creating admin session: {e}", api_base, username, password


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
        except Exception as e:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting version information: {e}")
            return None, f"Error getting version information: {e}"
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
        except Exception as e:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting version information: {e}")
            return None, f"Error getting version information: {e}"

    return {
        'firewall_generation': firewall_generation,
        'firmware_version': firmware_version,
        'device_model': device_model,
        'serial_number': serial_number,
    }, None


def export_tsr_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, silent=False):
    """Export TSR if enabled in arguments."""
    result = {'tsr_downloaded': False}

    if not args.export_tsr:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TSR download disabled.")
        return result

    if not silent:
        print(f"{generate_timestamp()}: Downloading TSR...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    tsr_file_name = f"{dm}-{sn}-tsr.wri"

    tsr_downloaded = download_tsr(api_base,
                                  api_session,
                                  filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tsr_file_name}",
                                  firewall_generation=firewall_info['firewall_generation'],
                                  silent=silent)

    if tsr_downloaded:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TSR downloaded to {tsr_file_name}")
        result['tsr_downloaded'] = True
        result['tsr_file_name'] = f"{constants.START_TIMESTAMP_FOLDER}/{tsr_file_name}"

    return result


def export_tracelogs_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, silent=False):
    """Export trace logs if enabled in arguments."""
    result = {'trace_logs_downloaded': False}

    if not args.export_tracelogs:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Trace log download disabled.")
        return result

    if not silent:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Downloading trace logs...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    tracelog_filename = f"{dm}-{sn}-tracelog-current.txt"

    trace_logs_downloaded = download_tracelog(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tracelog_filename}",
                                              log_selection="current",
                                              firewall_generation=firewall_info['firewall_generation'],
                                              silent=silent)

    if trace_logs_downloaded:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Trace logs downloaded.")
        result['trace_logs_downloaded'] = True
        result['tracelog_filename'] = f"{constants.START_TIMESTAMP_FOLDER}/{tracelog_filename}"

    return result


def export_settings_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, username: str, password: str, silent=False):
    """Export settings if enabled in arguments."""
    result = {'settings_exported': False}

    if not args.export_settings:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings export disabled.")
        return result

    if not silent:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Exporting settings...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    prefs_file_name = f"{dm}-{sn}-prefs.exp"

    prefs_downloaded = False
    firewall_generation = firewall_info['firewall_generation']

    if firewall_generation == 6:
        verbose_int = 1 if args.verbose else 0

        alternate_session = Login(
            ipaddress=api_base,
            userid=username,
            passwd=password,
            admin_mode="config",
            http_type="https",
            brwsr_cache=0,
            verbose=verbose_int,
            sessIdRef=0
        )

        logged_in, rmsg = alternate_session.login2()
        if logged_in == 1:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Successfully logged in to the firewall for settings export.")
            prefs_downloaded = export_preferences(api_base,
                                                  alternate_session,
                                                  filepath=f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}",
                                                  firewall_generation=firewall_generation,
                                                  silent=silent)
    else:
        # GEN5 and GEN7 use existing session
        prefs_downloaded = export_preferences(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}",
                                              firewall_generation=firewall_generation, silent=silent)

    if prefs_downloaded:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings exported.")
        result['settings_exported'] = True
        result['prefs_file_name'] = f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}"

    return result


def get_local_users(api_session, api_base: str, firewall_generation: int, firewall: str, sshport: str, username: str, password: str, target_numbers: tuple):
    """Retrieve local users from the firewall."""
    users = None

    try:
        if firewall_generation == 7:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=a.silent)
        elif firewall_generation == 6:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=a.silent)
        elif firewall_generation == 5:
            users = get_users_ssh(firewall, sshport, username, password)

            if users:
                if not a.silent:
                    print(f"{generate_timestamp()}: Users retrieved from SSH.")
            else:
                if not a.silent:
                    print(f"{generate_timestamp()}: Error getting users from SSH.")
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        if not a.silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting users from API: {e}")
        return None

    # Handle bytes response and JSON parsing for GEN6
    if isinstance(users, bytes):
        users = users.replace(b': expired', b': "expired"')
        users = json.loads(users.decode('utf-8'))

    # Validate users data
    if isinstance(users, dict):
        if users.get('user', {}).get('local', {}).get('user', None) is None:
            if not a.silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: No local users found.")
            return None
    elif isinstance(users, bool):
        if not a.silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: Unable to get users.")
        return None

    return users


def process_password_changes(users: dict, api_session, api_base: str, temp_password: str, randomize_temp_password: bool, firewall_generation: int,
                           firewall: str, sshport: str, username: str, password: str, target_numbers: tuple, args):
    """Process password changes for all eligible local users."""
    if not users:
        return []

    user_results = []
    users_list = users['user']['local']['user']

    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Updating the force password reset flag for all local users...")
    if temp_password != "" and not randomize_temp_password:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Passwords will be reset to '{temp_password}'. If the configured password did not meet complexity requirements, it was modified to include one of each character category (uppercase, lowercase, digit, special).")
    elif temp_password != "" and randomize_temp_password:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Passwords will be reset to a random password that includes at least one of each character category (uppercase, lowercase, digit, special).")

    # Create SSH session for GEN5 firewalls
    ssh_session = None
    ssh_connection = None
    if firewall_generation == 5:
        ssh_session, ssh_connection = get_ssh_session(firewall, sshport, username, password)
        if not ssh_session:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error creating SSH session.")
            return []

    for usr in users_list:
        # Skip special users
        skip_users = ['All LDAP Users', 'All RADIUS Users']
        if usr['name'] in skip_users:
            user_results.append({
                "name": usr['name'],
                "forced_password_change": False,
                "skipped": True,
                "reason": "Special user entry",
                "commit_successful": None
            })
            continue

        # Skip expired users
        if (usr.get('account_lifetime', {}).get('lifetime', "") == "expired" or
            usr.get('account_lifetime', {}).get('expired', False) is True):
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Skipping {usr['name']} (expired user)")
            user_results.append({
                "name": usr['name'],
                "forced_password_change": False,
                "skipped": True,
                "reason": "Expired user",
                "commit_successful": None
            })
            continue

        # Skip domain users based on generation
        if firewall_generation == 7 and usr.get('domain', None) is not None:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: GEN7: Skipping {usr['name']} (domain user)")
            user_results.append({
                "name": usr['name'],
                "forced_password_change": False,
                "skipped": True,
                "reason": "Domain user",
                "domain": usr.get('domain', ''),
                "commit_successful": None
            })
            if args.verbose:
                print(usr)
            continue

        if firewall_generation == 6 and usr.get('domain', {}).get('name', None) is not None:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: GEN6: Skipping {usr['name']} (domain user)")
            user_results.append({
                "name": usr['name'],
                "forced_password_change": False,
                "skipped": True,
                "reason": "Domain user",
                "domain": usr.get('domain', {}).get('name', ''),
                "commit_successful": None
            })
            if args.verbose:
                print(usr)
            continue

        # Process user password change
        usr['force_password_change'] = True

        # Update password if temporary password is set
        if temp_password != "":
            temp_password = create_random_password(length=12)
            if firewall_generation == 7:
                usr['password'] = temp_password
            elif firewall_generation == 6:
                usr['password']["pwd"] = temp_password
            elif firewall_generation == 5:
                usr['password'] = temp_password

        uname = usr['name']
        uuid = usr['uuid']

        routine_result_temp = {
            "name": usr['name'],
            "forced_password_change": True,
            "skipped": False,
            "reason": None,
            "user_update_successful": False,
            "commit_successful": False,
            "new_password": temp_password
        }

        if firewall_generation != 5:
            if not a.silent:
                # print(f"\nUpdating '{uname}'", end='')
                print(f"\nUpdating '{uname}'")
        else:
            if not a.silent:
                print(f"\nUpdating '{uname}'")

        # Create expected JSON structure
        data_structure = {
            "user": {
                "local": {
                    "user": [usr]
                }
            }
        }

        # Update the user based on generation
        update_resp = {'status': {'success': False}}
        if firewall_generation == 7:
            update_resp = patch_request(api_base, api_session,
                                      api_path=f"/api/sonicos/user/local/users/uuid/{uuid}",
                                      data=data_structure, silent=a.silent)
        elif firewall_generation == 6:
            update_resp = put_request(api_base, api_session,
                                    api_path=f"/api/sonicos/user/local/user/uuid/{uuid}",
                                    data=data_structure, silent=a.silent)
        elif firewall_generation == 5:
            update_resp = force_password_change_ssh(ssh_session, ssh_connection, data=usr)

        if update_resp['status']['success'] is False:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error updating user: {uname}")
            print(update_resp)
            print()
            # input("Press Enter to continue or CTRL+C to exit.")

        routine_result_temp['user_update_successful'] = True

        # Commit changes (GEN5 already committed via SSH)
        if firewall_generation != 5:
            commit_pending(api_base, api_session, silent=a.silent)
        routine_result_temp['commit_successful'] = True

        user_results.append(routine_result_temp)
        sleep(1)
        if not a.silent:
            print()

    return user_results


def unbind_totp_from_users(api_session, api_base: str, firewall_generation: int, users: dict, target_numbers: tuple):
    """Unbind TOTP from all eligible local users."""
    result = {
        'totp_unbind_attempted': True,
        'totp_unbind_successful_count': 0,
        'totp_unbind_failed_count': 0,
        'totp_unbind_results': []
    }

    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Starting TOTP unbind process for all local users...")

    # Skip TOTP unbind for GEN5 firewalls
    if firewall_generation == 5:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TOTP unbind skipped - GEN5 firewalls do not support TOTP.")
        result['totp_unbind_gen5_skipped'] = True
        return result

    # Get users for TOTP unbind if not already available
    totp_users = users
    if totp_users is None:
        if not a.silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Retrieving users for TOTP unbind...")
        try:
            if firewall_generation == 7:
                totp_users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=a.silent)
            elif firewall_generation == 6:
                totp_users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=a.silent)
        except KeyboardInterrupt:
            print(f"\nStopped!")
            exit()
        except Exception as e:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting users for TOTP unbind: {e}")
            result['totp_unbind_get_users_error'] = str(e)
            return result

        # Handle bytes response
        if isinstance(totp_users, bytes):
            totp_users = totp_users.replace(b': expired', b': "expired"')
            totp_users = json.loads(totp_users.decode('utf-8'))

    # Process TOTP unbind if we have users
    if totp_users and isinstance(totp_users, dict):
        if totp_users.get('user', {}).get('local', {}).get('user', None) is not None:
            users_list = totp_users['user']['local']['user']
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {len(users_list)} users for TOTP unbind processing...")

            for usr in users_list:
                # Skip special users
                skip_users = ['All LDAP Users', 'All RADIUS Users']
                if usr['name'] in skip_users:
                    result['totp_unbind_results'].append({
                        "name": usr['name'],
                        "totp_unbound": False,
                        "skipped": True,
                        "reason": "Special user entry"
                    })
                    continue

                # Skip expired users
                if (usr.get('account_lifetime', {}).get('lifetime', "") == "expired" or
                    usr.get('account_lifetime', {}).get('expired', False) is True):
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Skipping TOTP unbind for {usr['name']} (expired user)")
                    result['totp_unbind_results'].append({
                        "name": usr['name'],
                        "totp_unbound": False,
                        "skipped": True,
                        "reason": "Expired user"
                    })
                    continue

                # Skip domain users
                is_domain_user = False
                domain_name = ""
                if firewall_generation == 7:
                    is_domain_user = usr.get('domain', None) is not None
                    domain_name = usr.get('domain', '') if is_domain_user else ""
                elif firewall_generation == 6:
                    is_domain_user = usr.get('domain', {}).get('name', None) is not None
                    domain_name = usr.get('domain', {}).get('name', '') if is_domain_user else ""

                if is_domain_user:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Skipping TOTP unbind for {usr['name']} (domain user: {domain_name})")
                    result['totp_unbind_results'].append({
                        "name": usr['name'],
                        "totp_unbound": False,
                        "skipped": True,
                        "reason": "Domain user",
                        "domain": domain_name
                    })
                    continue

                # Perform TOTP unbind for this user
                uname = usr['name']
                if not a.silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unbinding TOTP for user '{uname}'...")

                totp_unbound = post_request(api_base,
                                            api_session,
                                            data=None,
                                            api_path=f"/api/sonicos/user/local/unbind-totp-key/{uname}",
                                            silent=a.silent)

                if totp_unbound:
                    api_result = totp_unbound.get('status', {}).get('info', [{}])[-1].get('message', 'No message returned.')
                    success = api_result.lower() == "changes made."
                    if not a.silent:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TOTP unbind for user '{uname}' -> {api_result}")

                    result['totp_unbind_results'].append({
                        "name": uname,
                        "totp_unbound": success,
                        "skipped": False,
                        "reason": None,
                        "api_response": api_result
                    })

                    if success:
                        result['totp_unbind_successful_count'] += 1
                    else:
                        result['totp_unbind_failed_count'] += 1
                else:
                    if not a.silent:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error unbinding TOTP for user '{uname}' - no response from API.")
                    result['totp_unbind_results'].append({
                        "name": uname,
                        "totp_unbound": False,
                        "skipped": False,
                        "reason": "API error - no response",
                        "api_response": None
                    })
                    result['totp_unbind_failed_count'] += 1

            # Commit changes after all TOTP unbinds
            if result['totp_unbind_successful_count'] > 0:
                if not a.silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Committing TOTP unbind changes...")
                commit_pending(api_base, api_session, silent=a.silent)

            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TOTP unbind complete - {result['totp_unbind_successful_count']} successful, {result['totp_unbind_failed_count']} failed")
        else:
            if not a.silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No local users found for TOTP unbind.")
            result['totp_unbind_no_users'] = True
    else:
        if not a.silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unable to retrieve users for TOTP unbind.")
        result['totp_unbind_get_users_failed'] = True

    return result


# Helper function for the summary
def calculate_routine_statistics(routine_results: dict, firewall: str):
    """Calculate and update routine statistics."""
    try:
        routine_results[firewall]['total_users_forced_to_update_password'] = len([u for u in routine_results[firewall].get('users', []) if u.get('commit_successful') is True])
    except (KeyError, TypeError):
        routine_results[firewall]['total_users_forced_to_update_password'] = 0

    try:
        routine_results[firewall]['commit_possibly_failed_count'] = len([u for u in routine_results[firewall].get('users', []) if u.get('commit_successful') is False])
    except (KeyError, TypeError):
        routine_results[firewall]['commit_possibly_failed_count'] = 0

    try:
        routine_results[firewall]['skipped_user_count'] = len([u for u in routine_results[firewall].get('users', []) if u.get('skipped') is True])
    except (KeyError, TypeError):
        routine_results[firewall]['skipped_user_count'] = 0

    try:
        routine_results[firewall]['total_postprocess_user_count'] = len(routine_results[firewall].get('users', []))
    except (KeyError, TypeError):
        routine_results[firewall]['total_postprocess_user_count'] = 0

    routine_results[firewall]['completed_routine_successfully'] = True


def generate_summary_table(results: dict):
    """Generate a rich table summarizing all security checks and their findings."""
    try:
        console = Console()

        # Main summary table
        table = Table(title="Remediation Playbook Summary",
                      show_lines=False,
                      show_header=True,
                      header_style="bold magenta",
                      caption_style="bold magenta",
                      caption=f"Refer to ./{constants.START_TIMESTAMP_FOLDER}/{results['device_model'].replace(' ', '')}-{results['serial_number']}-summary.md for resources to address each of the findings above."
                      )
        table.add_column("Configuration Area", style="cyan", no_wrap=True)
        table.add_column("Description", style="cyan", no_wrap=False, max_width=40)
        table.add_column("Priority", style="white", no_wrap=True)
        table.add_column("Status", style="white")
        table.add_column("Count", justify="right", style="yellow")
        table.add_column("Action Required", style="white")
        # table.add_column("Resource", style="white")

        # Helper function to determine count and status
        def get_count(data):
            if isinstance(data, dict):
                if 'server' in data or 'user' in data or 'vpn' in data:
                    # Try to extract list
                    for key in data.keys():
                        if isinstance(data[key], dict):
                            for subkey in data[key].keys():
                                val = data[key][subkey]
                                if isinstance(val, list):
                                    return len(val)
                                elif isinstance(val, dict) and 'server' in val:
                                    s = val.get('server', [])
                                    return len(s) if isinstance(s, list) else 1
                        elif isinstance(data[key], list):
                            return len(data[key])
            elif isinstance(data, list):
                return len(data)
            return 0

        # Authentication Servers - api/sonicos/user/tacacs/servers, /api/sonicos/user/radius/servers, /api/sonicos/user/ldap/servers
        ldap_count = get_count(results.get('ldap_servers', {}))
        if ldap_count > 0:
            table.add_row("LDAP Servers", "Find configured LDAP servers", "Critical",
                          "[green]Servers Configured[/green]", str(ldap_count), "[red]Update the LDAP bind credentials on the server and in SonicOS.[/red]")
        else:
            table.add_row("LDAP Servers", "Find configured LDAP servers", "Critical",
                          "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        radius_count = get_count(results.get('radius_servers', {}))
        if radius_count > 0:
            table.add_row("RADIUS Servers", "Find configured RADIUS servers", "Critical",
                          "[green]Servers Configured[/green]", str(radius_count), "[red]Update the RADIUS shared secret on the server and in SonicOS.[/red]")
        else:
            table.add_row("RADIUS Servers", "Find configured RADIUS servers", "Critical",
                          "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        tacacs_count = get_count(results.get('tacacs_servers', {}))
        if tacacs_count > 0:
            table.add_row("TACACS Servers", "Find configured TACACS servers", "Critical",
                          "[green]Servers Configured[/green]", str(tacacs_count), "[red]Update the shared secret on the server and in SonicOS.[/red]")
        else:
            table.add_row("TACACS Servers", "Find configured TACACS servers", "Critical",
                          "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        # VPN - /api/sonicos/vpn/policies/all
        vpn_count = get_count(results.get('vpn', {}).get('policy', []))
        if vpn_count > 0:
            table.add_row("VPN Policies", "Find configured VPN policies", "Critical",
                          "[green]Policies Found[/green]", str(vpn_count), "[red]Update the pre-shared secrets and/or encryption and authentication keys on each policy.[/red]")
        else:
            table.add_row("VPN Policies", "Find configured VPN policies", "Critical",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # WAN Interfaces (PPPoE/PPTP/L2TP) - /api/sonicos/interfaces/ipv4
        interesting_wans = results.get('interesting_wan_list', [])
        if len(interesting_wans) > 0:
            table.add_row("WAN Interfaces", "Looks for PPPoE/PPTP/L2TP WAN interfaces", "Critical",
                          "[green]Interfaces Found[/green]", str(len(interesting_wans)),
                          "[red]Update the credentials with your ISP, then in SonicOS.[/red]")
            table.add_row("", "", "", "", "", "[red] - Interface(s): " + ", ".join(interesting_wans) + "[/red]")
        else:
            table.add_row("WAN Interfaces", "Looks for PPPoE/PPTP/L2TP WAN interfaces", "Critical",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # AWS API - /api/sonicos/log/aws
        aws_enabled = results.get('log', {}).get('aws', {}).get('enable', False)
        if aws_enabled:
            table.add_row("AWS API Logging", "Check the AWS API integration status", "Critical",
                          "[green]Enabled[/green]", "", "[red]Update the secret key on the AWS Console, then in SonicOS.[/red]")
        else:
            table.add_row("AWS API Logging", "Check the AWS API integration status", "Critical",
                          "[dim]Not Enabled[/dim]", "", "[dim]No action required[/dim]")

        # Network Services - Dynamic DNS - /api/sonicos/dynamic-dns/profiles/ipv6 and /api/sonicos/dynamic-dns/profiles/ipv4
        ddns_v4 = get_count(results.get('ddns_services_v4', []))
        ddns_v6 = get_count(results.get('ddns_services_v6', []))
        total_ddns = ddns_v4 + ddns_v6
        if total_ddns > 0:
            table.add_row("Dynamic DNS", "Looks for IPv4/IPv6 DDNS entries", "High",
                          "[green]Profiles Found[/green]", str(total_ddns),
                          "[red]Update the credentials at the DDNS provider's website, then in SonicOS.[/red]")
        else:
            table.add_row("Dynamic DNS", "Looks for IPv4/IPv6 DDNS entries", "High",
                          "[dim]No profiles found[/dim]", "", "[dim]No action required[/dim]")

        # Cloud Secure Edge - /api/sonicos/cloud-secure-edge/base
        cse_enabled = results.get('cloud_secure_edge', {}).get('created', False)
        if cse_enabled:
            table.add_row("Cloud Secure Edge", "Checks Cloud Secure Edge (CSE) status", "Critical",
                          "[green]Enabled[/green]", "", "[red]Reset the CSE connector's API token.[/red]")
        else:
            table.add_row("Cloud Secure Edge", "Checks Cloud Secure Edge (CSE) status", "Critical",
                          "[dim]Not Enabled[/dim]", "", "[dim]No action required[/dim]")

        # Email Logging - /api/sonicos/log/automation
        email_logging_data = results.get('log_automation_data', {})
        if email_logging_data:
            if (
                    email_logging_data.get('pop3_flag', False) or
                    email_logging_data.get('smtp_flag', False) or
                    email_logging_data.get('ftp_flag', False)
            ):
                table.add_row("Email Logging", "Checks for Log Automation config", "Medium",
                              "[green]Configured[/green]", "", "[red]Update the email credentials on the server and in SonicOS.[/red]")
            if email_logging_data.get('pop3_flag', False):
                table.add_row("", "", "", "", "", "[red] - POP3: Update the email credentials on the server and in SonicOS.[/red]")
            if email_logging_data.get('smtp_flag', False):
                table.add_row("", "", "", "", "", "[red] - SMTP: Update the email credentials on the server and in SonicOS.[/red]")
            if email_logging_data.get('ftp_flag', False):
                table.add_row("", "", "", "", "", "[red] - FTP: Update the email credentials on the server and in SonicOS.[/red]")
            if (
                    email_logging_data.get('pop3_flag', False) is False and
                    email_logging_data.get('smtp_flag', False) is False and
                    email_logging_data.get('ftp_flag', False) is False
            ):
                table.add_row("Email Logging", "Checks for Log Automation config", "Medium",
                              "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")
        else:
            table.add_row("Email Logging", "Checks for Log Automation config", "Medium",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Packet Monitor FTP Logging - /api/sonicos/packet-monitor/base
        pktmon_flagged = results.get('packet_monitor_ftp_set', False)
        if pktmon_flagged:
            table.add_row("Packet Monitor FTP Logging", "Checks for FTP logging configuration", "Medium",
                          "[green]Configured[/green]", "", "[red]Update the FTP credentials on the server and in SonicOS.[/red]")
        else:
            table.add_row("Packet Monitor FTP Logging", "Checks for FTP logging configuration", "Medium",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Settings/TSR Scheduled Exports - /api/sonicos/ftp/base
        export_enabled = results.get('scheduled_exports_ftp_set', False)
        if export_enabled:
            table.add_row("TSR/EXP Scheduled Exports", "Checks for FTP configuration", "Medium",
                          "[green]Configured[/green]", "", "[red]Update the FTP credentials on the server and in SonicOS.[/red]")
        else:
            table.add_row("TSR Scheduled Exports", "Checks for FTP configuration", "Medium",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # SNMP - /api/sonicos/snmp/users
        snmp_count = get_count(results.get('snmp', {}).get('user', []))
        if snmp_count > 0:
            table.add_row("SNMPv3 Users", "Find configured SNMP user entries", "High",
                          "[green]Users Found[/green]", str(snmp_count), "[red]Update the password of each SNMP user.[/red]")
        else:
            table.add_row("SNMPv3 Users", "Find configured SNMP user entries", "High",
                          "[dim]No users found[/dim]", "", "[dim]No action required[/dim]")

        # Clearpass/NAC - /api/sonicos/network-access-control/clearpass/base
        # /api/sonicos/network-access-control/clearpass/servers
        clearpass_enabled = results.get('clearpass_enabled', False)
        clearpass_count = get_count(results.get('clearpass_servers', {}.get('clearpass_servers', [])))
        if clearpass_enabled or clearpass_count > 0:
            table.add_row("Clearpass/Network Access Control", "Finds configured servers", "High",
                          f"[green]{'Servers Found' if clearpass_count > 0 else 'Enabled'}[/green]", str(clearpass_count), "[red]Update the shared secret on the server and in SonicOS.[/red]")
            if clearpass_count == 0:
                table.add_row("", "", "", "", "", "[red] - Feature is enabled but no servers are configured.[/red]")
        else:
            table.add_row("Clearpass/Network Access Control", "Finds configured servers", "High",
                          "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        # Cellular WWAN - /api/sonicos/reporting/wwan
        cell_attached = results.get('cellular_data', {}).get('wwan_attached', False)
        if cell_attached:
            table.add_row("Cellular WWAN", "Checks for an attached modem", "High",
                          "[green]Modem Attached[/green]", "", "[red]Update the credentials with the cellular provider and in SonicOS.[/red]")
        else:
            table.add_row("Cellular WWAN", "Checks for an attached modem", "High",
                          "[dim]Modem not found[/dim]", "", "[dim]No action required[/dim]")

        # Zone Objects: Wireless Guest Services External Guest Authentication (Message Authentication)
        guest_message_auth = [i['zone'] for i in results.get('guest_zone_data', []) if i['guest_auth_ext_enabled']]
        guest_message_count = len(guest_message_auth)
        if guest_message_count > 0:
            table.add_row("Guest Services External Auth", "Finds Message Authentication config", "Medium",
                          "[green]Zones Found[/green]", str(guest_message_count), "[red]Update the Message Authentication password.[/red]")
            for g in guest_message_auth:
                table.add_row("", "", "", "", "", f"[red] - {str(g)}: Guest Services Message Authentication enabled. Update the Message Authentication password.[/red]")
        else:
            table.add_row("Guest Services External Auth", "Finds Message Authentication config", "Medium",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Zone Objects: WLAN RADIUS Servers - /api/sonicos/zones
        zone_data = results.get('wlan_zone_data', [])
        zone_radius_count = len(zone_data)
        if zone_radius_count > 0:
            table.add_row("Local RADIUS Server", "Finds WLAN RADIUS/LDAP config", "Medium",
                          "[green]Zones Found[/green]", str(zone_radius_count), "[red]Update the RADIUS shared secret and/or LDAP password.[/red]")
            for z in zone_data:
                if z['radius_server_enabled']:
                    table.add_row("", "", "", "", "", f"[red] - {z['zone']}: Local RADIUS server enabled. Update the RADIUS server shared secret.[/red]")
                if z['ldap_server_enabled'] or z['ldap_server_host']:
                    table.add_row("", "", "", "", "", f"[red] - {z['zone']}: LDAP server enabled. Update the LDAP server password.[/red]")
        else:
            table.add_row("Local RADIUS Server", "Finds WLAN RADIUS/LDAP config", "Medium",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Internal Wireless - Radio - /api/sonicos/wireless/radio
        radio_radius = results.get('internal_wlan', {}).get('wireless', {}).get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
        radio_psk = results.get('internal_wlan', {}).get('wireless', {}).get('wpa', {}).get('passphrase', None)
        if radio_radius or radio_psk:
            table.add_row("Internal WLAN Radio", "Looks for built-in WLAN config", "Medium",
                          "[green]Configured[/green]", "", "[red]Update the pre-shared keys, RADIUS, and RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            if radio_radius:
                table.add_row("", "", "", "", "", "[red] - Update the RADIUS and/or RADIUS Accounting secrets on the server, then in SonicOS.[/red]")
            if radio_psk:
                table.add_row("", "", "", "", "", "[red] - Update the pre-shared keys on the server, then in SonicOS.[/red]")
        else:
            table.add_row("Internal WLAN Radio", "Looks for built-in WLAN config", "Medium",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Internal Wireless - Virtual Access Point Objects - /api/sonicos/wireless/virtual-access-point/objects
        vap_count = get_count(results.get('internal_wlan_vaps', {}).get('wireless', {}).get('virtual_access_point', {}).get('object', []))
        vap_data = results.get('internal_wlan_vap_data', [])
        if vap_count > 0:
            table.add_row("Internal WLAN VAP Objects", "Checks for PSK/RADIUS in VAP objects", "Medium",
                          "[green]Found[/green]", str(vap_count), "[red]Update the pre-shared keys, RADIUS, and RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            for p in vap_data:
                if p['radius']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}, SSID: {p['ssid']}: Update the RADIUS server shared secret.")
                if p['accounting']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}, SSID: {p['ssid']}: Update the RADIUS Accounting server shared secret.")
        else:
            table.add_row("Internal WLAN VAP Objects", "Checks for PSK/RADIUS in VAP objects", "Medium",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Internal Wireless - Virtual Access Point Profiles - /api/sonicos/wireless/virtual-access-point/profiles
        vap_profile_count = get_count(results.get('internal_wlan_vap_profiles', {}).get('wireless', {}).get('virtual_access_point', {}).get('profile', []))
        profile_data = results.get('internal_wlan_vap_profile_data', [])
        if vap_profile_count > 0:
            table.add_row("Internal WLAN VAP Profiles", "Checks for PSK/RADIUS in VAP profiles", "Medium",
                          "[green]Found[/green]", str(vap_profile_count), "[red]Update the pre-shared keys, RADIUS, and RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            for p in profile_data:
                if p['radius']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS server shared secret.")
                if p['accounting']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS Accounting server shared secret.")
        else:
            table.add_row("Internal WLAN VAP Profiles", "Checks for PSK/RADIUS in VAP profiles", "Medium",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # SonicPoint/SonicWave Access Point Objects - /api/sonicos/sonicpoint/sonicpoints
        ap_count = get_count(results.get('sonicpoint_objects', {}).get('sonicpoint', {}).get('sonicpoint', []))
        ap_data = results.get('sonicpoint_object_data', [])

        if ap_count > 0:
            table.add_row("SonicPoint/SonicWave Objects", "Checks for PSK/RADIUS (AP objects)", "Medium",
                          "[green]Objects Found[/green]", str(ap_count), "[red]Update the pre-shared keys and RADIUS/RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            for p in ap_data:
                if p['radius'] and (p['radius'] != '' and p['radius'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS server shared secret.")
                if p['accounting'] and (p['accounting'] != '' and p['accounting'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS Accounting server shared secret.")
                if p['sslvpn_user'] or p['sslvpn_server']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the SSLVPN credentials {p['sslvpn_user']}@{p['sslvpn_server']}.")
                if p['administrator']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the administrator password.")
        else:
            table.add_row("SonicPoint/SonicWave Objects", "Checks for PSK/RADIUS (AP objects)", "Medium",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # SonicPoint/SonicWave Access Point Profiles - /api/sonicos/sonicpoint/profiles
        profile_count = len(results.get('sonicpoint_profiles', {}).get('sonicpoint', {}).get('profile', []))
        profile_data = results.get('sonicpoint_profile_data', [])
        if profile_count > 0:
            table.add_row("SonicPoint/SonicWave Profiles", "Checks for PSK/RADIUS (AP profiles)", "Medium",
                          "[green]Profiles Found[/green]", str(profile_count), "[red]Update the pre-shared keys and RADIUS/RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            for p in profile_data:
                if p['radius'] and (p['radius'] != '' and p['radius'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS server shared secret.")
                if p['accounting'] and (p['accounting'] != '' and p['accounting'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS Accounting server shared secret.")
                if p['sslvpn_user'] or p['sslvpn_server']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the SSLVPN credentials {p['sslvpn_user']}@{p['sslvpn_server']}.")
                if p['administrator']:
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the administrator password.")
        else:
            table.add_row("SonicPoint/SonicWave Profiles", "Checks for PSK/RADIUS (AP profiles)", "Medium",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # SonicPoint/SonicWave Virtual Access Points - /api/sonicos/sonicpoint/virtual-access-point/objects
        vap_count = get_count(results.get('sonicpoint_vaps', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('object', []))
        vap_data = results.get('sonicpoint_vap_data', [])
        if vap_count > 0:
            table.add_row("SonicPoint/SonicWave VAP Objects", "Checks for PSK/RADIUS (VAP objects)", "Medium",
                          "[green]Objects Found[/green]", str(vap_count), "[red]Update the pre-shared keys and RADIUS/RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            for p in vap_data:
                if p['radius'] and (p['radius'] != '' and p['radius'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}, SSID: {p['ssid']}: Update the RADIUS server shared secret.")
                if p['accounting'] and (p['accounting'] != '' and p['accounting'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}, SSID: {p['ssid']}: Update the RADIUS Accounting server shared secret.")
        else:
            table.add_row("SonicPoint/SonicWave VAP Objects", "Checks for PSK/RADIUS (VAP objects)", "Medium",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # SonicPoint/SonicWave Virtual Access Point Profiles - /api/sonicos/sonicpoint/virtual-access-point/profiles
        vap_profile_count = get_count(results.get('sonicpoint_vap_profiles', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', []))
        profile_data = results.get('sonicpoint_vap_profile_data', [])
        if vap_profile_count > 0:
            table.add_row("SonicPoint/SonicWave VAP Profiles", "Checks for PSK/RADIUS (VAP profiles)", "Medium",
                          "[green]Profiles Found[/green]", str(vap_profile_count), "[red]Update the pre-shared keys and RADIUS/RADIUS Accounting secrets on the server, then in SonicOS[/red]")
            for p in profile_data:
                if p['radius'] and (p['radius'] != '' and p['radius'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS server shared secret.")
                if p['accounting'] and (p['accounting'] != '' and p['accounting'] != '0.0.0.0'):
                    table.add_row("", "", "", "", "", f"[red] - {p['name']}: Update the RADIUS Accounting server shared secret.")
        else:
            table.add_row("SonicPoint/SonicWave VAP Profiles", "Checks for PSK/RADIUS (VAP profiles)", "Medium",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Dynamic External Address Objects - /api/sonicos/dynamic-external-objects
        deao_count = results.get('dynamic_ao_count', 0)
        deao_data = results.get('dynamic_ao_data', [])
        ftp_deaos = [d for d in deao_data if d['protocol'] == 'ftp']
        http_deaos = [d for d in deao_data if d['protocol'] == 'https']
        if deao_count > 0:
            table.add_row("Dynamic External Address Objects", "Finds configured objects", "High",
                          "[green]Objects Found[/green]", str(deao_count), "[red]Update the credentials at the server, then in SonicOS.[/red]")
            if len(ftp_deaos) > 0:
                table.add_row("", "", "", "", "", f"[red] - {str(len(ftp_deaos))} object(s) using FTP. Update the credentials at the server, then in SonicOS.[/red]")
            if len(http_deaos) > 0:
                table.add_row("", "", "", "", "", f"[red] - {str(len(http_deaos))} object(s) using HTTPS. Update the credentials at the server, then in SonicOS.[/red]")
        else:
            table.add_row("Dynamic External Address Objects", "Finds configured objects", "High",
                          "[dim]No objects found[/dim]", "", "[dim]No action required[/dim]")

        # Dynamic Botnet Server List - /api/sonicos/botnet/base
        botnet_data = results.get('botnet_data', {})
        if botnet_data:
            if botnet_data['protocol'] == 'ftp':
                table.add_row("Botnet Server List (FTP)", "Checks Botnet server list protocol", "Low",
                              "[green]Configured[/green]", "", "[red]Change the Botnet server list protocol to HTTPS.[/red]")
            elif botnet_data['protocol'] == 'https':
                table.add_row("Botnet Server List (HTTP)", "Checks Botnet server list protocol", "Low",
                              "[green]Configured[/green]", "", "[red]Change the Botnet server list protocol to HTTPS.[/red]")
            else:
                table.add_row("Botnet Server List", "Checks Botnet server list protocol", "Low",
                              "[green]Not configured[/green]", "", "[dim]No action required[/dim]")
        else:
            table.add_row("Botnet Server List", "Checks Botnet server list protocol", "Low",
                          "[dim]No configuration found[/dim]", "", "[dim]No action required[/dim]")

        # Extended Switches
        switch_count = get_count(results.get('switch_controller', {}).get('switch_info', []))
        if switch_count > 0:
            table.add_row("Extended Switches", "Checks for connected switches", "Low",
                          "[green]Switches Found[/green]", str(switch_count), "[red]Update the password for any extended switches.[/red]")
        else:
            table.add_row("Extended Switches", "Checks for connected switches", "Low",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Extended Switch Users
        switch_user_count = get_count(results.get('extended_switch_users', []))
        if switch_user_count > 0:
            table.add_row("External Switch Users", "Looks for users in switch config", "Low",
                          "[green]Users Found[/green]", str(switch_user_count), "[red]Update each user's password in the switch configuration.[/red]")
        else:
            table.add_row("External Switch Users", "Looks for users in switch config", "Low",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Extended Switch RADIUS Servers
        switch_radius_count = get_count(results.get('switch_controller', {}).get('radius', []))
        if switch_radius_count > 0:
            table.add_row("External Switch RADIUS Servers", "Looks for RADIUS server config", "Low",
                          "[green]Servers Found[/green]", str(switch_radius_count), "[red]Update the RADIUS shared secret on each server and in the switch configuration.[/red]")
        else:
            table.add_row("External Switch RADIUS Servers", "Looks for RADIUS server config", "Low",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # SSO Agents - /api/sonicos/user/sso/agents
        sso_count = get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', []))
        if sso_count > 0:
            table.add_row("Single Sign On Agents", "Finds configured SSO Agents", "Low",
                          "[green]Agents Found[/green]", str(sso_count), "[red]Update the shared secrets on each agent.[/red]")
        else:
            table.add_row("Single Sign On Agents", "Finds configured SSO Agents", "Low",
                          "[dim]No agents found[/dim]", "", "[dim]No action required[/dim]")

        # TS Agents - /api/sonicos/user/sso/terminal-services-agents
        tsa_count = get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', []))
        if tsa_count > 0:
            table.add_row("Terminal Services Agents", "Finds configured TS Agents", "Low",
                          "[green]Agents Found[/green]", str(tsa_count), "[red]Update the shared secrets on each agent.[/red]")
        else:
            table.add_row("Terminal Services Agents", "Finds configured TS Agents", "Low",
                          "[dim]No agents found[/dim]", "", "[dim]No action required[/dim]")

        # SSO RADIUS Accounting Clients - /api/sonicos/user/sso/radius-accounting-clients
        sso_radius_count = get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', []))
        if sso_radius_count > 0:
            table.add_row("SSO RADIUS Accounting Clients", "Finds configured SSO RA Clients", "Low",
                          "[green]RA Clients Found[/green]", str(sso_radius_count), "[red]Update the shared secrets on each client and in SonicOS.[/red]")
        else:
            table.add_row("SSO RADIUS Accounting Clients", "Finds configured SSO RA Clients", "Low",
                          "[dim]No RA clients found[/dim]", "", "[dim]No action required[/dim]")

        # SSO 3rd Party API - /api/sonicos/user/sso/third-party-api/clients
        sso_api_count = get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []))
        if sso_api_count > 0:
            table.add_row("SSO 3rd Party API Clients", "Finds SSO API Client entries", "Low",
                          "[green]API Clients Found[/green]", str(sso_api_count), "[red]Update the shared secrets on each client and in SonicOS.[/red]")
        else:
            table.add_row("SSO 3rd Party API Clients", "Finds SSO API Client entries", "Low",
                          "[dim]No API clients found[/dim]", "", "[dim]No action required[/dim]")

        # RADIUS Accounting Servers - /api/sonicos/user/radius/accounting/servers
        acct_count = get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', []))
        if acct_count > 0:
            table.add_row("RADIUS Accounting Servers", "Finds configured RA servers", "Low",
                          "[green]RA Servers Found[/green]", str(acct_count), "[red]Update the shared secrets on each server and in SonicOS.[/red]")
        else:
            table.add_row("RADIUS Accounting Servers", "Finds configured RA servers", "Low",
                          "[dim]No RA servers found[/dim]", "", "[dim]No action required[/dim]")

        # TACACS Accounting Servers - /api/sonicos/user/tacacs/accounting/servers
        tacacs_acct_count = get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []))
        if tacacs_acct_count > 0:
            table.add_row("TACACS Accounting Servers", "Finds configured TACACS Acct servers", "Low",
                          "[green]Servers Found[/green]", str(tacacs_acct_count), "[red]Update the shared secrets on each server and in SonicOS.[/red]")
        else:
            table.add_row("TACACS Accounting Servers", "Finds configured TACACS Acct servers", "Low",
                          "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        # AppFlow SFR Mailing - /api/sonicos/appflow/sfr-mailing/base
        sfr_smtp_configured = results.get('sfr_data', {}).get('smtp_configured', False)
        sfr_pop_configured = results.get('sfr_data', {}).get('pop_configured', False)
        if sfr_smtp_configured or sfr_pop_configured:
            table.add_row("AppFlow SFR Mailing", f"Checks for SMTP/POP configuration", "Low",
                          "[green]Configured[/green]", "", "[red]Update the email server credentials in SonicOS.[/red]")
        else:
            table.add_row("AppFlow SFR Mailing", "Checks for SMTP/POP configuration", "Low",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Custom NTP Servers - /api/sonicos/time/ntp-servers
        ntp_count = get_count(results.get('ntp_data', []))
        if ntp_count > 0:
            table.add_row("Custom NTP Servers", "Finds NTP entries with auth", "Low",
                          "[green]Entries Found[/green]", str(ntp_count), "[red]Update the credentials on each NTP server and in SonicOS.[/red]")
        else:
            table.add_row("Custom NTP Servers", "Finds NTP entries with auth", "Low",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Security Services Signature Proxy - /api/sonicos/security-services/base
        sig_proxy_auth = results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False)
        sig_proxy_username = results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', '')
        if sig_proxy_auth or sig_proxy_username:
            table.add_row("Security Services Proxy", "Checks for proxy for signature downloads", "Low",
                          "[green]Configured[/green]", "", "[red]Update the credentials on the proxy server and in SonicOS.[/red]")
        else:
            table.add_row("Security Services Proxy", "Checks for proxy for signature downloads", "Low",
                          "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # GMS IPSec Manaagement Tunnel - /api/sonicos/administration/global
        gms_conf = results.get('gms', {}).get('ipsec_tunnel', False)
        if gms_conf:
            table.add_row("GMS IPSec Management Tunnel", "Checks for GMS IPSec Management Tunnel", "Low",
                            "[green]Configured[/green]", "", "[red]Update the encryption/authentication keys.")

        else:
            table.add_row("GMS IPSec Management Tunnel", "Checks for GMS IPSec Management Tunnel", "Low",
                            "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Advanced Routing - /api/sonicos/dynamic-file/getAdvancedRoutingData.json
        adv_routing = results.get('routing_data', [])
        any_rip = [i for i in results.get('routing_data', []) if i.get('flag_rip', False)]
        any_ospf = [i for i in results.get('routing_data', []) if i.get('flag_ospfv2', False)]
        any_bgp = [i for i in results.get('routing_data', []) if i.get('flag_bgp', False)]
        adv_routing_count = len(any_rip) + len(any_ospf) + len(any_bgp)
        # rip_ints = [f"{i.get('interface', '')} ({i.get('zone', '')})" for i in any_rip]
        rip_ints = [i.get('interface', '') for i in any_rip]
        rip_ints = ", ".join(rip_ints)
        ospf_ints = [i.get('interface', '') for i in any_ospf]
        ospf_ints = ", ".join(ospf_ints)
        bgp_ints = [i.get('interface', '') for i in any_bgp]
        bgp_ints = ", ".join(bgp_ints)

        if adv_routing_count > 0:
            table.add_row("Advanced Routing Protocols", "Checks for RIP/OSPFv/BGP config", "Low",
                          "[green]Configured[/green]", str(adv_routing_count), "[red]Update the credentials on each routing peer and in SonicOS.[/red]")
            if any_rip:
                table.add_row("", "", "", "", "", f"[red] - RIP on {rip_ints}: Update the RIP password on the routing peer and in SonicOS.[/red]")
            if any_ospf:
                table.add_row("", "", "", "", "", f"[red] - OSPFv2 on {ospf_ints}: Update the OSPFv2 authentication on the routing peer and in SonicOS.[/red]")
            if any_bgp:
                table.add_row("", "", "", "", "", f"[red] - BGP on {bgp_ints}: Update the BGP password on the routing peer and in SonicOS.[/red]")
        else:
            table.add_row("Advanced Routing Protocols", "Checks for RIP/OSPFv/BGP config", "Low",
                          "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Blank row for spacing
        table.add_row("", "", "", "", "", "")

        # Local Users
        # Force Password Change
        # TODO: Make sure this works properly. The link is still here, meaning I may have missed something.
        total_users = results.get('total_user_count', 0)
        users_updated = results.get('total_users_forced_to_update_password', 0)
        users_skipped = results.get('skipped_user_count', 0)
        if total_users > 0:
            table.add_row("Force Password Change", "Total users updated and skipped",
                          "Critical", "[green]Users Found[/green]", str(total_users),
                         f"[green]{users_updated} updated[/green], [yellow]{users_skipped} skipped[/yellow]")
        else:
            table.add_row("Force Password Change", "Total users updated and skipped",
                          "Critical", "[red]Not Performed[/red]", "N/A", "[red]No users found or not executed.[/red]")

        # TOTP Unbind
        totp_unbind_attempted = results.get('totp_unbind_attempted', False)
        totp_unbind_results = results.get('totp_unbind_results', [])
        if totp_unbind_attempted:
            failed = results.get('totp_unbind_failed_count', 0)
            success = results.get('totp_unbind_successful_count', 0)
            if success > 0 or failed > 0:
                table.add_row("Reset TOTP Bindings", "Total bindings reset: succeeded/failed",
                              "Critical", "[green]Processed[/green]", f"{success+failed}",
                             f"[green]{success} unbound[/green], [yellow]{failed} failed[/yellow]")
            else:
                table.add_row("Reset TOTP Bindings", "Total bindings reset: succeeded/failed",
                              "Critical", "[red]No Users Processed[/red]", "0", "[red]No TOTP bindings were reset.[/red]")
        else:
            table.add_row("Reset TOTP Bindings", "Total bindings reset: succeeded/failed",
                          "Critical", "[red]Not Performed[/red]", "N/A", "[red]TOTP bindings were not reset.[/red]")

        console.print("\n")
        console.print(table)
        console.print("\n")

        return table
    except Exception as e:
        print(f"Error generating summary table: {e}")
        return None


def generate_markdown_summary(results: dict, firewall: str, firewall_info: dict):
    """Generate a markdown summary report of all checks and findings."""
    md_lines = []

    try:
        # Header
        md_lines.append(f"# Remediation Playbook Summary Report")
        md_lines.append(f"")
        md_lines.append(f"- **Firewall:** {firewall}")
        md_lines.append(f"- **Device Model:** {firewall_info.get('device_model', 'Unknown')}")
        md_lines.append(f"- **Serial Number:** {firewall_info.get('serial_number', 'Unknown')}")
        md_lines.append(f"- **Firmware Version:** {firewall_info.get('firmware_version', 'Unknown')}")
        md_lines.append(f"- **Generation:** GEN{firewall_info.get('firewall_generation', 'Unknown')}")
        md_lines.append(f"- **Report Generated:** {generate_timestamp()}")
        md_lines.append(f"")
        md_lines.append(f"---")
        md_lines.append(f"")
    except Exception as e:
        print(f"Error generating markdown header: {e}")
        return None

    try:
        # Exports
        md_lines.append(f"### Log and Configuration Exports")
        md_lines.append(f"")
        tsr_location = f"[{results.get('tsr_file_name', '')}]({results.get('tsr_file_name', '')})"
        tracelogs_location = f"[{results.get('tracelog_filename', '')}]({results.get('tracelog_filename', '')})"
        settings_location = f"[{results.get('prefs_file_name', '')}]({results.get('prefs_file_name', '')})"

        if results.get('trace_logs_downloaded'):
            md_lines.append(f"- **Trace Logs Downloaded:** {tracelogs_location}")
        else:
            md_lines.append(f"- **Trace Logs Downloaded:** No")

        if results.get('tsr_downloaded'):
            md_lines.append(f"- **TSR Downloaded:** {tsr_location}")
        else:
            md_lines.append(f"- **TSR Downloaded:** No")

        if results.get('settings_exported'):
            md_lines.append(f"- **Settings Exported:** {settings_location}")
        else:
            md_lines.append(f"- **Settings Exported:** No")

        md_lines.append(f"")
        md_lines.append(f"---")
        md_lines.append(f"")
    except Exception as e:
        print(f"Error generating markdown exports section: {e}")
        return None

    # Executive Summary
    md_lines.append(f"## Brief Summary")
    md_lines.append(f"")

    action_items = []
    review_items = []
    completed_items = []

    # Count items requiring action
    def get_count(data):
        try:
            if isinstance(data, dict):
                for key in data.keys():
                    if isinstance(data[key], dict):
                        for subkey in data[key].keys():
                            val = data[key][subkey]
                            if isinstance(val, list):
                                return len(val)
            elif isinstance(data, list):
                return len(data)
            return 0
        except Exception as e:
            print(f"Error getting count from '{data}': {e}")
            return 0

    # LDAP  Servers
    if get_count(results.get('ldap_servers', {})) > 0:
        action_items.append(f"| Critical | {get_count(results.get('ldap_servers', {}))} Server(s) Configured | LDAP server(s) require bind password updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_LDAP_Authentication) |")

    # RADIUS/TACACS Servers
    if get_count(results.get('radius_servers', {})) > 0:
        action_items.append(f"| Critical | {get_count(results.get('radius_servers', {}))} Server(s) Configured | RADIUS server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Authentication) |")

    # TACACS Servers
    if get_count(results.get('tacacs_servers', {})) > 0:
        action_items.append(f"| Critical | {get_count(results.get('tacacs_servers', {}))} Server(s) Configured | TACACS server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_TACACS__Authentication) |")

    # VPN Policies
    if get_count(results.get('vpn', {})) > 0:
        action_items.append(f"| Critical | {get_count(results.get('vpn', {}))} VPN Configured | VPN policies require pre-shared key, authentication/encryption key updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared) |")

    # Dynamic DNS
    ddns_v4 = get_count(results.get('ddns_services_v4', []))
    ddns_v6 = get_count(results.get('ddns_services_v6', []))
    if ddns_v4 + ddns_v6 > 0:
        action_items.append(f"| High | {ddns_v4 + ddns_v6} Profile(s) | Dynamic DNS profile(s) require credential updates | [Link](https://www.sonicwall.com/support/knowledge-base/how-to-configure-dynamic-dns-for-a-particular-interface/170504323594835) |")

    # WAN Interfaces (L2TP/PPPoE/PPTP)
    interesting_wan_ints = [i for i in results.get('interesting_wan_list', [])]
    if len(interesting_wan_ints) > 0:
        action_items.append(f"| Critical | {len(interesting_wan_ints)} WAN interface(s) | {', '.join(interesting_wan_ints)} require credential updates for L2TP/PPPoE/PPTP connections | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a) |")

    # AWS API Logging
    if results.get('log', {}).get('aws', {}).get('enable', False):
        action_items.append(f"| Critical | Enabled | AWS API Logging is enabled - Update the secret key in the AWS Console | [Link](https://www.sonicwall.com/support/knowledge-base/aws-integration-with-sonicwall-sonicos-6-5-x/181024232124532) |")

    # Cloud Secure Edge
    if results.get('cloud_secure_edge', {}).get('created', False):
        action_items.append(f"| Critical | Enabled | Cloud Secure Edge is enabled - Reset the CSE connector's API token | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_CSE) |")

    # Email logging actions
    email_logging = results.get('log_automation_data', {})
    email_actions = []
    if email_logging.get('pop3_flag'):
        email_actions.append("POP3")
    if email_logging.get('smtp_flag'):
        email_actions.append("SMTP")
    if email_logging.get('ftp_flag'):
        email_actions.append("FTP")
    if email_actions:
        action_items.append(f"| Medium | Configured | Email logging credentials require updates for the following protocols: {', '.join(email_actions)} | [Link](https://www.sonicwall.com/support/knowledge-base/how-can-i-e-mail-logs-and-alerts-via-smtp-server/170503803088038) |")

    try:
        # Packet Monitor FTP action
        if results.get('packet_monitor_ftp_set', False):
            action_items.append(f"| Medium | Configured | Packet Monitor FTP credentials require updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Reset_any_passwords:~:text=for%20more%20information.-,FTP/Web%20Passwords,-Reset%20the%20password) |")
    except Exception as e:
        print(f"Error checking packet monitor FTP setting: {e}")

    try:
        # Scheduled Exports FTP action
        if results.get('scheduled_exports_ftp_set', False):
            action_items.append(f"| Medium | Configured | TSR/EXP Scheduled Exports credentials require updates | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/Firmware_Settings/firmware-backup-configuring.htm) |")
    except Exception as e:
        print(f"Error checking scheduled exports FTP setting: {e}")

    # SNMPv3 Users
    if get_count(results.get('snmp', {}).get('user', [])) > 0:
        action_items.append(f"| High | {get_count(results.get('snmp', {}).get('user', []))} Users Found | SNMPv3 user(s) require authentication/privacy password updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_SNMP_-_SNMP) |")

    # ClearPass/Network Access Control (NAC)
    try:
        if results.get('clearpass_enabled', False):
            clearpass_server_count = len(results.get('clearpass_servers', []))
            action_items.append(f"| High | Enabled ({clearpass_server_count} Servers) | ClearPass/Network Access Control (NAC) is enabled with {clearpass_server_count} server(s) - {'update the shared secret on each configured entry' if clearpass_server_count > 0 else 'configure NAC entries or disable the feature if not in use'} | [Link](https://www.sonicwall.com/support/knowledge-base/how-to-add-a-clearpass-server-on-a-sonicwall-firewall/240523045608440) |")
    except Exception as e:
        print(f"Error checking ClearPass setting: {e}")

    # Cellular WWAN
    if results.get('cellular_data', {}).get('wwan_attached', False):
        action_items.append(f"| High | Modem Found | Cellular WWAN is enabled - Update the cellular provider credentials | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a) |")

    # Wireless: Guest Services External Authentication
    try:
        guest_auth = results.get('guest_zone_data', [])
        if guest_auth:
            action_items.append(f"| Medium | {len(guest_auth)} Zone(s) Found | Wireless Guest Services External Authentication is enabled - Update the shared secret on each configured entry | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Reset_any_passwords:~:text=more%20information.-,Guest%20Services,-Reset%20the%20shared) |")
    except Exception as e:
        print(f"Error checking Wireless Guest Services setting: {e}")

    # Wireless: Local RADIUS Servers on Wireless type Zones
    try:
        wireless_radius_count = get_count(results.get('wlan_zone_data', []))
        if wireless_radius_count > 0:
            action_items.append(f"| Medium | {wireless_radius_count} Zone(s) Found | {wireless_radius_count} Wireless Zone(s) configured with Local RADIUS Servers - Update the shared secret on each configured entry | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-access_points/Content/Access_Points_Settings/access-point-settings-about-local-radius-servers.htm) |")
    except Exception as e:
        print(f"Error checking Wireless Local RADIUS Servers: {e}")

    # Wireless: Internal WLAN Radio
    try:
        radio_radius = results.get('internal_wlan', {}).get('wireless', {}).get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
        radio_psk = results.get('internal_wlan', {}).get('wireless', {}).get('wpa', {}).get('passphrase', None)
        if radio_radius or radio_psk:
            action_items.append(f"| Medium | Configured | Internal WLAN Radio is enabled - Update the pre-shared keys, RADIUS, and RADIUS Accounting secrets on the server, then in SonicOS | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking Internal WLAN Radio setting: {e}")

    # Wireless: Internal WLAN Virtual Access Points (VAPs) Objects
    try:
        vap_count = get_count(results.get('internal_wlan_vaps', {}).get('wireless', {}).get('virtual_access_point', {}).get('object', []))
        if vap_count > 0:
            action_items.append(f"| Medium | {vap_count} Internal WLAN Virtual Access Point(s) Found | Update the WLAN password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking Internal WLAN VAPs: {e}")

    # Wireless: Internal WLAN Virtual Access Points (VAPs) Profiles
    try:
        vap_profile_count = get_count(results.get('internal_wlan_vap_profiles', {}).get('wireless', {}).get('virtual_access_point', {}).get('profile', []))
        if vap_profile_count > 0:
            action_items.append(f"| Medium | {vap_profile_count} Profile(s) Found | Update the WLAN Virtual Access Point Profile(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking Internal WLAN VAP Profiles: {e}")

    # Wireless: SonicPoint/SonicWave Access Point Objects
    try:
        ap_count = get_count(results.get('sonicpoint_objects', {}).get('sonicpoint', {}).get('sonicpoint', []))
        if ap_count > 0:
            action_items.append(f"| Medium | {ap_count} Ojects Found | Update the WLAN SonicPoint/SonicWave Access Point(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking SonicPoint/SonicWave Access Points: {e}")

    # Wireless: SonicPoint/SonicWave Access Point Profiles
    try:
        ap_profile_count = len(results.get('sonicpoint_profiles', {}).get('sonicpoint', {}).get('profile', []))
        if ap_profile_count > 0:
            action_items.append(f"| Medium | {ap_profile_count} Profile(s) Found | Update the WLAN SonicPoint/SonicWave Access Point Profile(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking SonicPoint/SonicWave Access Point Profiles: {e}")

    # Wireless: SonicPoint/SonicWave Virtual Access Points (VAPs) Objects
    try:
        sp_vap_count = get_count(results.get('sonicpoint_vaps', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('object', []))
        if sp_vap_count > 0:
            action_items.append(f"| Medium | {sp_vap_count} Objects Found | Update the WLAN SonicPoint/SonicWave Virtual Access Point(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking SonicPoint/SonicWave VAPs: {e}")

    # Wireless: SonicPoint/SonicWave Virtual Access Points (VAPs) Profiles
    try:
        sp_vap_profile_count = get_count(results.get('sonicpoint_vap_profiles', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', []))
        if sp_vap_profile_count > 0:
            action_items.append(f"| Medium | {sp_vap_profile_count} Profile(s) Found | Update the WLAN SonicPoint/SonicWave Virtual Access Point Profile(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
    except Exception as e:
        print(f"Error checking SonicPoint/SonicWave VAP Profiles: {e}")

    # Dynamic External Address Objects
    try:
        dynamic_address_count = get_count(results.get('dynamic_ao_count', 0))
        if dynamic_address_count > 0:
            action_items.append(f"| High | {dynamic_address_count} Object(s) Found | Review and update credentials for Dynamic External Address Object(s) | [Link](https://www.sonicwall.com/support/knowledge-base/what-are-dynamic-external-objects-groups-and-how-can-we-configure-it/200507105852280) |")
    except Exception as e:
        print(f"Error checking Dynamic External Address Objects: {e}")

    # Dynamic Botnet List Server (FTP/HTTPS)
    try:
        botnet_data = results.get('botnet_data', {})
        if botnet_data.get('protocol', False):
            action_items.append(f"| Low | Configured ({botnet_data.get('protocol', '').upper()}) | Review and update Dynamic Botnet List Server credentials | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-rules_policies_policy/Content/Settings/settings-botnet-dynamic-botnet-list-server-config.htm) |")
    except Exception as e:
        print(f"Error checking Dynamic Botnet List Server: {e}")

    # Extended Switches
    try:
        ext_switch_count = get_count(results.get('extended_switches', []))
        if ext_switch_count > 0:
            action_items.append(f"| Low | {ext_switch_count} Extended Switch(es) Found | Review and update credentials on the switch(es) | [Link](https://www.sonicwall.com/support/knowledge-base/how-to-change-the-password-for-sonicwall-switch/200607142015373) |")
    except Exception as e:
        print(f"Error checking Extended Switches: {e}")

    # Extended Switch Users
    try:
        ext_switch_user_count = get_count(results.get('extended_switch_users', []))
        if ext_switch_user_count > 0:
            action_items.append(f"| Low | {ext_switch_user_count} Extended Switch User(s) Found | Review and update credentials on the switch(es) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=and%20Backup%20Settings)-,Extended%20Switches,-Reset%20the%20password) |")
    except Exception as e:
        print(f"Error checking Extended Switch Users: {e}")

    # Extended Switch RADIUS Servers
    try:
        ext_switch_radius_count = get_count(results.get('extended_switch_radius_servers', []))
        if ext_switch_radius_count > 0:
            action_items.append(f"| Low | {ext_switch_radius_count} Extended Switch RADIUS Server(s) Found | Review and update shared secrets on the switch(es) and in SonicOS | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=and%20Backup%20Settings)-,Extended%20Switches,-Reset%20the%20password) |")
    except Exception as e:
        print(f"Error checking Extended Switch RADIUS Servers: {e}")

    # SSO Agents
    if get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', []))} Agents Found | SSO agent(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # Terminal Services Agents
    if get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', []))} Agents Found | Terminal Services agent(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # RADIUS Accounting Clients
    if get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', []))} RA Clients Found | SSO RADIUS Accounting client(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # 3rd Party API Clients
    if get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []))} API Clients Found | SSO 3rd Party API client(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # RADIUS Accounting Servers
    if get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', []))} Servers Found | RADIUS Accounting server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries) |")

    # TACACS Accounting Servers
    if get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []))} Servers Found | TACACS Accounting server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries) |")

    # AppFlow SFR Mailing
    if results.get('sfr_data', {}).get('smtp_configured', False) or results.get('sfr_data', {}).get('pop_configured', False):
        action_items.append(f"| Low | Configured | AppFlow SFR Mailing is configured - Update the email server credentials | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-appflow_device/Content/appflow-d-flow-reporting-sfr-mailing.htm) |")

    # Custom NTP Servers
    if get_count(results.get('ntp_data', [])) > 0:
        action_items.append(f"| Low | {get_count(results.get('ntp_data', []))} Servers Found | Custom NTP server(s) require authentication password updates | [Link](https://www.sonicwall.com/support/knowledge-base/service-configuration-how-to-configure-ntp-and-snmp-services/210715103828777) |")

    # Security Services Signature Proxy
    if results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False) or results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', ''):
        action_items.append(f"| Low | Configured | Security Services Proxy is configured - Update the proxy server credentials | [Link](https://www.sonicwall.com/support/knowledge-base/signature-downloads-through-a-proxy-server/170503292286520) |")

    # GMS IPSec Management Tunnel
    if results.get('gms', {}).get('ipsec_tunnel', False):
        action_items.append(f"| Low | Configured | GMS IPSec Management Tunnel is configured - Update the encryption/authentication keys | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared) |")

    # Advanced Routing Protocols
    adv_routing = results.get('routing_data', [])
    any_rip = [i for i in results.get('routing_data', []) if i.get('flag_rip', False)]
    any_ospf = [i for i in results.get('routing_data', []) if i.get('flag_ospfv2', False)]
    any_bgp = [i for i in results.get('routing_data', []) if i.get('flag_bgp', False)]
    adv_routing_count = len(any_rip) + len(any_ospf) + len(any_bgp)
    if adv_routing_count > 0:
        action_items.append(f"| Low | RIP {len(any_rip)}, OSPFv2 {len(any_ospf)}, BGP {len(any_bgp)} | Routing configuration requires authentication/password updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=the%20remediation%20instructions.-,Advanced%20Routing,-Update%20passwords%20used) |")

    # Force Password Change
    try:
        total_users = results.get('total_user_count', 0)
        users_updated = results.get('total_users_forced_to_update_password', 0)
        users_skipped = results.get('skipped_user_count', 0)
        if users_updated > 0 or users_skipped > 0:
            completed_items.append(f"- **{users_updated} local user(s)** forced to change password on next login. **{users_skipped} user(s)** skipped (e.g., non-local users).")
        elif total_users == 0:
            review_items.append(f"- No local users found or not executed. Ensure the 'Force Password Change' action is enabled in the input CSV file or using CLI arguments. This is strongly recommended for all local users.")
    except Exception as e:
        print(f"Error checking users updated count: {e}")

    # TOTP Unbind
    try:
        totp_unbind_attempted = results.get('totp_unbind_attempted', False)
        if totp_unbind_attempted:
            failed = results.get('totp_unbind_failed_count', 0)
            success = results.get('totp_unbind_successful_count', 0)
            if success > 0 or failed > 0:
                completed_items.append(f"- **{success} user(s)** had TOTP unbound successfully. **{failed} user(s)** failed to unbind TOTP.")
        else:
            review_items.append(f"- TOTP unbind was not attempted. Enable TOTP unbinding in the input CSV file or using CLI arguments. This is strongly recommended for all users.")
    except Exception as e:
        print(f"Error checking TOTP unbind count: {e}")

    if action_items:
        md_lines.append(f"### Action Items ({len(action_items)}) for {firewall_info.get('device_model', 'Unknown')} ({firewall_info.get('serial_number', 'Unknown')})")
        md_lines.append(f"The following items were identified by the tool during the execution of the remediation playbook checks. Please review and manually take action as necessary.")
        md_lines.append(f"")
        md_lines.append("| Priority | Finding | Action Item | Resources |")
        md_lines.append("|----------|---------|-------------|-----------|")
        for item in action_items:
            md_lines.append(item)
        md_lines.append(f"")

    if review_items:
        md_lines.append(f"### Review Items ({len(review_items)})")
        md_lines.append(f"The following items may require your attention.")
        md_lines.append(f"")
        for item in review_items:
            md_lines.append(item)
        md_lines.append(f"")

    if completed_items:
        md_lines.append(f"### Completed Actions ({len(completed_items)})")
        md_lines.append(f"The following actions were completed by the tool, as requested via CLI argument or CSV input file.")
        md_lines.append(f"")
        for item in completed_items:
            md_lines.append(item)
        md_lines.append(f"")

    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")

    # Recommendations
    md_lines.append(f"## Recommendations")
    md_lines.append(f"")
    md_lines.append(f"1. **Immediately** update all credentials, pre-shared keys, and shared secrets identified in the Action Items section")
    md_lines.append(f"2. **Test** critical services after credential updates to ensure continued operation")
    md_lines.append(f"3. **Distribute** the temporary password to each user, if one was set. If randomized passwords were enabled, refer to the `user_passwords.csv` file generated during playbook execution")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")

    # Detailed Findings
    md_lines.append(f"## Detailed Findings")
    md_lines.append(f"The following sections provide detailed information on the findings and actions taken during the remediation playbook execution.")
    md_lines.append(f"")

    # Authentication
    md_lines.append(f"### Authentication")
    md_lines.append(f"")

    # LDAP Servers
    try:
        ldap_count = get_count(results.get('ldap_servers', {}))
        md_lines.append(f"- **LDAP Servers:** {ldap_count}")
        if ldap_count > 0:
            md_lines.append(f"  - **Action:** Update bind password on the LDAP server(s), then update in SonicOS")
            md_lines.append(f"  - **Priority:** Critical")
            md_lines.append(f"  - **Reference:** [LDAP Authentication](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_LDAP_Authentication)")
    except Exception as e:
        print(f"Error processing LDAP servers: {e}")
        md_lines.append(f"- **LDAP Servers:** Error retrieving count")

    # RADIUS Servers
    try:
        radius_count = get_count(results.get('radius_servers', {}))
        md_lines.append(f"- **RADIUS Servers:** {radius_count}")
        if radius_count > 0:
            md_lines.append(f"  - **Action:** Update RADIUS shared secrets on the RADIUS server(s), then update in SonicOS")
            md_lines.append(f"  - **Priority:** Critical")
            md_lines.append(f"  - **Reference:** [RADIUS Authentication](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Authentication)")
    except Exception as e:
        print(f"Error processing RADIUS servers: {e}")
        md_lines.append(f"- **RADIUS Servers:** Error retrieving count")

    # TACACS Servers
    try:
        tacacs_count = get_count(results.get('tacacs_servers', {}))
        md_lines.append(f"- **TACACS Servers:** {tacacs_count}")
        if tacacs_count > 0:
            md_lines.append(f"  - **Action:** Update TACACS+ shared secrets")
            md_lines.append(f"  - **Priority:** Critical")
            md_lines.append(f"  - **Reference:** [TACACS+ Authentication](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_TACACS__Authentication)")
    except Exception as e:
        print(f"Error processing TACACS servers: {e}")
        md_lines.append(f"- **TACACS Servers:** Error retrieving count")

    # SSO Agents
    try:
        sso_count = get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', []))
        md_lines.append(f"- **SSO Agents:** {sso_count}")
        if sso_count > 0:
            md_lines.append(f"  - **Action:** Update shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SSO Shared Secret Update](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets)")
    except Exception as e:
        print(f"Error generating SSO section: {e}")
        md_lines.append(f"- **SSO Agents:** Error retrieving information")

    # Terminal Services Agents
    try:
        ts_count = get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', []))
        md_lines.append(f"- **Terminal Services Agents:** {ts_count}")
        if ts_count > 0:
            md_lines.append(f"  - **Action:** Update shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SSO Shared Secret Update](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets)")
    except Exception as e:
        print(f"Error generating Terminal Services section: {e}")
        md_lines.append(f"- **Terminal Services Agents:** Error retrieving information")

    # RADIUS Accounting Clients
    try:
        radius_acct_count = get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', []))
        md_lines.append(f"- **RADIUS Accounting Clients:** {radius_acct_count}")
        if radius_acct_count > 0:
            md_lines.append(f"  - **Action:** Update shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [RADIUS Accounting Clients](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets)")
    except Exception as e:
        print(f"Error generating RADIUS Accounting section: {e}")
        md_lines.append(f"- **RADIUS Accounting Clients:** Error retrieving information")

    # 3rd Party API Clients
    try:
        api_client_count = get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []))
        md_lines.append(f"- **3rd Party API Clients:** {api_client_count}")
        if api_client_count > 0:
            md_lines.append(f"  - **Action:** Update shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [3rd Party API Clients](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets)")
    except Exception as e:
        print(f"Error generating 3rd Party API Clients section: {e}")
        md_lines.append(f"- **3rd Party API Clients:** Error retrieving information")

    # RADIUS Accounting Servers
    try:
        radius_acct_server_count = get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', []))
        md_lines.append(f"- **RADIUS Accounting Servers:** {radius_acct_server_count}")
        if radius_acct_server_count > 0:
            md_lines.append(f"  - **Action:** Update shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [RADIUS Accounting Servers](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries)")
    except Exception as e:
        print(f"Error generating RADIUS Accounting Servers section: {e}")
        md_lines.append(f"- **RADIUS Accounting Servers:** Error retrieving information")

    # TACACS Accounting Servers
    try:
        tacacs_acct_server_count = get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []))
        md_lines.append(f"- **TACACS Accounting Servers:** {tacacs_acct_server_count}")
        if tacacs_acct_server_count > 0:
            md_lines.append(f"  - **Action:** Update shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [TACACS Accounting Servers](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries)")
    except Exception as e:
        print(f"Error generating TACACS Accounting Servers section: {e}")
        md_lines.append(f"- **TACACS Accounting Servers:** Error retrieving information")
    md_lines.append(f"")

    # VPN Configuration
    md_lines.append(f"### VPN")
    md_lines.append(f"")
    try:
        vpn_count = get_count(results.get('vpn', {}).get('policy', []))
        md_lines.append(f"- **VPN Policies:** {vpn_count}")
        if vpn_count > 0:
            md_lines.append(f"  - **Action:** Review and update pre-shared keys and authentication/encryption keys")
            md_lines.append(f"  - **Priority:** Critical")
            md_lines.append(f"  - **Reference:** [IPSec VPN pre-shared keys](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared)")
            md_lines.append(f"  - **Policy List:**")
        for policy in results.get('vpn', {}).get('policy', []):
            policy_name = policy.get('ipv4', {}).get('group_vpn', {}).get('name') or policy.get('ipv4', {}).get('site_to_site', {}).get('name') or policy.get('ipv4', {}).get('tunnel_interface', {}).get('name')
            policy_status = policy.get('ipv4', {}).get('group_vpn', {}).get('enable', False) or policy.get('ipv4', {}).get('site_to_site', {}).get('enable', False) or policy.get('ipv4', {}).get('tunnel_interface', {}).get('enable', False)
            md_lines.append(f"    - **{policy_name}** {'policy is enabled' if policy_status else 'policy is disabled'}")
    except Exception as e:
        print(f"Error processing VPN policies: {e}")
        md_lines.append(f"- **VPN Policies:** Error retrieving count")
    md_lines.append(f"")

    # Network Services
    md_lines.append(f"### Network Services")
    md_lines.append(f"")

    # WAN Interfaces (PPPoE/PPTP/L2TP)
    try:
        interesting_wans = results.get('interesting_wan_list', [])
        wan_interface_count = get_count(interesting_wans)
        md_lines.append(f"- **PPPoE/PPTP/L2TP WAN Interfaces:** {wan_interface_count}")
        if wan_interface_count > 0:
            md_lines.append(f"  - **Action:** Update the username and password for each WAN interface configured with PPPoE, PPTP, or L2TP")
            md_lines.append(f"  - **Priority:** High")
            md_lines.append(f"  - **Reference:** [PPPoE Configuration](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a)")
            md_lines.append(f"  - **Interface List:**")
        for interface in interesting_wans:
            md_lines.append(f"    - **{interface}**")
    except Exception as e:
        print(f"Error processing WAN interfaces: {e}")
        md_lines.append(f"- **WAN Interfaces (PPPoE/PPTP/L2TP):** Error retrieving count")

    # Cellular WWAN
    try:
        wwan_attached = results.get('cellular_attached', 0)
        if wwan_attached != 0:
            md_lines.append(f"- **Cellular WWAN Model Detected:** {wwan_attached}")
            md_lines.append(f"  - **Action:** Update cellular provider credentials at the provider's website, then update in SonicOS")
            md_lines.append(f"  - **Priority:** High")
            md_lines.append(f"  - **Reference:** [Cellular WWAN Configuration](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a)")
    except Exception as e:
        print(f"Error processing Cellular WWAN: {e}")
        md_lines.append(f"- **Cellular WWAN Interfaces:** Error retrieving information")

    # Dynamic DNS
    md_lines.append(f"- **Dynamic DNS (IPv4) Profiles:** {ddns_v4}")
    md_lines.append(f"- **Dynamic DNS (IPv6) Profiles:** {ddns_v6}")
    if ddns_v4 + ddns_v6 > 0:
        md_lines.append(f"  - **Action:** Update DDNS provider credentials for each configured entry at the provider's website, then update in SonicOS")
        md_lines.append(f"  - **Priority:** High")
        md_lines.append(f"  - **Reference:** [Dynamic DNS Configuration](https://www.sonicwall.com/support/knowledge-base/how-to-configure-dynamic-dns-for-a-particular-interface/170504323594835)")

    # ClearPass/NAC
    try:
        clearpass_enabled = results.get('clearpass_enabled', False)
        clearpass_server_count = len(results.get('clearpass_servers', []))

        if clearpass_enabled:
            md_lines.append(f"- **ClearPass/NAC:** Enabled with {clearpass_server_count} server(s)")
            md_lines.append(f"  - **Action:** Update shared secrets on ClearPass servers")
            md_lines.append(f"  - **Priority:** High")
            md_lines.append(f"  - **Reference:** [ClearPass/NAC Configuration](https://www.sonicwall.com/support/knowledge-base/how-to-add-a-clearpass-server-on-a-sonicwall-firewall/240523045608440)")
        else:
            md_lines.append(f"- **ClearPass/NAC:** Not enabled")
    except Exception as e:
        print(f"Error generating ClearPass section: {e}")
        md_lines.append(f"- **ClearPass/NAC:** Error retrieving information")

    # Dynamic External Address Objects
    try:
        dynamic_address_count = results.get('dynamic_ao_count', 0)
        deao_data = results.get('dynamic_ao_data', [])
        ftp_deaos = [d for d in deao_data if d['protocol'] == 'ftp']
        http_deaos = [d for d in deao_data if d['protocol'] == 'https']

        md_lines.append(f"- **Dynamic External Address Objects:** {dynamic_address_count}")
        if dynamic_address_count > 0:
            md_lines.append(f"  - **Action:** Review and update credentials for Dynamic External Address Object(s)")
            md_lines.append(f"  - **Priority:** High")
            md_lines.append(f"  - **Reference:** [Dynamic External Address Objects](https://www.sonicwall.com/support/knowledge-base/what-are-dynamic-external-objects-groups-and-how-can-we-configure-it/200507105852280)")
            if len(ftp_deaos) > 0:
                md_lines.append(f"  - **FTP-based DEAOs:** {len(ftp_deaos)}")
                for obj in ftp_deaos:
                    md_lines.append(f"    - **{obj.get('name', 'Unnamed Object')}** (Server: {obj.get('server', 'Unknown')})")
            if len(http_deaos) > 0:
                md_lines.append(f"  - **HTTPS-based DEAOs:** {len(http_deaos)}")
                for obj in http_deaos:
                    md_lines.append(f"    - **{obj.get('name', 'Unnamed Object')}** (URL: {obj.get('url', 'Unknown')})")
    except Exception as e:
        print(f"Error processing Dynamic External Address Objects: {e}")
        md_lines.append(f"- **Dynamic External Address Objects:** Error retrieving count")

    # Dynamic Botnet Server List
    try:
        botnet_data = results.get('botnet_data', {})
        if botnet_data.get('protocol', False):
            md_lines.append(f"- **Dynamic Botnet List Server:** Configured using {botnet_data.get('protocol', '').upper()}")
            md_lines.append(f"  - **Action:** Review and update Dynamic Botnet List Server credentials")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [Dynamic Botnet List Server](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-rules_policies_policy/Content/Settings/settings-botnet-dynamic-botnet-list-server-config.htm)")
        else:
            md_lines.append(f"- **Dynamic Botnet List Server:** Not configured")
    except Exception as e:
        print(f"Error processing Dynamic Botnet List Server: {e}")
        md_lines.append(f"- **Dynamic Botnet List Server:** Error retrieving information")

    # Custom NTP Servers
    try:
        ntp_count = get_count(results.get('ntp_data', []))
        md_lines.append(f"- **Custom NTP Servers:** {ntp_count}")
        if ntp_count > 0:
            md_lines.append(f"  - **Action:** Update authentication passwords on each NTP server and in SonicOS")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [NTP Configuration](https://www.sonicwall.com/support/knowledge-base/service-configuration-how-to-configure-ntp-and-snmp-services/210715103828777)")
    except Exception as e:
        print(f"Error processing NTP servers: {e}")
        md_lines.append(f"- **Custom NTP Servers:** Error retrieving count")

    # Security Services Proxy
    try:
        sig_proxy_auth = results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False)
        sig_proxy_username = results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', '')
        if sig_proxy_auth or sig_proxy_username:
            md_lines.append(f"- **Security Services Proxy:** Configured")
            md_lines.append(f"  - **Action:** Update the proxy server credentials in SonicOS")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [Signature Downloads Through a Proxy Server](https://www.sonicwall.com/support/knowledge-base/signature-downloads-through-a-proxy-server/170503292286520)")
        else:
            md_lines.append(f"- **Security Services Proxy:** Not configured")
    except Exception as e:
        print(f"Error processing Security Services Proxy: {e}")
        md_lines.append(f"- **Security Services Proxy:** Error retrieving information")
    md_lines.append(f"")

    # Wireless
    md_lines.append(f"### Wireless Configuration")
    md_lines.append(f"")

    # Wireless: Guest Services External Authentication (Message Auth)
    try:
        guest_zones = results.get('guest_zone_data', [])
        md_lines.append(f"- **Guest Services External Authentication (Message Authentication):** {len(guest_zones)} Zone(s) configured")
        if len(guest_zones) > 0:
            md_lines.append(f"  - **Action:** Update shared secrets on each server and in SonicOS")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [Guest Services External Authentication](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Reset_any_passwords:~:text=more%20information.-,Guest%20Services,-Reset%20the%20shared)")
            md_lines.append(f"  - **Zones with External Guest Auth with Message Authentication:**")
            for zone in guest_zones:
                md_lines.append(f"    - **{zone.get('zone', 'Unnamed Zone')}** Zone")
    except Exception as e:
        print(f"Error processing Guest Services External Authentication: {e}")
        md_lines.append(f"- **Guest Services External Authentication Servers:** Error retrieving count")

    # Wireless: WLAN Local RADIUS Server
    try:
        wlan_radius_zones = results.get('wlan_zone_data', [])
        md_lines.append(f"- **WLAN Local RADIUS Server:** {len(wlan_radius_zones)} Zone(s) configured")
        if len(wlan_radius_zones) > 0:
            md_lines.append(f"  - **Action:** Update the RADIUS shared secrets and LDAP server password in SonicOS")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [WLAN Local RADIUS Servers](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-access_points/Content/Access_Points_Settings/access-point-settings-about-local-radius-servers.htm)")
            for zone in wlan_radius_zones:
                md_lines.append(f"    - **{zone.get('zone', 'Unnamed Zone')}** Zone")
                if zone['radius_server_enabled']:
                    md_lines.append(f"      - Local RADIUS Server is enabled. Update the RADIUS shared secret.")
                if zone['ldap_server_enabled'] or zone['ldap_server_host']:
                    md_lines.append(f"      - LDAP Server is enabled. Update the LDAP server password.")
    except Exception as e:
        print(f"Error processing WLAN Local RADIUS Servers: {e}")
        md_lines.append(f"- **WLAN Local RADIUS Servers:** Error retrieving count")

    # Wireless: Internal WLAN Radio
    try:
        radio_radius = results.get('wireless', {}).get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
        radio_psk = results.get('wireless', {}).get('wpa', {}).get('passphrase', None)
        md_lines.append(f"- **Internal WLAN Radio:** {'Configured' if radio_radius or radio_psk else 'Not Configured'}")
        if radio_radius or radio_psk:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [Internal WLAN Radio Configuration](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            if radio_radius:
                md_lines.append(f"    - RADIUS Server is configured. Update the RADIUS shared secret.")
            if radio_psk:
                md_lines.append(f"    - Pre-shared key is configured. Update the pre-shared key.")
    except Exception as e:
        print(f"Error processing Internal WLAN Radios: {e}")
        md_lines.append(f"- **Internal WLAN Radios:** Error retrieving count")

    # Wireless: Internal WLAN Virtual Access Point Objects
    try:
        vap_count = get_count(results.get('internal_wlan_vaps', {}).get('wireless', {}).get('virtual_access_point', {}).get('object', []))
        vap_data = results.get('internal_wlan_vap_data', [])
        md_lines.append(f"- **Internal WLAN Virtual Access Points:** {vap_count} Object(s) configured")
        if vap_count > 0:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [Internal WLAN Virtual Access Points](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            for vap in vap_data:
                md_lines.append(f"    - **{vap.get('name', 'Unnamed VAP')}** Virtual Access Point")
                if vap.get('radius', False):
                    md_lines.append(f"      - RADIUS Server is enabled. Update the RADIUS shared secret.")
                if vap.get('accounting', False) or vap.get('wpa_passphrase', None):
                    md_lines.append(f"      - Pre-shared key is enabled. Update the pre-shared key.")
    except Exception as e:
        print(f"Error processing Internal WLAN Virtual Access Points: {e}")
        md_lines.append(f"- **Internal WLAN Virtual Access Points:** Error retrieving count")

    # Wireless: Internal WLAN Virtual Access Point Profiles
    try:
        vap_profile_count = get_count(results.get('internal_wlan_vap_profiles', {}).get('wireless', {}).get('virtual_access_point', {}).get('profile', []))
        vap_profile_data = results.get('internal_wlan_vap_profile_data', [])
        md_lines.append(f"- **Internal WLAN Virtual Access Point Profiles:** {vap_profile_count} Profile(s) configured")
        if vap_profile_count > 0:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [Internal WLAN Virtual Access Point Profiles](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            md_lines.append(f"  - **Profile List:**")
            for profile in vap_profile_data:
                md_lines.append(f"    - **{profile.get('name', 'Unnamed Profile')}**")
                if profile.get('radius', False):
                    md_lines.append(f"      - RADIUS Server is enabled. Update the RADIUS shared secret.")
                if profile.get('accounting', False):
                    md_lines.append(f"      - Update the RADIUS Accounting server shared secret.")
    except Exception as e:
        print(f"Error processing Internal WLAN Virtual Access Point Profiles: {e}")
        md_lines.append(f"- **Internal WLAN Virtual Access Point Profiles:** Error retrieving count")

    # Wireless: SonicPoint/SonicWave Access Point Objects
    try:
        ap_count = get_count(results.get('sonicpoint_objects', {}).get('sonicpoint', {}).get('sonicpoint', []))
        ap_data = results.get('sonicpoint_object_data', [])
        md_lines.append(f"- **SonicPoint/SonicWave Access Points:** {ap_count} Object(s) configured")
        if ap_count > 0:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicPoint/SonicWave Access Points](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            for p in ap_data:
                md_lines.append(f"    - **{p.get('name', 'Unnamed AP')}** Access Point")
                if p['radius'] and (p['radius'] != '' and p['radius'] != '0.0.0.0'):
                    md_lines.append(f"      - Update the RADIUS server shared secret.")
                if p['accounting'] and (p['accounting'] != '' and p['accounting'] != '0.0.0.0'):
                    md_lines.append(f"      - Update the RADIUS Accounting server shared secret.")
                if p['sslvpn_user']  or p['sslvpn_server']:
                    md_lines.append(f"      - Update the SSL VPN credentials {p['sslvpn_user']}@{p['sslvpn_server']}")
                if p['administrator']:
                    md_lines.append(f"      - Update the Access Point administrator password.")
    except Exception as e:
        print(f"Error processing SonicPoint/SonicWave Access Points: {e}")
        md_lines.append(f"- **SonicPoint/SonicWave Access Points:** Error retrieving count")

    # Wireless: SonicPoint/SonicWave Access Point Profiles
    try:
        ap_profile_count = get_count(results.get('sonicpoint_profiles', {}).get('sonicpoint', {}).get('profile', []))
        ap_profile_data = results.get('sonicpoint_profile_data', [])
        md_lines.append(f"- **SonicPoint/SonicWave Access Point Provisioning Profiles:** {ap_profile_count} Profile(s) configured")
        if ap_profile_count > 0:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS/RADIUS Accounting shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicPoint/SonicWave Access Point Profiles](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            md_lines.append(f"  - **Profile List:**")
            for profile in ap_profile_data:
                md_lines.append(f"    - **{profile.get('name', 'Unnamed Profile')}**")
                md_lines.append(f"      - Update the pre-shared keys.")
                if profile.get('radius', False) and (profile.get('radius', '') != '' and profile.get('radius', '0.0.0.0') != '0.0.0.0'):
                    md_lines.append(f"      - RADIUS Server is enabled. Update the RADIUS shared secret.")
                if profile.get('accounting', False) and (profile.get('accounting', '') != '' and profile.get('accounting', '0.0.0.0') != '0.0.0.0'):
                    md_lines.append(f"      - Update the RADIUS Accounting server shared secret.")
                if profile.get('sslvpn_user', False) or profile.get('sslvpn_server', False):
                    md_lines.append(f"      - Update the SSL VPN credentials {profile.get('sslvpn_user', 'Unknown User')}@{profile.get('sslvpn_server', 'Unknown Server')}")
                if profile.get('administrator', False):
                    md_lines.append(f"      - Update the Access Point administrator password.")
    except Exception as e:
        print(f"Error processing SonicPoint/SonicWave Access Point Profiles: {e}")
        md_lines.append(f"- **SonicPoint/SonicWave Access Point Profiles:** Error retrieving count")

    # Wireless: SonicPoint/SonicWave Virtual Access Point Objects
    try:
        spvap_count = get_count(results.get('sonicpoint_vaps', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('object', []))
        spvap_data = results.get('sonicpoint_vap_data', [])
        md_lines.append(f"- **SonicPoint/SonicWave Virtual Access Points:** {spvap_count} VAP Object(s) configured")
        if spvap_count > 0:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicPoint/SonicWave Virtual Access Points](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            md_lines.append(f"  - **Virtual Access Point Object List:**")
            for vap in spvap_data:
                md_lines.append(f"    - **{vap.get('name', 'Unnamed VAP')}**")
                md_lines.append(f"      - Update the pre-shared keys.")
                if vap.get('radius', False) and (vap.get('radius', '') != '' and vap.get('radius', '0.0.0.0') != '0.0.0.0'):
                    md_lines.append(f"      - Update the RADIUS server shared secret.")
                if vap.get('accounting', False) and (vap.get('accounting', '') != '' and vap.get('accounting', '0.0.0.0') != '0.0.0.0'):
                    md_lines.append(f"      - Update the RADIUS Accounting server shared secret.")
    except Exception as e:
        print(f"Error processing SonicPoint/SonicWave Virtual Access Points: {e}")
        md_lines.append(f"- **SonicPoint/SonicWave Virtual Access Points:** Error retrieving count")

    # Wireless: SonicPoint/SonicWave Virtual Access Point Profiles
    try:
        spvap_profile_count = get_count(results.get('sonicpoint_vap_profiles', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', []))
        spvap_profile_data = results.get('sonicpoint_vap_profile_data', [])
        md_lines.append(f"- **SonicPoint/SonicWave Virtual Access Point Profiles:** {spvap_profile_count} VAP Profile(s) configured")
        if spvap_profile_count > 0:
            md_lines.append(f"  - **Action:** Update pre-shared keys and RADIUS shared secrets")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicPoint/SonicWave Virtual Access Point Profiles](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi)")
            md_lines.append(f"  - **Virtual Access Point Profile List:**")
            for profile in spvap_profile_data:
                md_lines.append(f"    - **{profile.get('name', 'Unnamed Profile')}**")
                md_lines.append(f"      - Update the pre-shared keys.")
                if profile.get('radius', False) and (profile.get('radius', '') != '' and profile.get('radius', '0.0.0.0' ) != '0.0.0.0'):
                    md_lines.append(f"      - RADIUS Server is enabled. Update the RADIUS shared secret.")
                if profile.get('accounting', False) and (profile.get('accounting', '') != '' and profile.get('accounting', '0.0.0.0') != '0.0.0.0'):
                    md_lines.append(f"      - Update the RADIUS Accounting server shared secret.")
    except Exception as e:
        print(f"Error processing SonicPoint/SonicWave Virtual Access Point Profiles: {e}")
        md_lines.append(f"- **SonicPoint/SonicWave Virtual Access Point Profiles:** Error retrieving count")

    md_lines.append(f"")

    # Extended Infrastructure
    md_lines.append(f"### Infrastructure")
    md_lines.append(f"")
    try:
        switch_count = get_count(results.get('switch_controller', {}).get('switch_info', []))
        md_lines.append(f"- **Extended Switches:** {switch_count}")
        if switch_count > 0:
            md_lines.append(f"  - **Action:** Update the password for any connected switches")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicWall Switch Password Change](https://www.sonicwall.com/support/knowledge-base/how-to-change-the-password-for-sonicwall-switch/200607142015373)")
    except Exception as e:
        print(f"Error processing extended switches: {e}")
        md_lines.append(f"- **Extended Switches:** Error retrieving information")

    # Extended Switch Users
    try:
        switch_user_count = get_count(results.get('extended_switch_users', []))
        md_lines.append(f"- **Extended Switch Users:** {switch_user_count}")
        if switch_user_count > 0:
            md_lines.append(f"  - **Action:** Update each user's password in the switch configuration")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicWall Switch Password Change](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=and%20Backup%20Settings)-,Extended%20Switches,-Reset%20the%20password)")
    except Exception as e:
        print(f"Error processing extended switch users: {e}")
        md_lines.append(f"- **Extended Switch Users:** Error retrieving information")

    # Extended Switch RADIUS Servers
    try:
        switch_radius_count = get_count(results.get('switch_controller', {}).get('radius', []))
        md_lines.append(f"- **Extended Switch RADIUS Servers:** {switch_radius_count}")
        if switch_radius_count > 0:
            md_lines.append(f"  - **Action:** Update the shared secret on each server and in the switch configuration")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [SonicWall Switch Password Change](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=and%20Backup%20Settings)-,Extended%20Switches,-Reset%20the%20password)")
    except Exception as e:
        print(f"Error processing extended switch RADIUS servers: {e}")
        md_lines.append(f"- **Extended Switch RADIUS Servers:** Error retrieving information")

    # GMS IPSec Management Tunnel
    try:
        gms_ipsec = results.get('gms', {}).get('ipsec_tunnel', False)
        if gms_ipsec:
            md_lines.append(f"- **GMS IPSec Management Tunnel Detected:**")
            md_lines.append(f"  - **Action:** Update the authentication/encryption keys")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [GMS IPSec Management Tunnel](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared)")
    except Exception as e:
        print(f"Error processing GMS IPSec Management Tunnels: {e}")
        md_lines.append(f"- **GMS IPSec Management Tunnels:** Error retrieving information")

    # Advanced Routing Protocols (RIP/OSPFv2/BGP)
    try:
        any_rip = [i for i in results.get('routing_data', []) if i.get('flag_rip', False)]
        any_ospf = [i for i in results.get('routing_data', []) if i.get('flag_ospfv2', False)]
        any_bgp = [i for i in results.get('routing_data', []) if i.get('flag_bgp', False)]
        adv_routing_count = len(any_rip) + len(any_ospf) + len(any_bgp)
        # rip_ints = [f"{i.get('interface', '')} ({i.get('zone', '')})" for i in any_rip]
        rip_ints = [i.get('interface', '') for i in any_rip]
        rip_ints = ", ".join(rip_ints)
        ospf_ints = [i.get('interface', '') for i in any_ospf]
        ospf_ints = ", ".join(ospf_ints)
        bgp_ints = [i.get('interface', '') for i in any_bgp]
        bgp_ints = ", ".join(bgp_ints)

        if adv_routing_count > 0:
            if any_rip or any_ospf or any_bgp:
                md_lines.append(f"- **Advanced Routing Protocols Enabled:**")
                if any_rip:
                    md_lines.append(f"  - **RIP:** Enabled on {len(any_rip)} interface(s) ({rip_ints})")
                if any_ospf:
                    md_lines.append(f"  - **OSPFv2:** Enabled on {len(any_ospf)} interface(s) ({ospf_ints})")
                if any_bgp:
                    md_lines.append(f"  - **BGP:** Enabled on {len(any_bgp)} interface(s) ({bgp_ints})")
                md_lines.append(f"  - **Action:** Update authentication keys for each enabled protocol")
                md_lines.append(f"  - **Priority:** Low")
                md_lines.append(f"  - **Reference:** [Advanced Routing Protocols](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=the%20remediation%20instructions.-,Advanced%20Routing,-Update%20passwords%20used)")
        else:
            md_lines.append(f"- **Advanced Routing Protocols:** None enabled")
    except Exception as e:
        print(f"Error processing advanced routing protocols: {e}")
        md_lines.append(f"- **Advanced Routing Protocols:** Error retrieving information")

    md_lines.append(f"")

    # Monitoring & Management
    md_lines.append(f"### Reporting, Monitoring, and Management")
    md_lines.append(f"")

    # SNMPv3 Users
    try:
        snmp_count = get_count(results.get('snmp', {}).get('user', []))
        md_lines.append(f"- **SNMPv3 Users:** {snmp_count}")
        if snmp_count > 0:
            md_lines.append(f"  - **Action:** Update authentication and privacy passwords")
            md_lines.append(f"  - **Priority:** High")
            md_lines.append(f"  - **Reference:** [SNMPv3 User Configuration](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_SNMP_-_SNMP)")
    except Exception as e:
        print(f"Error generating SNMP section: {e}")
        md_lines.append(f"- **SNMPv3 Users:** Error retrieving information")

    # Email Logging
    try:
        email_logging = results.get('log_automation_data', {})
        email_services = []
        if email_logging.get('pop3_flag'):
            email_services.append("POP3")
        if email_logging.get('smtp_flag'):
            email_services.append("SMTP")
        if email_logging.get('ftp_flag'):
            email_services.append("FTP")

        if email_services:
            md_lines.append(f"- **Email Logging:** {len(email_services)} service(s) configured ({', '.join(email_services)})")
            md_lines.append(f"  - Action: Update email server credentials")
            md_lines.append(f"  - Priority: Medium")
            md_lines.append(f"  - Reference: [Email Logging Configuration](https://www.sonicwall.com/support/knowledge-base/how-can-i-e-mail-logs-and-alerts-via-smtp-server/170503803088038)")
        else:
            md_lines.append(f"- **Email Logging:** Not configured")
    except Exception as e:
        print(f"Error generating Email Logging section: {e}")
        md_lines.append(f"- **Email Logging:** Error retrieving information")

    # Packet Monitor FTP
    try:
        if results.get('packet_monitor_ftp_set', False):
            md_lines.append(f"- **Packet Monitor FTP:** Configured")
            md_lines.append(f"  - Action: Update FTP server credentials")
            md_lines.append(f"  - Priority: Medium")
            md_lines.append(f"  - Reference: [Packet Monitor Configuration](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Reset_any_passwords:~:text=for%20more%20information.-,FTP/Web%20Passwords,-Reset%20the%20password)")
        else:
            md_lines.append(f"- **Packet Monitor FTP:** Not configured")
    except Exception as e:
        print(f"Error generating Packet Monitor section: {e}")
        md_lines.append(f"- **Packet Monitor FTP:** Error retrieving information")

    # TSR/EXP Scheduled Exports
    try:
        if results.get('scheduled_exports_ftp_set', False):
            md_lines.append(f"- **TSR/EXP Scheduled Exports:** Configured")
            md_lines.append(f"  - Action: Update FTP server credentials")
            md_lines.append(f"  - Priority: Medium")
            md_lines.append(f"  - Reference: [TSR/EXP Scheduled Exports](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/Firmware_Settings/firmware-backup-configuring.htm)")
        else:
            md_lines.append(f"- **TSR/EXP Scheduled Exports:** Not configured")
    except Exception as e:
        print(f"Error generating Scheduled Exports section: {e}")
        md_lines.append(f"- **TSR/EXP Scheduled Exports:** Error retrieving information")

    # AppFlow SFR Mailing
    try:
        sfr_smtp = results.get('sfr_data', {}).get('smtp_configured', False)
        sfr_pop = results.get('sfr_data', {}).get('pop_configured', False)
        if sfr_smtp or sfr_pop:
            md_lines.append(f"- **AppFlow SFR Mailing:** Configured")
            md_lines.append(f"  - **Action:** Update email server credentials")
            md_lines.append(f"  - **Priority:** Low")
            md_lines.append(f"  - **Reference:** [AppFlow SFR Email Configuration](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-appflow_device/Content/appflow-d-flow-reporting-sfr-mailing.htm)")
            if sfr_smtp:
                md_lines.append(f"  - **SMTP Server:** Configured")
            if sfr_pop:
                md_lines.append(f"  - **POP3 Server:** Configured")
        else:
            md_lines.append(f"- **AppFlow SFR Mailing:** Not configured")
    except Exception as e:
        print(f"Error generating AppFlow SFR Mailing section: {e}")
        md_lines.append(f"- **AppFlow SFR Mailing:** Error retrieving information")

    md_lines.append(f"")
    md_lines.append(f"### Cloud & Integrations")
    md_lines.append(f"")

    # AWS API Logging
    try:
        aws_enabled = results.get('log', {}).get('aws', {}).get('enable', False)
        md_lines.append(f"- **AWS API Logging:** {'Enabled' if aws_enabled else 'Not Enabled'}")
        if aws_enabled:
            md_lines.append(f"  - **Action:** Update the AWS secret key on the AWS console and in SonicOS")
            md_lines.append(f"  - **Priority:** Critical")
            md_lines.append(f"  - **Reference:** [AWS Integration with SonicWall](https://www.sonicwall.com/support/knowledge-base/aws-integration-with-sonicwall-sonicos-6-5-x/181024232124532)")
    except Exception as e:
        print(f"Error processing AWS API logging: {e}")
        md_lines.append(f"- **AWS API Logging:** Error retrieving information")

    # Cloud Secure Edge
    try:
        cse_enabled = results.get('cloud_secure_edge', {}).get('created', False)
        md_lines.append(f"- **Cloud Secure Edge:** {'Enabled' if cse_enabled else 'Not Enabled'}")
        if cse_enabled:
            md_lines.append(f"  - **Action:** Reset Cloud Secure Edge connector authentication key")
            md_lines.append(f"  - **Priority:** Critical")
            md_lines.append(f"  - **Reference:** [Cloud Secure Edge](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_CSE)")
    except Exception as e:
        print(f"Error processing Cloud Secure Edge: {e}")
        md_lines.append(f"- **Cloud Secure Edge:** Error retrieving information")


    md_lines.append(f"")

    # Local Users
    md_lines.append(f"### Local User Management")
    md_lines.append(f"")

    # Actions taken on local users
    # Force Password Change
    try:
        # The key will only be present if force password change is disabled.
        if not results.get('force_password_change_disabled', False):
            md_lines.append(f"- **Force Password Change on Local Users:** Enabled")
            md_lines.append(f"   - **Action Taken:** All local users have been forced to update their password at next login")
            md_lines.append(f"   - **Priority:** Critical")
            md_lines.append(f"   - **Reference:** [Local User Password Change](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=for%20more%20information.-,Local%20Users,-Force%20a%20password)")
        else:
            md_lines.append(f"- **Force Password Change on Local Users:** Not Enabled")
            md_lines.append(f"   - **Action Taken:** None")
    except Exception as e:
        print(f"Error processing action taken on local users: {e}")
        md_lines.append(f"- **Action Taken on Local Users:** Error retrieving information")

    # Unbind TOTP
    try:
        # The key will only be present if TOTP unbind was disabled.
        if not results.get('totp_unbind_disabled', False) and results.get('totp_unbind_attempted', False):
            md_lines.append(f"- **Unbind TOTP from Local Users:** Enabled")
            md_lines.append(f"   - **Action Taken:** All TOTP tokens have been unbound from local users")
            md_lines.append(f"   - **Priority:** Critical")
            md_lines.append(f"   - **Reference:** [Local User TOTP Unbind](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=for%20more%20information.-,Local%20Users,-Unbind%20TOTP%20tokens)")
        else:
            md_lines.append(f"- **Unbind TOTP from Local Users:** Not Enabled")
            md_lines.append(f"   - **Action Taken:** None")
    except Exception as e:
        print(f"Error processing action taken on TOTP unbind: {e}")
        md_lines.append(f"- **Action Taken on TOTP Unbind:** Error retrieving information")

    md_lines.append(f"")

    # User Counts and Details
    try:
        md_lines.append(f"#### Statistics")
        total_users = results.get('total_user_count', 0)
        users_updated = results.get('total_users_forced_to_update_password', 0)
        users_skipped = results.get('skipped_user_count', 0)
        totp_unbind_attempted = results.get('totp_unbind_attempted', False)
        totp_unbind_successful_count = results.get('totp_unbind_successful_count', 0)
        totp_unbind_failed_count = results.get('totp_unbind_failed_count', 0)

        md_lines.append(f"- **Total Local Users:** {total_users}")
        md_lines.append(f"- **Users Updated:**")
        md_lines.append(f"  - **Forced Password Change:** {users_updated} successful, {users_skipped} skipped")
        md_lines.append(f"  - **Reset/Unbound TOTP:** {totp_unbind_successful_count} successful, {totp_unbind_failed_count} skipped or failed")
    except Exception as e:
        print(f"Error processing local users: {e}")
        md_lines.append(f"- **Local Users:** Error retrieving information")

    # Copies of the two lists to merge
    totp_unbind_results = results.get('totp_unbind_results', [])
    fpc_results = results.get('users', [])

    # Change some key named to avoid collision during merge
    for t in totp_unbind_results:
        t['totp_skipped'] = t.pop('skipped', False)
        t['totp_reason'] = t.pop('reason', None)
    totp_lookup = {t["name"]: t for t in totp_unbind_results}

    # Merges the two lists based on username
    user_list = [{**u, **totp_lookup.get(u["name"], {})} for u in fpc_results]

    try:
        if user_list:
            md_lines.append(f"")
            md_lines.append(f"#### User Details")
            md_lines.append(f"")
            md_lines.append(f"| Username | Force Password Change | Skipped Force Password Change | Reset/Unbind TOTP | Skipped TOTP Binding Reset | New Password |")
            md_lines.append(f"|----------|-----------------------|-------------------------------|-------------------|----------------------------|--------------|")
            for user in user_list:
                force_pass = "✅" if user.get('commit_successful') else "❌"
                skipped = "Yes" if user.get('skipped') else "No"
                unbound_totp = "✅" if user.get('totp_unbound', False) and not user.get('skipped', False) else ("❌" if user.get('totp_unbind_attempted') else "N/A")
                totp_skipped = "Yes" if user.get('totp_skipped', False) else "No"
                new_passwd = user.get('new_password', '')
                md_lines.append(f"| {user.get('name', 'Unknown')} | {force_pass} | {skipped} | {unbound_totp} | {totp_skipped} | {new_passwd} |")
    except Exception as e:
        print(f"Error generating user details table: {e}")

    return "\n".join(md_lines)


def print_and_save_summary(results: dict, firewall: str, firewall_info: dict, output_folder: str):
    """Print summary table to console and save markdown report to file."""
    try:
        if not a.no_summary:
            generate_summary_table(results)
    except Exception as e:
        print(f"Error printing summary table: {e}")

    try:
        # Generate and save markdown report
        md_content = generate_markdown_summary(results, firewall, firewall_info)

        dm = firewall_info['device_model'].replace(" ", "")
        sn = firewall_info['serial_number']
        md_filename = f"{output_folder}/{dm}-{sn}-summary.md"

        try:
            write_to_file(md_content, filename=md_filename)
            print(f"\n{generate_timestamp()}: Summary report saved to {md_filename}\n")
        except Exception as e:
            print(f"Error writing markdown summary to file: {e}")

    except Exception as e:
        raise
        print(f"Error generating markdown summary: {e}")


def finalize_routine(api_session, api_base: str, firewall: str, firewall_generation: int,
                    sshport: str, username: str, password: str, target_numbers: tuple, firewall_info: dict):
    """Finalize routine by cleaning up, writing results, and logging out."""
    # Sort results for consistency
    routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

    # Generate and print summary
    print_and_save_summary(routine_results[firewall], firewall, firewall_info, constants.START_TIMESTAMP_FOLDER)

    # Write results to file
    results_str = json.dumps(routine_results[firewall], indent=4)
    results_str = "\n" + results_str + "\n"

    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    write_to_file(results_str, filename=f"{constants.START_TIMESTAMP_FOLDER}/{dm}-{sn}-results.txt")

    # Disable auto-enabled SonicOS API if needed
    if constants.get_autoenabled_sonicos_api():
        disable_sonicos_api_ssh(firewall, sshport, username, password)

    # Logout from session
    try:
        logout(api_base, api_session, firewall_generation=firewall_generation)
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error logging out: {e}")


# The routine function will get the list of users, update the force password reset flag, and commit the changes.
def routine(target: FirewallTarget, target_numbers=None, silent=False, **kwargs):
    """
    Main routine - now refactored into smaller, focused functions.

    Args:
        target (FirewallTarget): The firewall target configuration object
        target_numbers (tuple): Current/total target numbers (default: None)
        silent (bool): If True, suppresses non-essential output (default: False)
        **kwargs: Additional optional parameters that can override target settings
    """
    # Extract parameters from the target object, with kwargs as overrides
    firewall = target.firewall
    username = kwargs.get('username', target.username)
    password = kwargs.get('password', target.password)
    sshport = kwargs.get('sshport', target.sshport)
    temp_password = kwargs.get('temp_password', target.temp_password)
    randomize_temp_password = kwargs.get('randomize_temp_password', target.randomize_temp_password)
    unbind_totp = kwargs.get('unbind_totp', target.unbind_totp)
    force_password_change = kwargs.get('force_password_change', target.force_password_change)

    # Reset auto-enabled SonicOS API flag for each new firewall
    if constants.get_autoenabled_sonicos_api() is True:
        constants.set_autoenabled_sonicos_api(False)

    # Initialize routine results
    routine_results[firewall] = {
        'api_base': f"https://{firewall}" if "https://" not in firewall else firewall,
        'api_session_successful': False,
        'firewall_generation': None,
        'firmware_version': None,
        'device_model': None,
        'serial_number': None
    }

    if sshport == "no":
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: SSH logic is disabled.")
        routine_results[firewall]['ssh_logic_disabled'] = True

    # Print verbose details if enabled
    print_verbose_details(target, target_numbers, a, username=username, password=password,
                         sshport=sshport, temp_password=temp_password, randomize_temp_password=randomize_temp_password, unbind_totp=unbind_totp)

    # Initialize session with the firewall
    api_session, return_msg, api_base, username, password = initialize_session(
        target, target_numbers, username=username, password=password, sshport=sshport)

    if api_session is None or api_session is False:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: Unable to create an admin session. Return message: {return_msg}")

        # Write error results and return
        routine_results[firewall] = dict(sorted(routine_results[firewall].items()))
        results_str = json.dumps(routine_results[firewall], indent=4)
        write_to_file(f"\n{results_str}\n", filename=f"{constants.START_TIMESTAMP_FOLDER}/{target_numbers[0]}results.txt")
        return False, return_msg

    # Update session status
    if isinstance(api_session, Login):
        routine_results[firewall]['api_session_successful'] = False
        routine_results[firewall]['alternate_session_successful'] = True
    else:
        routine_results[firewall]['api_session_successful'] = True

    # Gather firewall information
    firewall_info, error_msg = gather_firewall_info(api_session, api_base, target_numbers, silent=silent)
    if firewall_info is None:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error gathering firewall information: {error_msg}")
        return False, f"Error gathering firewall information: {error_msg}"

    # Update routine results with firewall information
    update_routine_results(routine_results, firewall, 'firewall_info', firewall_info)

    # Export operations (if enabled)
    tsr_result = export_tsr_if_enabled(api_session, api_base, a, target_numbers, firewall_info, silent=silent)
    update_routine_results(routine_results, firewall, 'tsr_result', tsr_result)
    if not silent:
        print()

    tracelog_result = export_tracelogs_if_enabled(api_session, api_base, a, target_numbers, firewall_info, silent=silent)
    update_routine_results(routine_results, firewall, 'tracelog_result', tracelog_result)
    if not silent:
        print()

    settings_result = export_settings_if_enabled(api_session, api_base, a, target_numbers,
                                                firewall_info, username, password, silent=silent)
    update_routine_results(routine_results, firewall, 'settings_result', settings_result)
    if not silent:
        print()

    # Remediation Playbook -- Checks the items in this KB article:
    # https://www.sonicwall.com/support/knowledge-base/remediation-playbook/250916130050523
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Starting Remediation Playbook checks...")

    # List LDAP servers
    try:
        ldap_servers = get_request(api_base, api_session, '/api/sonicos/user/ldap/servers', silent=silent)
        ldap_count = 0
        if ldap_servers:
            try:
                ldap_key = ldap_servers['user']['ldap']
                if isinstance(ldap_key, dict):
                    ldap_key = ldap_key.get('server', {})
                    if ldap_key == {}:
                        ldap_count = 0
                    elif isinstance(ldap_key, list):
                        ldap_count = len(ldap_key)
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining LDAP server count.")
                print(type(ldap_servers), "->", ldap_servers)
                print("-----------------------")

            if ldap_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ldap_count} LDAP servers configured.")
                ldap_servers = ldap_servers['user']['ldap']['server']
                if not silent:
                    print("LDAP Servers:")
                for server in ldap_servers:
                    server_host = server.get('host', '')
                    server_status = server.get('enable', '')
                    primary_domain = server.get('directory', {}).get('primary_domain', '')
                    primary_role = server.get('role', {}).get('primary', False)
                    secondary_role = server.get('role', {}).get('secondary', False)
                    backup_role = server.get('role', {}).get('backup', False)
                    server_role = 'primary role' if primary_role else 'secondary role' if secondary_role else 'backup' if backup_role else 'unknown'
                    backup_for = server.get('backup_for')
                    if backup_for:
                        server_role += f" for {backup_for}"
                    if not silent:
                        print(f"  - {server_host}, {server_role}: Status: {'enabled' if server_status else 'disabled'}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No LDAP servers found.")

            update_routine_results(routine_results, firewall, 'ldap_servers', ldap_servers)

        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No LDAP servers found")
                print(type(ldap_servers), "->", ldap_servers)
                print("-----------------------")
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving LDAP servers: {e}")

    if not silent:
        print()

    # List RADIUS servers
    try:
        radius_servers = get_request(api_base, api_session, '/api/sonicos/user/radius/servers', silent=silent)
        radius_count = 0
        if radius_servers:
            try:
                radius_key = radius_servers['user']['radius']
                if isinstance(radius_key, dict):
                    radius_key = radius_key.get('server', {})
                    if radius_key == {}:
                        radius_count = 0
                    elif isinstance(radius_key, list):
                        radius_count = len(radius_key)
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining RADIUS server count.")
                if not silent:
                    print(type(radius_servers), "->", radius_servers)
                    print("-----------------------")

            if radius_count > 0:
                radius_servers = radius_servers['user']['radius']['server']
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {radius_count} RADIUS servers configured.")
                    print("RADIUS Servers:")
                for server in radius_servers:
                    server_host = server.get('host', '')
                    server_port = server.get('port', '')
                    server_status = server.get('enable', '')
                    if not silent:
                        print(f"  - {server_host}, port {server_port}: Status: {'enabled' if server_status else 'disabled'}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS servers found.")

            update_routine_results(routine_results, firewall, 'radius_servers', radius_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS servers found")
            print(type(radius_servers), "->", radius_servers)
            print("-----------------------")
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving RADIUS servers: {e}")

    if not silent:
        print()

    # List TACACS servers
    # TODO: Investigate what to do with GEN6. API endpoint does not exist or is wrong. Says endpoing is incomplete.
    # TODO: VPN response needs to be handled for GEN6. I assume there is an API endpoint for it.
    # TODO: Dynamic DNS gets an empty dict on GEN6. Need to make sure that NOT having something configured is handled properly.
    # TODO: SNMPv3 users are available on GEN6. API endpoint may not exist.... says incomplete.
    # TODO: dynamic address object on GEN6. Says API not found.
    # TODO: Packet monitor info on GEN6. Says nonetype object does not support item assignment. Need to review response.
    try:
        tacacs_servers = get_request(api_base, api_session, '/api/sonicos/user/tacacs/servers', silent=silent)
        tacacs_count = 0
        if tacacs_servers:
            try:
                tacacs_key = tacacs_servers['user']['tacacs']
                if isinstance(tacacs_key, dict):
                    tacacs_key = tacacs_key.get('server', {})
                    if tacacs_key == {}:
                        tacacs_count = 0
                    elif isinstance(tacacs_key, list):
                        tacacs_count = len(tacacs_key)
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining TACACS server count.")
                    print(type(tacacs_servers), "->", tacacs_servers)
                    print()

            if tacacs_count > 0:
                tacacs_servers = tacacs_servers['user']['tacacs']['server']
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {tacacs_count} TACACS servers configured.")
                    print("TACACS Servers:")
                for server in tacacs_servers:
                    server_host = server.get('host', '')
                    server_port = server.get('port', '')
                    server_status = server.get('enable', '')
                    if not silent:
                        print(f"  - {server_host}, port {server_port}: Status: {'enabled' if server_status else 'disabled'}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS servers found.")

            update_routine_results(routine_results, firewall, 'tacacs_servers', tacacs_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS servers found")
            print(type(tacacs_servers), "->", tacacs_servers)
            print("-----------------------")
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving TACACS servers: {e}")

    if not silent:
        print()

    # List VPN policies
    try:
        vpn_policies = get_request(api_base, api_session, '/api/sonicos/vpn/policies/all', silent=silent)
        vpn_policy_count = 0
        if vpn_policies:
            try:
                vpn_key = vpn_policies['vpn']
                if isinstance(vpn_key, dict):
                    vpn_key = vpn_key.get('policy', {})
                    if vpn_key == {}:
                        vpn_policy_count = 0
                    elif isinstance(vpn_key, list):
                        vpn_policy_count = len(vpn_key)
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining VPN policy count.")
                    print(type(vpn_policies), "->", vpn_policies)
                    print()

            if vpn_policy_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vpn_policy_count} VPN policies configured.")
                    print("VPN Policies:")
                for policy in vpn_policies['vpn'].get('policy', []):
                    policy_name = policy.get('ipv4', {}).get('group_vpn', {}).get('name') or policy.get('ipv4', {}).get('site_to_site', {}).get('name') or policy.get('ipv4', {}).get('tunnel_interface', {}).get('name')
                    policy_status = policy.get('ipv4', {}).get('group_vpn', {}).get('enable', False) or policy.get('ipv4', {}).get('site_to_site', {}).get('enable', False) or policy.get('ipv4', {}).get('tunnel_interface', {}).get('enable', False)
                    if not silent:
                        print(f"  - {policy_name}: {'enabled' if policy_status else 'disabled'}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No VPN policies found.")

            update_routine_results(routine_results, firewall, 'vpn', vpn_policies)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No VPN policies found")
                print(type(vpn_policies), "->", vpn_policies)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving VPN policies: {e}")

    if not silent:
        print()

    # List WAN interfaces (check for L2TP/PPTP/PPPoE/WWAN)
    try:
        interfaces = get_request(api_base, api_session, '/api/sonicos/interfaces/ipv4', silent=silent)
        if interfaces:
            wan_interfaces = []
            wan_list = []
            for intf in interfaces.get('interfaces', []):
                if intf.get('ipv4', {}).get('ip_assignment', {}).get('zone', '') == 'WAN':
                    wan_interfaces.append(intf)

            if len(wan_interfaces) > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {len(wan_interfaces)} WAN interfaces configured.")
                    print("WAN Interfaces:")
                for intf in wan_interfaces:
                    intf_name = intf.get('ipv4', {}).get('name', '')
                    intf_mode = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', None)
                    pppoe = False
                    pptp = False
                    l2tp = False
                    dhcp = False
                    static = False
                    if intf_mode:
                        pppoe = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('pppoe', False)
                        pptp = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('pptp', False)
                        l2tp = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('l2tp', False)
                        dhcp = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('dhcp', False)
                        static = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('static', False)
                    intf_type = 'PPPoE' if pppoe else 'PPTP' if pptp else 'L2TP' if l2tp else 'DHCP' if dhcp else 'Static' if static else intf_mode

                    if intf_type != 'Static' and intf_type != 'DHCP':
                        wan_list.append(intf_name)
                        if not silent:
                            print(f"  - {intf_name} ({intf_type})")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No WAN interfaces found.")

            wan_interfaces = {"interesting_wan_list": wan_list, "wan_interfaces": wan_interfaces}
            update_routine_results(routine_results, firewall, 'wan_interfaces', wan_interfaces)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No interfaces found")
                print(type(interfaces), "->", interfaces)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving interfaces: {e}")

    if not silent:
        print()

    # Check AWS API status (log/aws)
    try:
        aws_api = get_request(api_base, api_session, '/api/sonicos/log/aws', silent=silent)
        if aws_api:
            aws_enabled = aws_api.get('log', {}).get('aws', {}).get('enable', False)
            if aws_enabled:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AWS API is enabled. Please update the secret key.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AWS API is not enabled.")

            update_routine_results(routine_results, firewall, 'aws_api', aws_api)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No AWS API information found")
                print(type(aws_api), "->", aws_api)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving AWS API information: {e}")

    if not silent:
        print()

    # List dynamic DNS services
    try:
        ddns_services_v4 = get_request(api_base, api_session, '/api/sonicos/dynamic-dns/profiles/ipv4', silent=silent)
        # print(ddns_services_v4)
        ddns_count = 0
        if ddns_services_v4:
            try:
                ddns_key = ddns_services_v4.get('dynamic_dnss', None) or ddns_services_v4.get('dynamic_dns', None)
                if isinstance(ddns_key, list):
                    ddns_count = len(ddns_key)
                    ddns_services_v4 = ddns_key
                elif isinstance(ddns_key, dict):
                    ddns_key = ddns_key.get('profile', {})
                    if ddns_key == {}:
                        ddns_count = 0
                elif ddns_key is None:
                    ddns_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining IPv4 dynamic DNS service count.")
                    print(type(ddns_services_v4), "->", ddns_services_v4)
                    print()

            if ddns_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ddns_count} IPv4 dynamic DNS services configured.")
                    print("IPv4 Dynamic DNS Services:")
                for service in ddns_services_v4:
                    service_name = service.get('profile', {}).get('ipv4', {}).get('profile_name', '')
                    service_provider = service.get('profile', {}).get('ipv4', {}).get('provider', '')
                    service_status = service.get('profile', {}).get('ipv4', {}).get('enable', False)
                    service_domain = service.get('profile', {}).get('ipv4', {}).get('domain', '')
                    if not silent:
                        print(f"  - Profile Name: {service_name}, Domain: {service_domain}, Provider: {service_provider}: {'enabled' if service_status else 'disabled'}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv4 dynamic DNS services found.")

            update_routine_results(routine_results, firewall, 'ddns_services_v4', ddns_services_v4)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv4 dynamic DNS services found")
                print(type(ddns_services_v4), "->", ddns_services_v4)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving IPv4 dynamic DNS services: {e}")

    try:
        ddns_services_v6 = get_request(api_base, api_session, '/api/sonicos/dynamic-dns/profiles/ipv6', silent=silent)
        # print(ddns_services_v6)
        ddns_count = 0
        if ddns_services_v6:
            try:
                ddns_key = ddns_services_v6.get('dynamic_dnss', None) or ddns_services_v6.get('dynamic_dns', None)
                if isinstance(ddns_key, list):
                    ddns_count = len(ddns_key)
                    ddns_services_v6 = ddns_key
                elif isinstance(ddns_key, dict):
                    ddns_key = ddns_key.get('profile', {})
                    if ddns_key == {}:
                        ddns_count = 0
                elif ddns_key is None:
                    ddns_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining IPv6 dynamic DNS service count.")
                    print(type(ddns_services_v6), "->", ddns_services_v6)
                    print()

            if ddns_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ddns_count} IPv6 dynamic DNS services configured.")
                    print("IPv6 Dynamic DNS Services:")
                for service in ddns_services_v6:
                    service_name = service.get('profile', {}).get('ipv6', {}).get('profile_name', '')
                    service_provider = service.get('profile', {}).get('ipv6', {}).get('provider', '')
                    service_status = service.get('profile', {}).get('ipv6', {}).get('enable', False)
                    service_domain = service.get('profile', {}).get('ipv6', {}).get('domain', '')
                    if not silent:
                        print(f"  - Profile Name: {service_name}, Domain: {service_domain}, Provider: {service_provider}: {'enabled' if service_status else 'disabled'}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv6 dynamic DNS services found.")

            update_routine_results(routine_results, firewall, 'ddns_services_v6', ddns_services_v6)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv6 dynamic DNS services found")
                print(type(ddns_services_v6), "->", ddns_services_v6)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving IPv6 dynamic DNS services: {e}")

    if not silent:
        print()

    # Check Clearpass/NAC status
    try:
        clearpass_base = get_request(api_base, api_session, '/api/sonicos/network-access-control/clearpass/base', silent=silent)
        if clearpass_base:
            clearpass_enabled = clearpass_base.get('network_access_control', {}).get('clearpass', {}).get('enable', False)
            if clearpass_enabled:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is enabled. Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is not enabled.")
            clearpass_base['clearpass_enabled'] = clearpass_enabled
            update_routine_results(routine_results, firewall, 'clearpass_base', clearpass_base)

        clearpass_servers = get_request(api_base, api_session, '/api/sonicos/network-access-control/clearpass/servers', silent=silent)
        cp_servers = []
        if clearpass_servers:
            if not silent:
                print("Clearpass/NAC Servers:")
            for server in clearpass_servers.get('network_access_control', {}).get('clearpass', {}).get('server', []):
                server_host = server.get('name', '')
                server_port = server.get('port', '')
                cp_servers.append(server_host)
                if not silent:
                    print(f"  - {server_host}, port {server_port}")
            clearpass_servers['clearpass_servers'] = cp_servers
            update_routine_results(routine_results, firewall, 'clearpass_servers', clearpass_servers)
        elif not clearpass_servers:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is enabled but no servers found.")
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Clearpass/NAC information: {e}")

    if not silent:
        print()

    # List SNMPv3 users
    try:
        snmpv3_users = get_request(api_base, api_session, '/api/sonicos/snmp/users', silent=silent)
        snmpv3_user_count = 0
        if snmpv3_users:
            try:
                snmpv3_key = snmpv3_users['snmp']
                if isinstance(snmpv3_key, dict):
                    snmpv3_key = snmpv3_key.get('user', {})
                    if snmpv3_key == {}:
                        snmpv3_user_count = 0
                    elif isinstance(snmpv3_key, list):
                        snmpv3_user_count = len(snmpv3_key)
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SNMP user count.")
                    print(type(snmpv3_users), "->", snmpv3_users)
                    print()

            if snmpv3_user_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {snmpv3_user_count} SNMP users configured.")
                    print("SNMPv3 Users:")
                for user in snmpv3_users['snmp'].get('user', []):
                    user_name = user.get('name', '')
                    user_level = user.get('security_level', {}).get('authentication_only', None) or user.get('security_level', {}).get('authentication_and_privacy', None) or None
                    user_level_key = list(user.get('security_level', {}).keys())
                    user_level_key = user_level_key[0] if user_level_key else None
                    if not silent:
                        print(f"  - {user_name}, Security Level: {user_level_key if user_level else None}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SNMP users found.")

            update_routine_results(routine_results, firewall, 'snmp_users', snmpv3_users)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SNMP users found")
                print(type(snmpv3_users), "->", snmpv3_users)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SNMP users: {e}")

    if not silent:
        print()

    # Cloud Secure Edge (CSE)
    try:
        cse_info = get_request(api_base, api_session, '/api/sonicos/cloud-secure-edge/base', silent=silent)
        if cse_info:
            cse_enabled = cse_info.get('cloud_secure_edge', {}).get('created', False)
            if cse_enabled:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is enabled. Reset the Cloud Secure Edge connector authentication key.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is not enabled.")

            update_routine_results(routine_results, firewall, 'cse_info', cse_info)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No CSE information found")
                print(type(cse_info), "->", cse_info)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving CSE information: {e}")

    if not silent:
        print()

    # Email Logging
    try:
        email_logging = get_request(api_base, api_session, '/api/sonicos/log/automation', silent=silent)
        if email_logging:
            mail_server = email_logging.get('log', {}).get('automation', {}).get('mail_server', None)
            authentication_method = email_logging.get('log', {}).get('automation', {}).get('authentication_method', None)
            pop3_server = email_logging.get('log', {}).get('automation', {}).get('pop3_server', None)
            pop3_username = email_logging.get('log', {}).get('automation', {}).get('pop3_user_name', None)
            pop3_password = email_logging.get('log', {}).get('automation', {}).get('pop3_user_name', None)
            smtp_user = email_logging.get('log', {}).get('automation', {}).get('mail_server_advanced', {}).get('user_name', None)
            smtp_password = email_logging.get('log', {}).get('automation', {}).get('mail_server_advanced', {}).get('password', None)
            ftp_logging = email_logging.get('log', {}).get('automation', {}).get('ftp_log', {})
            ftp_server = ftp_logging.get('server', None)
            ftp_username = ftp_logging.get('user_name', None)
            ftp_password = ftp_logging.get('password', None)
            email_logging_data = {
                'mail_server': mail_server,
                'authentication_method': authentication_method,
                'pop3_server': pop3_server,
                'pop3_username': pop3_username,
                'pop3_password_set': bool(pop3_password),
                'smtp_user': smtp_user,
                'smtp_password_set': bool(smtp_password),
                'ftp_server': ftp_server,
                'ftp_username': ftp_username,
                'ftp_password_set': bool(ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None)
            }

            if pop3_password or smtp_password or (ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None):
                if not silent:
                    print("Log Automation:")
            if pop3_password:
                email_logging_data['pop3_flag'] = True
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: POP3 password is set for {pop3_username}@{pop3_server}. Please update the account's password, then update it in SonicOS.")

            if smtp_password:
                email_logging_data['smtp_flag'] = True
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: SMTP password is set for {smtp_user}@{mail_server}. Please update the account's password, then update it in SonicOS.")

            if ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None:
                email_logging_data['ftp_flag'] = True
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")

            email_logging = {'log_automation_data': email_logging_data, 'log_automation_json': email_logging}
            update_routine_results(routine_results, firewall, 'email_logging', email_logging)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No log automation information found")
                print(type(email_logging), "->", email_logging)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving log automation information: {e}")

    if not silent:
        print()

    # Packet Monitor FTP Logging.
    try:
        pktmon_settings = get_request(api_base, api_session, '/api/sonicos/packet-monitor/base', silent=silent)
        pkmon_flag = False
        if pktmon_settings:
            pktmon_ftp = pktmon_settings.get('packet_monitor', {}).get('ftp', None)
            if pktmon_ftp:
                ftp_server = pktmon_ftp.get('server', None)
                ftp_username = pktmon_ftp.get('login', None)
                ftp_password = pktmon_ftp.get('password', None)

                if ftp_password and ftp_server != "0.0.0.0" and ftp_server != "" and ftp_server is not None:
                    pkmon_flag = True
                    if not silent:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Packet Monitor FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Could not retrieve the Packet Monitor FTP settings.")
            pktmon_ftp['packet_monitor_ftp_set'] = pkmon_flag
            update_routine_results(routine_results, firewall, 'packetmonitor_ftp', pktmon_ftp)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Packet Monitor information found")
                print(type(pktmon_settings), "->", pktmon_settings)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Packet Monitor information: {e}")

    if not silent:
        print()

    # Settings/TSR scheduled exports
    try:
        scheduled_exports = get_request(api_base, api_session, '/api/sonicos/ftp/base', silent=silent)
        scheduled_exports_flag = False
        if scheduled_exports:
            ftp_server = scheduled_exports.get('server', None)
            ftp_username = scheduled_exports.get('user', None)
            ftp_password = scheduled_exports.get('password', None)

            if ftp_password and ftp_server != "0.0.0.0" and ftp_server != "" and ftp_server is not None:
                scheduled_exports_flag = True
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings/TSR scheduled export FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")
            scheduled_exports['scheduled_exports_ftp_set'] = scheduled_exports_flag
            update_routine_results(routine_results, firewall, 'scheduled_exports', scheduled_exports)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No settings/TSR scheduled exports information found")
                print(type(scheduled_exports), "->", scheduled_exports)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving settings/TSR scheduled exports information: {e}")

    if not silent:
        print()

    # Dynamic External Address Objects
    try:
        dynamic_address_objects = get_request(api_base, api_session, '/api/sonicos/dynamic-external-objects', silent=silent)
        # print(dynamic_address_objects)
        deao_data = []
        if dynamic_address_objects:
            dynamic_object_count = 0
            try:
                dynamic_key = dynamic_address_objects['dynamic_external_objects']
                if isinstance(dynamic_key, dict):
                    dynamic_key = dynamic_key.get('dynamic_external_objects', {})
                    if dynamic_key == {}:
                        dynamic_object_count = 0
                elif isinstance(dynamic_key, list):
                    dynamic_object_count = len(dynamic_key)
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining dynamic address object count.")
                    print(type(dynamic_address_objects), "->", dynamic_address_objects)
                    print()

            if dynamic_object_count > 0:
                dynamic_address_objects['dynamic_ao_count'] = dynamic_object_count
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {dynamic_object_count} dynamic address objects configured.")
                    print("Dynamic Address Objects:")
                for obj in dynamic_address_objects.get('dynamic_external_objects', []):
                    obj_name = obj.get('name', '')
                    obj_protocol = obj.get('protocol', '')
                    obj_server = obj.get('server', {}).get('value', '')
                    obj_username = obj.get('login', '')
                    obj_url = obj.get('url', '')
                    deao_entry = {
                        'name': obj_name,
                        'protocol': obj_protocol,
                        'server': obj_server,
                        'username': obj_username,
                        'url': obj_url
                    }
                    deao_data.append(deao_entry)
                    if obj_protocol == 'https':
                        if not silent:
                            print(f"  - {obj_name}: Protocol: {obj_protocol}, URL: {obj_url}")
                    elif obj_protocol == 'ftp':
                        if not silent:
                            print(f"  - {obj_name}: Protocol: {obj_protocol}, Server: {obj_server}, Username: {obj_username}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No dynamic address objects found.")

            dynamic_address_objects['dynamic_ao_data'] = deao_data
            update_routine_results(routine_results, firewall, 'dynamic_address_objects', dynamic_address_objects)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No dynamic address objects found")
                print(type(dynamic_address_objects), "->", dynamic_address_objects)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving dynamic address objects: {e}")

    if not silent:
        print()

    # Dynamic Botnet List
    try:
        dynamic_botnet_list = get_request(api_base, api_session, '/api/sonicos/botnet/base', silent=silent)
        # print(dynamic_botnet_list)
        dynamic_botnet_data = {}
        if dynamic_botnet_list:
            botnet_dynlist_enabled = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('enable', False)
            botnet_dynlist_protocol = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('protocol', None)
            botnet_dynlist_ftp_server = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp', {}).get('server_ip_address', None)
            botnet_dynlist_ftp_username = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp', {}).get('login', None)
            botnet_dynlist_ftp_password = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp', {}).get('password', None)
            botnet_dynlist_https_username = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('https', {}).get('login', None)
            botnet_dynlist_https_password = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('https', {}).get('password', None)
            botnet_dynlist_https_url = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('https', {}).get('url_name', None)
            dynamic_botnet_data = {
                'enabled': botnet_dynlist_enabled,
                'protocol': botnet_dynlist_protocol,
                'ftp_server': botnet_dynlist_ftp_server,
                'ftp_username': botnet_dynlist_ftp_username,
                'ftp_password_set': bool(botnet_dynlist_ftp_password),
                'https_url': botnet_dynlist_https_url,
                'https_username': botnet_dynlist_https_username,
                'https_password_set': bool(botnet_dynlist_https_password)
            }
            if botnet_dynlist_protocol == 'ftp':
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: A Dynamic Botnet List Server is configured. Protocol: {botnet_dynlist_protocol}, {botnet_dynlist_ftp_username}@{botnet_dynlist_ftp_server}. Please update the password on the server, then update it in SonicOS.")
            elif botnet_dynlist_protocol == 'https':
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: A Dynamic Botnet List Server is configured. Protocol: {botnet_dynlist_protocol}, URL: {botnet_dynlist_https_url}, Login: {botnet_dynlist_https_username}. Please update the password on the server, then update it in SonicOS.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Dynamic Botnet List Server is not configured.")

            dynamic_botnet_list = {'botnet': dynamic_botnet_list, 'botnet_data': dynamic_botnet_data}
            update_routine_results(routine_results, firewall, 'dynamic_botnet_list_server', dynamic_botnet_list)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No dynamic botnet list information found")
                print(type(dynamic_botnet_list), "->", dynamic_botnet_list)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving dynamic botnet list information: {e}")

    if not silent:
        print()

    # Extended Switches
    try:
        ext_switches = get_request(api_base, api_session, '/api/sonicos/switch-controller/switch-info', silent=silent)
        if ext_switches:
            ext_switch_count = 0
            try:
                ext_switch_key = ext_switches.get('switch_controller', {}).get('switch_info', {})
                if isinstance(ext_switch_key, list):
                    ext_switch_count = len(ext_switch_key)
                elif isinstance(ext_switch_key, dict) and ext_switch_count == {}:
                    ext_switch_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining extended switch count.")
                    print(type(ext_switches), "->", ext_switches)
                    print()

            if ext_switch_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ext_switch_count} extended switches configured.")
                    print("Extended Switches:")
                for switch in ext_switches.get('switch_controller', {}).get('switch_info', []):
                    switch_id = switch.get('id', None)
                    switch_name = switch.get('name', '')
                    switch_serial = switch.get('serial', '')
                    if switch_id:
                        if not silent:
                            print(f"  - {switch_name} ({switch_serial})")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switches found.")

            update_routine_results(routine_results, firewall, 'extended_switches', ext_switches)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switches found")
                print(type(ext_switches), "->", ext_switches)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switches: {e}")

    if not silent:
        print()

    # Extended Switches - Users
    try:
        switch_users = get_request(api_base, api_session, '/api/sonicos/switch-controller/user', silent=silent)
        if switch_users:
            switch_user_count = 0
            try:
                switch_user_key = switch_users.get('switch_controller', {}).get('user', {})
                if isinstance(switch_user_key, list):
                    switch_user_count = len(switch_user_key)
                elif isinstance(switch_user_key, dict) and switch_user_key == {}:
                    switch_user_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining extended switch user count.")
                    print(type(switch_users), "->", switch_users)
                    print()

            if switch_user_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {switch_user_count} extended switch users configured.")
                    print("Extended Switch Users:")
                for user in switch_users.get('switch_controller', {}).get('user', []):
                    user_name = user.get('user_name', '')
                    user_switch = user.get('switch', '')
                    user_priv = user.get('privilege_type', '')
                    if not silent:
                        print(f"  - {user_name} on switch {user_switch}, Privilege: {user_priv}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch users found.")

            update_routine_results(routine_results, firewall, 'extended_switch_users', switch_users)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch users found")
                print(type(switch_users), "->", switch_users)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switch users: {e}")

    if not silent:
        print()

    # Extended Switches - RADIUS Servers
    try:
        switch_radius = get_request(api_base, api_session, '/api/sonicos/switch-controller/radius', silent=silent)
        if switch_radius:
            switch_radius_count = 0
            try:
                switch_radius_key = switch_radius.get('switch_controller', {}).get('radius', {})
                if isinstance(switch_radius_key, list):
                    switch_radius_count = len(switch_radius_key)
                elif isinstance(switch_radius_key, dict) and switch_radius_key == {}:
                    switch_radius_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining extended switch RADIUS server count.")
                    print(type(switch_radius), "->", switch_radius)
                    print()

            if switch_radius_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {switch_radius_count} extended switch RADIUS servers configured.")
                    print("Extended Switch RADIUS Servers:")
                for server in switch_radius.get('switch_controller', {}).get('radius', []):
                    server_ip = server.get('server_ip', '')
                    server_switch = server.get('switch', '')
                    if not silent:
                        print(f"  - {server_ip} a {server_switch}")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch RADIUS servers found.")

            update_routine_results(routine_results, firewall, 'extended_switch_radius_servers', switch_radius)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch RADIUS servers found")
                print(type(switch_radius), "->", switch_radius)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switch RADIUS servers: {e}")

    if not silent:
        print()

    # Zone Objects: WLAN RADIUS Server
    try:
        all_zone_objects = get_request(api_base, api_session, '/api/sonicos/zones', silent=silent)
        zone_objects = [z for z in all_zone_objects.get('zones', []) if z.get('security_type', '').lower() == 'wireless']
        if zone_objects:
            zone_data = []
            if len(zone_objects) > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: WLAN Local RADIUS Server:")
            try:
                for zone in zone_objects:
                    if zone.get('security_type', '').lower() == 'wireless':
                        radius_server_enabled = zone.get('local_radius_server', {}).get('enable', False)
                        ldap_server_enabled = zone.get('local_radius_server', {}).get('ldap_server', {}).get('enable', False)
                        ldap_server_host = zone.get('local_radius_server', {}).get('ldap_server', {}).get('server', None)
                        zone_data_entry = {'zone': zone.get('name', ''),
                                           'radius_server_enabled': radius_server_enabled,
                                           'ldap_server_enabled': ldap_server_enabled,
                                           'ldap_server_host': ldap_server_host
                                           }
                        if radius_server_enabled:
                            if not silent:
                                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}:  - Local RADIUS server is enabled on Zone {zone.get('name', '')}. Please update the RADIUS server client password.")
                        if ldap_server_enabled or ldap_server_host:
                            if not silent:
                                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}:  - LDAP server is enabled on Zone {zone.get('name', '')}, Host: {ldap_server_host}. Please update the LDAP server password, then update it in SonicOS.")
                        zone_data.append(zone_data_entry)
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving WLAN RADIUS Server configuration from zone objects.")
                print(type(zone_objects), "->", zone_objects)
                print()

            zone_objects = {'wlan_radius_servers': zone_objects, 'wlan_zone_data': zone_data}
            update_routine_results(routine_results, firewall, 'wlan_radius_servers', zone_objects)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No zone objects found")
                print(type(zone_objects), "->", zone_objects)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving zone objects: {e}")

    if not silent:
        print()

    # Guest Services External Guest Authentication (Message Authentication)
    # This flags when the Message Authentication option is enabled under Guest Services > External Guest Authentication
    try:
        guest_zones = [z for z in all_zone_objects.get('zones', []) if z.get('guest_services', {}).get('external_auth', {}).get('message_auth', {}).get('enable', False)]
        if guest_zones:
            guest_zone_data = []
            if len(guest_zones) > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Guest Services External Guest Authentication (Message Authentication):")
            try:
                for zone in guest_zones:
                    guest_auth_ext_enabled = zone.get('guest_services', {}).get('external_auth', {}).get('message_auth', {}).get('enable', False)
                    guest_zone_data_entry = {'zone': zone.get('name', ''), 'guest_auth_ext_enabled': guest_auth_ext_enabled}
                    guest_zone_data.append(guest_zone_data_entry)
                    if guest_auth_ext_enabled:
                        if not silent:
                            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}:  - External Guest Authentication is enabled on Zone {zone.get('name', '')}. Please update the message authentication shared secret.")
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Guest Services External Guest Authentication configuration from zone objects.")
                    print(type(guest_zones), "->", guest_zones)
                    print()

            guest_zones = {'guest_services_external_auth': guest_zones, 'guest_zone_data': guest_zone_data}
            update_routine_results(routine_results, firewall, 'guest_services_external_auth', guest_zones)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No zone objects with Guest Services External Guest Authentication found")
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving zone objects for Guest Services: {e}")

    if not silent:
        print()

    # SSO Agents
    try:
        sso_agents = get_request(api_base, api_session, '/api/sonicos/user/sso/agents', silent=silent)
        if sso_agents:
            sso_agent_count = 0
            try:
                sso_agent_key = sso_agents.get('user', {}).get('sso', {}).get('agent', {})
                if isinstance(sso_agent_key, list):
                    sso_agent_count = len(sso_agent_key)
                elif isinstance(sso_agent_key, dict) and sso_agent_key == {}:
                    sso_agent_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SSO agent count.")
                    print(type(sso_agents), "->", sso_agents)
                    print()

            if sso_agent_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sso_agent_count} SSO Agent(s) configured.")
                    print("SSO Agents:")
                for agent in sso_agents.get('user', {}).get('sso', {}).get('agent', []):
                    agent_status = agent.get('enable', '')
                    agent_host = agent.get('host', '')
                    agent_port = agent.get('port', '')
                    agent_shared_secret = agent.get('shared_key', None)
                    if agent_shared_secret:
                        if not silent:
                            print(f"  - {agent_host}, port {agent_port} ({'enabled' if agent_status else 'disabled'}): Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO agents found.")

            sso_agents = {'sso_agents': sso_agents}
            update_routine_results(routine_results, firewall, 'sso_agents', sso_agents)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO Agents found")
                print(type(sso_agents), "->", sso_agents)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO Agents: {e}")

    if not silent:
        print()

    # Terminal Server Agent (TSA)
    try:
        ts_agents = get_request(api_base, api_session, '/api/sonicos/user/sso/terminal-services-agents', silent=silent)
        if ts_agents:
            ts_agent_count = 0
            try:
                ts_agent_key = ts_agents.get('user', {}).get('sso', {}).get('terminal_services_agent', {})
                if isinstance(ts_agent_key, list):
                    ts_agent_count = len(ts_agent_key)
                elif isinstance(ts_agent_key, dict) and ts_agent_key == {}:
                    ts_agent_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining TS Agent count.")
                    print(type(ts_agents), "->", ts_agents)
                    print()

            if ts_agent_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ts_agent_count} TS Agent(s) configured.")
                    print("Terminal Services Agents:")
                for agent in ts_agents.get('user', {}).get('sso', {}).get('terminal_services_agent', []):
                    agent_status = agent.get('enable', '')
                    agent_host = agent.get('host', '')
                    agent_port = agent.get('port', '')
                    agent_shared_secret = agent.get('shared_key', None)
                    if agent_shared_secret:
                        if not silent:
                            print(f"  - {agent_host}, port {agent_port} ({'enabled' if agent_status else 'disabled'}): Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TS agents found.")

            ts_agents = {'ts_agents': ts_agents}
            update_routine_results(routine_results, firewall, 'tsa_agents', ts_agents)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TS agents found")
                print(type(ts_agents), "->", ts_agents)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving TSA agents: {e}")

    if not silent:
        print()

    # SSO RADIUS Accounting Clients
    try:
        sso_radius_clients = get_request(api_base, api_session, '/api/sonicos/user/sso/radius-accounting-clients', silent=silent)
        if sso_radius_clients:
            sso_radius_client_count = 0
            try:
                sso_radius_client_key = sso_radius_clients.get('user', {}).get('sso', {}).get('radius_accounting_client', {})
                if isinstance(sso_radius_client_key, list):
                    sso_radius_client_count = len(sso_radius_client_key)
                elif isinstance(sso_radius_client_key, dict) and sso_radius_client_key == {}:
                    sso_radius_client_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SSO RADIUS client count.")
                    print(type(sso_radius_clients), "->", sso_radius_clients)
                    print()

            if sso_radius_client_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sso_radius_client_count} SSO RADIUS Client(s) configured.")
                    print("SSO RADIUS Clients:")
                for client in sso_radius_clients.get('user', {}).get('sso', {}).get('radius_accounting_client', []):
                    client_host = client.get('host', '')
                    client_shared_secret = client.get('shared_secret', None)
                    if client_shared_secret:
                        if not silent:
                            print(f"  - {client_host}: Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO RADIUS clients found.")

            sso_radius_clients = {'sso_radius_clients': sso_radius_clients}
            update_routine_results(routine_results, firewall, 'sso_radius_clients', sso_radius_clients)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO RADIUS clients found")
                print(type(sso_radius_clients), "->", sso_radius_clients)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO RADIUS clients: {e}")

    if not silent:
        print()

    # 3rd Party SSO API Clients
    try:
        sso_api_clients = get_request(api_base, api_session, '/api/sonicos/user/sso/third-party-api/clients', silent=silent)
        if sso_api_clients:
            sso_api_client_count = 0
            try:
                sso_api_client_key = sso_api_clients.get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', {})
                if isinstance(sso_api_client_key, list):
                    sso_api_client_count = len(sso_api_client_key)
                elif isinstance(sso_api_client_key, dict) and sso_api_client_key == {}:
                    sso_api_client_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SSO API client count.")
                    print(type(sso_api_clients), "->", sso_api_clients)
                    print()

            if sso_api_client_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sso_api_client_count} SSO API Client(s) configured.")
                    print("SSO API Clients:")
                for client in sso_api_clients.get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []):
                    client_host = client.get('host', '')
                    client_shared_secret = client.get('shared_secret', None)
                    if client_host and not client_shared_secret:
                        if not silent:
                            print(f"  - {client_host}: Please consider setting a shared secret.")
                    elif client_shared_secret:
                        if not silent:
                            print(f"  - {client_host}: Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO API clients found.")

            sso_api_clients = {'sso_api_clients': sso_api_clients}
            update_routine_results(routine_results, firewall, 'sso_api_clients', sso_api_clients)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO API clients found")
                print(type(sso_api_clients), "->", sso_api_clients)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO API clients: {e}")

    if not silent:
        print()

    # RADIUS Accounting Servers (Users > Settings > Accounting > RADIUS Accounting)
    try:
        acct_servers = get_request(api_base, api_session, '/api/sonicos/user/radius/accounting/servers', silent=silent)
        if acct_servers:
            acct_server_count = 0
            try:
                acct_server_key = acct_servers.get('user', {}).get('radius', {}).get('accounting', {}).get('server', {})
                if isinstance(acct_server_key, list):
                    acct_server_count = len(acct_server_key)
                elif isinstance(acct_server_key, dict) and acct_server_key == {}:
                    acct_server_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining RADIUS accounting server count.")
                    print(type(acct_servers), "->", acct_servers)
                    print()

            if acct_server_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {acct_server_count} RADIUS Accounting Server(s) configured.")
                    print("RADIUS Accounting Servers:")
                for server in acct_servers.get('user', {}).get('radius', {}).get('accounting', {}).get('server', []):
                    server_host = server.get('host', '')
                    server_port = server.get('port', 0)
                    server_status = server.get('enable', False)
                    server_shared_secret = server.get('shared_secret', None)
                    if server_shared_secret:
                        if not silent:
                            print(f"  - {server_host}, port {server_port} ({'enabled' if server_status else 'disabled'}): Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS accounting servers found.")

            acct_servers = {'acct_servers': acct_servers}
            update_routine_results(routine_results, firewall, 'radius_accounting_servers', acct_servers)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS accounting servers found")
                print(type(acct_servers), "->", acct_servers)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving RADIUS accounting servers: {e}")

    if not silent:
        print()

    # TACACS+ Servers (Users > Settings > Accounting > TACACS+)
    try:
        tacacs_servers = get_request(api_base, api_session, '/api/sonicos/user/tacacs/accounting/servers', silent=silent)
        if tacacs_servers:
            tacacs_server_count = 0
            try:
                tacacs_server_key = tacacs_servers.get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', {})
                if isinstance(tacacs_server_key, list):
                    tacacs_server_count = len(tacacs_server_key)
                elif isinstance(tacacs_server_key, dict) and tacacs_server_key == {}:
                    tacacs_server_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining TACACS+ server count.")
                    print(type(tacacs_servers), "->", tacacs_servers)
                    print()

            if tacacs_server_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {tacacs_server_count} TACACS+ Server(s) configured.")
                    print("TACACS+ Servers:")
                for server in tacacs_servers.get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []):
                    server_host = server.get('host', '')
                    server_port = server.get('port', '')
                    server_status = server.get('enable', '')
                    server_shared_secret = server.get('shared_secret', None)
                    if server_shared_secret:
                        if not silent:
                            print(f"  - {server_host}, port {server_port} ({'enabled' if server_status else 'disabled'}): Please update the shared secret.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS+ servers found.")

            tacacs_servers = {'tacacs_accounting_servers': tacacs_servers}
            update_routine_results(routine_results, firewall, 'tacacs_accounting_servers', tacacs_servers)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS+ servers found")
                print(type(tacacs_servers), "->", tacacs_servers)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving TACACS+ servers: {e}")

    if not silent:
        print()

    # AppFlow SFR Reporting
    try:
        sfr = get_request(api_base, api_session, '/api/sonicos/appflow/sfr-mailing/base', silent=silent)
        if sfr:
            sfr_reporting_enabled = sfr.get('appflow', {}).get('sfr_mailing', {}).get('send_email', False)
            sfr_smtp_auth = sfr.get('appflow', {}).get('sfr_mailing', {}).get('smtp_auth', False)
            sfr_pop_auth = sfr.get('appflow', {}).get('sfr_mailing', {}).get('pop_before_smtp', False)
            sfr_server = sfr.get('appflow', {}).get('sfr_mailing', {}).get('smtp_server_host', None)
            sfr_server_pop = sfr.get('appflow', {}).get('sfr_mailing', {}).get('pop_server_address', None)
            sfr_username = sfr.get('appflow', {}).get('sfr_mailing', {}).get('smtp_user', None)
            sfr_password = sfr.get('appflow', {}).get('sfr_mailing', {}).get('smtp_pass', None)
            sfr_username_pop = sfr.get('appflow', {}).get('sfr_mailing', {}).get('pop_username', None)
            sfr_password_pop = sfr.get('appflow', {}).get('sfr_mailing', {}).get('pop_pass', None)
            sfr_data = {'smtp_configured': False, 'pop_configured': False}

            if sfr_server != "" and sfr_server is not None and sfr_password:
                sfr_data['smtp_configured'] = True
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AppFlow SFR Mailing SMTP server is configured to use {sfr_username}@{sfr_server}. Please update the account's password, then update it in SonicOS.")

            if sfr_server_pop != "" and sfr_server_pop is not None and sfr_password_pop:
                if not silent:
                    sfr_data['pop_configured'] = True
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AppFlow SFR Mailing POP server is configured to use {sfr_username_pop}@{sfr_server_pop}. Please update the account's password, then update it in SonicOS.")

            sfr = {'sfr_reporting': sfr, "sfr_data": sfr_data}
            update_routine_results(routine_results, firewall, 'sfr_reporting', sfr)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No AppFlow SFR reporting information found")
                print(type(sfr), "->", sfr)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving AppFlow SFR reporting information: {e}")

    if not silent:
        print()

    # Custom NTP Servers
    try:
        ntp_servers = get_request(api_base, api_session, '/api/sonicos/time/ntp-servers', silent=silent)
        if ntp_servers:
            ntp_server_count = 0
            try:
                ntp_server_key = ntp_servers.get('time', {}).get('ntp_server', {})
                if isinstance(ntp_server_key, list):
                    ntp_server_count = len([x for x in ntp_server_key if x.get('no_auth', False) is False])
                elif isinstance(ntp_server_key, dict) and ntp_server_key == {}:
                    ntp_server_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining NTP server count.")
                    print(type(ntp_servers), "->", ntp_servers)
                    print()

            ntps = []
            if ntp_server_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ntp_server_count} NTP Server(s) with authentication configured.")
                    print("NTP Servers with authentication:")
                for server in ntp_servers.get('time', {}).get('ntp_server', {}):
                    server_host = server.get('name', '')
                    server_auth = server.get('no_auth', False)
                    if server_host and server_auth is False:
                        ntps.append({'host': server_host, 'no_auth': server_auth})
                        if not silent:
                            print(f"  - {server_host} ({'auth disabled' if server_auth else 'auth enabled'}): Please update the password at the server, then update it in SonicOS.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No NTP servers found.")

            ntp_servers = {'custom_ntp_servers': ntp_servers, 'ntp_data': ntps}
            update_routine_results(routine_results, firewall, 'ntp_servers', ntp_servers)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No NTP servers found")
                print(type(ntp_servers), "->", ntp_servers)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving NTP servers: {e}")

    if not silent:
        print()

    # Security Services Signature Proxy
    try:
        security_services = get_request(api_base, api_session, '/api/sonicos/security-services/base', silent=silent)
        if security_services:
            sig_proxy_enabled = security_services.get('security_services', {}).get('proxy_server', {}).get('enable', False)
            sig_proxy_auth = security_services.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False)
            sig_proxy_host = security_services.get('security_services', {}).get('proxy_server', {}).get('host', '')
            sig_proxy_username = security_services.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', '')
            sig_proxy_password = security_services.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('password', None)

            if sig_proxy_auth or sig_proxy_username:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Security Services Signature Proxy authentication is configured with user '{sig_proxy_username}', host '{sig_proxy_host}'. Please update the account's password, then update it in SonicOS.")

            update_routine_results(routine_results, firewall, 'security_services_signature_proxy', security_services)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Security Services Signature Proxy information found")
                print(type(security_services), "->", security_services)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Security Services Signature Proxy information: {e}")

    if not silent:
        print()

    # GMS IPsec Management Tunnel
    try:
        gms_config = get_request(api_base, api_session, '/api/sonicos/administration/global', silent=silent)
        gms_config = gms_config.get('administration', {}).get('gms_management', {})
        if gms_config:
            ipsec_management = gms_config.get('ipsec_tunnel', False)
            if ipsec_management:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: GMS Management:")
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: - GMS IPSec Management Tunnel is configured. Please ensure the encryption/authentication keys are updated.")

            gms_config = {'gms': gms_config}
            update_routine_results(routine_results, firewall, 'gms_ipsec_management_tunnel', gms_config)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No GMS IPsec Management Tunnel information found")
                print(type(gms_config), "->", gms_config)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving GMS IPsec Management Tunnel information: {e}")

    if not silent:
        print()

    # Advanced Routing Protocols (RIP, OSPFv2, BGP)
    routing_adv_data = get_request(api_base, api_session, '/api/sonicos/dynamic-file/getAdvancedRoutingData.json', silent=silent)
    if routing_adv_data:
        try:
            adv_routing_enabled = routing_adv_data.get('data', {}).get('ipv4', {}).get('advancedRoutingEnabled', False)
            bgp_enabled = routing_adv_data.get('data', {}).get('ipv4', {}).get('isBGPEnabled', False)
            routing_interfaces = routing_adv_data.get('data', {}).get('ipv4', {}).get('interfaces', [])
            routing_data = []
            for intf in routing_interfaces:
                intf_name = intf.get('name', '')
                intf_zone = intf.get('zone', '')
                intf_rip = intf.get('RIP', {}).get('status', '')
                intf_rip_password = intf.get('RIP', {}).get('password', '')
                intf_ospfv2 = intf.get('OSPFv2', {}).get('status', False)
                intf_ospfv2_authentication = intf.get('OSPFv2', {}).get('authentication', False)
                intf_ospfv2_password = intf.get('OSPFv2', {}).get('password', '')
                routing_data_entry = {
                    'interface': intf_name,
                    'zone': intf_zone if intf_name != 'MGMT' else 'MGMT',
                    'rip_enabled': False,
                    'rip_password_set': bool(intf_rip_password != ''),
                    'ospfv2_enabled': False,
                    'ospfv2_authentication': False,
                    'ospfv2_password_set': bool(intf_ospfv2_password != ''),
                    'flag_rip': False,
                    'flag_ospfv2': False,
                    'flag_bgp': False
                }

                if intf_rip == 'disabled':
                    intf_rip = False
                else:
                    intf_rip = True
                    routing_data_entry['rip_enabled'] = True

                if intf_ospfv2 == 'disabled':
                    intf_ospfv2 = False
                else:
                    intf_ospfv2 = True
                    routing_data_entry['ospfv2_enabled'] = True

                if intf_ospfv2_authentication == 'disabled':
                    intf_ospfv2_authentication = False
                else:
                    intf_ospfv2_authentication = True
                    routing_data_entry['ospfv2_authentication'] = True

                if intf_rip or intf_rip_password != '':
                    routing_data_entry['flag_rip'] = True
                    if not silent:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Routing - RIP is enabled or password is set on interface {intf_name}. Please ensure any RIP passwords are updated.")
                if intf_ospfv2 or intf_ospfv2_authentication or intf_ospfv2_password != '':
                    routing_data_entry['flag_ospfv2'] = True
                    if not silent:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Routing - OSPFv2 is enabled or password is set on interface {intf_name}. Please ensure any OSPFv2 passwords are updated.")
                if bgp_enabled:
                    routing_data_entry['flag_bgp'] = True
                    if not silent:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Routing - BGP is enabled on interface {intf_name}. Please ensure any BGP passwords are updated.")
                routing_data.append(routing_data_entry)

            routing_adv_data = {'advanced_routing_protocols': routing_adv_data, 'routing_data': routing_data}
            update_routine_results(routine_results, firewall, 'advanced_routing_protocols', routing_adv_data)
        except (KeyError, TypeError) as e:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Advanced Routing Protocols configuration.")
                print(type(routing_adv_data), "->", routing_adv_data)
                print()
    else:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Advanced Routing Protocols information found")
            print(type(routing_adv_data), "->", routing_adv_data)
            print()

    if not silent:
        print()

    # Cellular WWAN
    try:
        cellular = get_request(api_base, api_session, '/api/sonicos/reporting/wwan', silent=silent)
        if isinstance(cellular, list) and len(cellular) > 0:
            wwan_attached = False
            try:
                for wwan in cellular:
                    wwan_attached = wwan.get('modem_attached', 0)
                    wwan_name = wwan.get('vendor_name', None)

                    if wwan_attached != 0 or wwan_name is not None:
                        wwan_attached = True
                        if not silent:
                            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: WWAN modem attached: {wwan_attached}/'{wwan_name}'. Please update the account's password, then update it in SonicOS.")

                cellular = {'cellular_wwan': cellular, 'cellular_attached': wwan_attached}
                update_routine_results(routine_results, firewall, 'cellular_wwan', cellular)
            except (KeyError, TypeError) as e:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving WWAN modem configuration.")
                    print(type(cellular), "->", cellular)
                    print()
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No WWAN modem information found")
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving WWAN modem information: {e}")

    if not silent:
        print()

    # Internal Wireless Radio (preshared key and/or RADIUS)
    try:
        radios = get_request(api_base, api_session, '/api/sonicos/wireless/radio', silent=silent)
        if radios:
            # The only confirmed radio role is access_point_mesh. Changing the setting does not trigger an API change when in read only.
            # TODO: Confirm the other radio role values.
            radio_role = (
                    radios.get('wireless', {}).get('radio_role', {}).get('access_point_mesh', None) or
                    radios.get('wireless', {}).get('radio_role', {}).get('access_point_station', None) or
                    radios.get('wireless', {}).get('radio_role', {}).get('station', None) or
                    radios.get('wireless', {}).get('radio_role', {}).get('access_point', None)
            )
            radio_auth_type = radios.get('wireless', {}).get('authentication_type', {})
            radio_radius = radios.get('wireless', {}).get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
            radio_psk = radios.get('wireless', {}).get('wpa', {}).get('passphrase', None)

            if radio_psk:
                if not silent:
                    print(f"  - The internal wireless radio is configured with a pre-shared key. Please update the pre-shared key.")
            if radio_radius:
                if not silent:
                    print(f"  - RADIUS is configured on the internal wireless radio. Please ensure the RADIUS server shared secret is updated.")

            radios = {'internal_wlan': radios}
            update_routine_results(routine_results, firewall, 'internal_wlan_radios', radios)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Radios found")
                print(type(radios), "->", radios)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Internal Wireless Radios: {e}")

    if not silent:
        print()

    # Internal Wireless Virtual Access Points
    try:
        vaps = get_request(api_base, api_session, '/api/sonicos/wireless/virtual-access-point/objects', silent=silent)
        if vaps:
            vap_count = 0
            try:
                vap_key = vaps.get('wireless', {}).get('virtual_access_point', {}).get('object', {})
                if isinstance(vap_key, list):
                    vap_count = len(vap_key)
                elif isinstance(vap_key, dict) and vap_key == {}:
                    vap_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining Internal Wireless VAP count.")
                    print(type(vaps), "->", vaps)
                    print()

            vap_data = []
            if vap_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vap_count} Internal Wireless Virtual Access Point(s) configured.")
                    print("Internal Wireless Virtual Access Points:")
                all_vaps = vaps.get('wireless', {}).get('virtual_access_point', {}).get('object', [])
                for vap in all_vaps:
                    vap_name = vap.get('name', '')
                    vap_ssid = vap.get('ssid', '')
                    vap_vlan = vap.get('vlan', '')
                    vap_status = vap.get('enable', '')
                    vap_security = vap.get('authentication_type', {})
                    vap_radius = vap.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    vap_accounting = vap.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or vap.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    vap_data_entry = {'name': vap_name, 'ssid': vap_ssid, 'vlan': vap_vlan, 'status': vap_status, 'radius': vap_radius, 'accounting': vap_accounting}
                    vap_data.append(vap_data_entry)
                    if vap_name:
                        if not silent:
                            print(f"  - {vap_name}, SSID: {vap_ssid}, VLAN: {vap_vlan} ({'enabled' if vap_status else 'disabled'}): Please update the pre-shared key.")
                        if vap_radius:
                            if not silent:
                                print(f"    - RADIUS is configured on the VAP. Please ensure the RADIUS server shared secret is updated.")
                        if vap_accounting:
                            if not silent:
                                print(f"    - RADIUS Accounting is configured on the VAP. Please ensure the RADIUS Accounting server shared secret is updated.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Points found.")

            vaps = {'internal_wlan_vaps': vaps, 'internal_wlan_vap_data': vap_data}
            update_routine_results(routine_results, firewall, 'virtual_access_points', vaps)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Points found")
                print(type(vaps), "->", vaps)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Internal Wireless Virtual Access Points: {e}")

    if not silent:
        print()

    # Internal Wireless Virtual Access Point Profiles
    try:
        vap_profiles = get_request(api_base, api_session, '/api/sonicos/wireless/virtual-access-point/profiles', silent=silent)

        if vap_profiles:
            vap_profile_count = 0
            try:
                vap_profile_key = vap_profiles.get('wireless', {}).get('virtual_access_point', {}).get('profile', {})
                if isinstance(vap_profile_key, list):
                    vap_profile_count = len(vap_profile_key)
                elif isinstance(vap_profile_key, dict) and vap_profile_key == {}:
                    vap_profile_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining Internal Wireless VAP profile count.")
                    print(type(vap_profiles), "->", vap_profiles)
                    print()

            vap_profile_data = []
            if vap_profile_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vap_profile_count} Internal Wireless Virtual Access Point Profile(s) configured.")
                    print("Internal Wireless Virtual Access Point Profiles:")
                all_vap_profiles = vap_profiles.get('wireless', {}).get('virtual_access_point', {}).get('profile', [])
                for profile in all_vap_profiles:
                    profile_name = profile.get('name', '')
                    profile_security = profile.get('authentication_type', {})
                    profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    vap_profile_data.append({'name': profile_name, 'radius': profile_radius, 'accounting': profile_accounting})
                    if profile_name:
                        if not silent:
                            print(f"  - {profile_name}: Please update the pre-shared key.")
                        if profile_radius:
                            if not silent:
                                print(f"    - RADIUS is configured on the VAP Profile. Please ensure the RADIUS server shared secret is updated.")
                        if profile_accounting:
                            if not silent:
                                print(f"    - RADIUS Accounting is configured on the VAP Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Point Profiles found.")

            vap_profiles = {'internal_wlan_vap_profiles': vap_profiles, 'internal_wlan_vap_profile_data': vap_profile_data}
            update_routine_results(routine_results, firewall, 'internal_wlan_virtual_access_point_profiles', vap_profiles)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Point Profiles found")
                print(type(vap_profiles), "->", vap_profiles)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Internal Wireless Virtual Access Point Profiles: {e}")

    if not silent:
        print()

    # Wireless SonicPoint/SonicWave/Virtual Access Points. Preshared keys, RADIUS shared secrets, etc.
    # SonicPoint/SonicWave Virtual Access Point Objects
    try:
        vaps = get_request(api_base, api_session, '/api/sonicos/sonicpoint/virtual-access-point/objects', silent=silent)

        if vaps:
            vap_count = 0
            try:
                vap_key = vaps.get('sonicpoint', {}).get('virtual_access_point', {}).get('object', {})
                if isinstance(vap_key, list):
                    vap_count = len(vap_key)
                elif isinstance(vap_key, dict) and vap_key == {}:
                    vap_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining VAP count.")
                    print(type(vaps), "->", vaps)
                    print()

            vap_data = []
            if vap_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found SonicPoint/SonicWave {vap_count} Virtual Access Point(s) configured.")
                    print("SonicPoint/SonicWave Virtual Access Points:")
                all_vaps = vaps.get('sonicpoint', {}).get('virtual_access_point', {}).get('object', [])
                for vap in all_vaps:
                    vap_name = vap.get('name', '')
                    vap_ssid = vap.get('ssid', '')
                    vap_vlan = vap.get('vlan', '')
                    vap_status = vap.get('enable', '')
                    vap_security = vap.get('authentication_type', {})
                    vap_radius = vap.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    vap_accounting = vap.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or vap.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    vap_data_entry = {'name': vap_name, 'ssid': vap_ssid, 'vlan': vap_vlan, 'status': vap_status, 'radius': vap_radius, 'accounting': vap_accounting}
                    vap_data.append(vap_data_entry)
                    if vap_name:
                        if not silent:
                            print(f"  - {vap_name}, SSID: {vap_ssid}, VLAN: {vap_vlan} ({'enabled' if vap_status else 'disabled'}): Please update the pre-shared key.")
                        if vap_radius:
                            if not silent:
                                print(f"    - RADIUS is configured on the VAP. Please ensure the RADIUS server shared secret is updated.")
                        if vap_accounting:
                            if not silent:
                                print(f"    - RADIUS Accounting is configured on the VAP. Please ensure the RADIUS Accounting server shared secret is updated.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Virtual Access Points found.")

            vaps = {'sonicpoint_vaps': vaps, 'sonicpoint_vap_data': vap_data}
            update_routine_results(routine_results, firewall, 'virtual_access_points', vaps)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Virtual Access Points found")
                print(type(vaps), "->", vaps)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Virtual Access Points: {e}")

    if not silent:
        print()

    # SonicPoint/SonicWave Virtual Access Point Profiles
    try:
        vap_profiles = get_request(api_base, api_session, '/api/sonicos/sonicpoint/virtual-access-point/profiles', silent=silent)

        if vap_profiles:
            vap_profile_count = 0
            try:
                vap_profile_key = vap_profiles.get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', {})
                if isinstance(vap_profile_key, list):
                    vap_profile_count = len(vap_profile_key)
                elif isinstance(vap_profile_key, dict) and vap_profile_key == {}:
                    vap_profile_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave VAP profile count.")
                    print(type(vap_profiles), "->", vap_profiles)
                    print()

            vap_profile_data = []
            if vap_profile_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vap_profile_count} SonicPoint/SonicWave Virtual Access Point Profile(s) configured.")
                    print("SonicPoint/SonicWave Virtual Access Point Profiles:")
                all_vap_profiles = vap_profiles.get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', [])
                for profile in all_vap_profiles:
                    profile_name = profile.get('name', '')
                    profile_security = profile.get('authentication_type', {})
                    profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    vap_profile_data.append({'name': profile_name, 'radius': profile_radius, 'accounting': profile_accounting})
                    if profile_name:
                        if not silent:
                            print(f"  - {profile_name}: Please update the pre-shared key.")
                        if profile_radius:
                            if not silent:
                                print(f"    - RADIUS is configured on the VAP Profile. Please ensure the RADIUS server shared secret is updated.")
                        if profile_accounting:
                            if not silent:
                                print(f"    - RADIUS Accounting is configured on the VAP Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Virtual Access Point Profiles found.")

            vap_profiles = {'sonicpoint_vap_profiles': vap_profiles, 'sonicpoint_vap_profile_data': vap_profile_data}
            update_routine_results(routine_results, firewall, 'virtual_access_point_profiles', vap_profiles)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Virtual Access Point Profiles found")
                print(type(vap_profiles), "->", vap_profiles)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Virtual Access Point Profiles: {e}")

    if not silent:
        print()

    # Wireless Access Points (SonicPoint/SonicWave Profiles and Objects)
    # SonicPoint/SonicWave Profiles
    try:
        sp_profiles = get_request(api_base, api_session, '/api/sonicos/sonicpoint/profiles', silent=silent)
        if sp_profiles:
            sp_profile_count = 0
            try:
                sp_profile_key = sp_profiles.get('sonicpoint', {}).get('profile', {})
                if isinstance(sp_profile_key, list):
                    sp_profile_count = len(sp_profile_key)
                elif isinstance(sp_profile_key, dict) and sp_profile_key == {}:
                    sp_profile_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave profile count.")
                    print(type(sp_profiles), "->", sp_profiles)
                    print()

            sp_profile_data = []
            if sp_profile_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sp_profile_count} SonicPoint/SonicWave Profile(s) configured.")
                    print("SonicPoint/SonicWave Profiles:")
                all_sp_profiles = sp_profiles.get('sonicpoint', {}).get('profile', [])
                for profile in all_sp_profiles:
                    profile_name = (profile.get('waveax', {}).get('name_prefix', None) or
                                    profile.get('n', {}).get('name_prefix', None) or
                                    profile.get('ndr', {}).get('name_prefix', None) or
                                    profile.get('ac', {}).get('name_prefix', None) or
                                    profile.get('wave2', {}).get('name_prefix', None)
                                    )
                    profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    profile_administrator = profile.get('administrator', {}).get('name', None)
                    profile_sslvpn_server = profile.get('sslvpn', {}).get('server', False)
                    profile_sslvpn_user = profile.get('sslvpn', {}).get('user_name', False)
                    sp_profile_data.append({'name': profile_name, 'radius': profile_radius, 'accounting': profile_accounting, 'administrator': profile_administrator, 'sslvpn_user': profile_sslvpn_user, 'sslvpn_server': profile_sslvpn_server})
                    if profile_name:
                        if not silent:
                            print(f"  - {profile_name}: Please update the pre-shared key.")
                        if profile_radius and (profile_radius != '' and profile_radius != '0.0.0.0'):
                            if not silent:
                                print(f"    - RADIUS is configured on the SonicPoint/SonicWave Profile. Please ensure the RADIUS server shared secret is updated.")
                        if profile_accounting and (profile_accounting != '' and profile_accounting != '0.0.0.0'):
                            if not silent:
                                print(f"    - RADIUS Accounting is configured on the SonicPoint/SonicWave Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
                        if profile_administrator:
                            if not silent:
                                print(f"    - Administrator account '{profile_administrator}' is set on the SonicPoint/SonicWave Profile. Please ensure the administrator account password is updated.")
                        if profile_sslvpn_server or profile_sslvpn_user:
                            if not silent:
                                print(f"    - L3 SSLVPN Management is configured on the SonicPoint/SonicWave Profile ({profile_sslvpn_user}@{profile_sslvpn_server}). Please ensure the SSLVPN server and user account password is updated.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Profiles found.")

            sp_profiles = {"sonicpoint_profiles": sp_profiles, "sonicpoint_profile_data": sp_profile_data}
            update_routine_results(routine_results, firewall, 'sonicpoint', sp_profiles)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Profiles found")
                print(type(sp_profiles), "->", sp_profiles)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Profiles: {e}")

    if not silent:
        print()

    # SonicPoint/SonicWave Access Point Objects
    try:
        sp_objects = get_request(api_base, api_session, '/api/sonicos/sonicpoint/sonicpoints', silent=silent)
        if sp_objects:
            sp_object_count = 0
            try:
                sp_object_key = sp_objects.get('sonicpoint', {}).get('sonicpoint', {})
                if isinstance(sp_object_key, list):
                    sp_object_count = len(sp_object_key)
                elif isinstance(sp_object_key, dict) and sp_object_key == {}:
                    sp_object_count = 0
            except (KeyError, TypeError):
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave object count.")
                    print(type(sp_objects), "->", sp_objects)
                    print()

            sp_object_data = []
            if sp_object_count > 0:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sp_object_count} SonicPoint/SonicWave Object(s) configured.")
                    print("SonicPoint/SonicWave Objects:")
                all_sp_objects = sp_objects.get('sonicpoint', {}).get('sonicpoint', [])
                for obj in all_sp_objects:
                    obj_name = (obj.get('waveax', {}).get('name', None) or
                                    obj.get('n', {}).get('name', None) or
                                    obj.get('ndr', {}).get('name', None) or
                                    obj.get('ac', {}).get('name', None) or
                                    obj.get('wave2', {}).get('name', None)
                                    )
                    obj_radius = obj.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    obj_accounting = obj.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or obj.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    obj_administrator = obj.get('administrator', {}).get('name', None)
                    obj_sslvpn_server = obj.get('sslvpn', {}).get('server', False)
                    obj_sslvpn_user = obj.get('sslvpn', {}).get('user_name', False)
                    sp_object_data.append({'name': obj_name, 'radius': obj_radius, 'accounting': obj_accounting, 'administrator': obj_administrator, 'sslvpn_user': obj_sslvpn_user, 'sslvpn_server': obj_sslvpn_server})
                    if obj:
                        if not silent:
                            print(f"  - {obj}: Please update the pre-shared key.")
                        if obj_radius and (obj_radius != '' and obj_radius != '0.0.0.0'):
                            if not silent:
                                print(f"    - RADIUS is configured on the SonicPoint/SonicWave Object. Please ensure the RADIUS server shared secret is updated.")
                        if obj_accounting and (obj_accounting != '' and obj_accounting != '0.0.0.0'):
                            if not silent:
                                print(f"    - RADIUS Accounting is configured on the SonicPoint/SonicWave Object. Please ensure the RADIUS Accounting server shared secret is updated.")
                        if obj_administrator:
                            if not silent:
                                print(f"    - Administrator account '{obj_administrator}' is set on the SonicPoint/SonicWave Object. Please ensure the administrator account password is updated.")
                        if obj_sslvpn_server or obj_sslvpn_user:
                            if not silent:
                                print(f"    - L3 SSLVPN Management is configured on the SonicPoint/SonicWave Object ({obj_sslvpn_user}@{obj_sslvpn_server}). Please ensure the SSLVPN server and user account password is updated.")
            else:
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Objects found.")

            sp_objects = {"sonicpoint_objects": sp_objects, "sonicpoint_object_data": sp_object_data}
            update_routine_results(routine_results, firewall, 'sonicpoint_sonicwave_objects', sp_objects)
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Objects found")
                print(type(sp_objects), "->", sp_objects)
                print()
    except Exception as e:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Objects: {e}")

    # REMEDIATION CHECKS END
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Completed remediation playbook checks.")

    # TODO: The checks above need to be compiled into functions to reduce the size of this routine function.

    # Process user operations (if enabled)
    print()
    users = None
    if force_password_change or a.force_password_change:
        # Get local users
        users = get_local_users(api_session, api_base, firewall_info['firewall_generation'],
                               firewall, sshport, username, password, target_numbers)

        if users is None:
            return "UNABLE_TO_GET_USERS", "Unable to get users"

        routine_results[firewall]['got_users'] = True
        routine_results[firewall]['total_user_count'] = len(users['user']['local']['user'])

        # Process password changes
        user_results = process_password_changes(
            users, api_session, api_base, temp_password, randomize_temp_password or a.randomize_password,
            firewall_info['firewall_generation'], firewall, sshport, username, password, target_numbers, a)

        routine_results[firewall]['users'] = user_results
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: Force password change logic is disabled. Enable it with -fpc or in the input CSV.")
        routine_results[firewall]['force_password_change_disabled'] = True

    # Handle TOTP unbind operations (if enabled)
    if unbind_totp or a.unbind_totp:
        totp_result = unbind_totp_from_users(api_session, api_base, firewall_info['firewall_generation'],
                                           users, target_numbers)
        update_routine_results(routine_results, firewall, 'totp_unbind', totp_result)
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: TOTP unbind logic is disabled. Enable it with -ut or in the input CSV.")
        routine_results[firewall]['totp_unbind_disabled'] = True

    # Calculate routine statistics
    calculate_routine_statistics(routine_results, firewall)

    # Finalize routine (cleanup, write results, logout)
    finalize_routine(api_session, api_base, firewall, firewall_info['firewall_generation'],
                    sshport, username, password, target_numbers, firewall_info)

    print(f"Refer to ./{constants.START_TIMESTAMP_FOLDER}/{routine_results[firewall]['device_model'].replace(' ', '')}-{routine_results[firewall]['serial_number']}-summary.md for resources to address each of the findings above.")
    return "ROUTINE_COMPLETE", "Routine completed successfully."


# Main function
if __name__ == "__main__":
    banner_info = [
        "Remediation Playbook / Essential Credential Reset Tool",
        "",
        "This tool assists administrators by analyzing SonicOS configurations and producing a",
        "  detailed report based on the 'Remediation Playbook' and 'Essential Credential Reset' KB articles:",
        "    https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590",
        "    https://www.sonicwall.com/support/knowledge-base/remediation-playbook/250916130050523",
        "",
        "What this tool does:",
        "  - Connects to SonicWall firewalls using the SonicOS API",
        "    - SSH may be used as a fallback for auto-enabling SonicOS API and other operations",
        "    - SonicOS API will be auto-disabled if enabled by the tool",
        "  - Performs automated checks from the 'Essential Credential Reset' guidelines",
        "  - Identifies configuration items requiring attention",
        "  - Generates a summary table of findings and recommended actions with resources for remediation",
        "  - Produces a detailed findings report for review",
        "  - Optionally resets local user passwords to a specified temporary password with randomization",
        "     - Users will also be forced to change the password at next login",
        "  - Optionally unbinds TOTP from all local users",
        "",
        "Important:",
        "  - This tool does NOT make the recommended configuration changes for you.",
        "  - It uses the SonicOS API to gather data and provide guidance for manual remediation.",
    ]
    print_banner(info=banner_info)

    # Creates the folders for any output.
    if path.exists(constants.RUNS_FOLDER) is False:
        mkdir(constants.RUNS_FOLDER)

    # The -target argument could be an IP, hostname, or a CSV file containing firewall configurations.
    # Load targets using the new simplified CSV handling
    targets = load_targets(a.target)

    if len(targets) > 0:
        if path.exists(constants.START_TIMESTAMP_FOLDER) is False:
            mkdir(constants.START_TIMESTAMP_FOLDER)

    for target_index, target in enumerate(targets):
        # Now target is always a FirewallTarget object
        fw = target.firewall

        if fw == "" or fw is None:
            print(f"({target_index+1}/{len(targets)}) {generate_timestamp()}: Error: The target firewall is empty.")
            exit(1)

        # Print the target information
        try:
            print(f"({target_index+1}/{len(targets)}) {generate_timestamp()}: Target {target_index+1}/{len(targets)} - {fw}: Running routine...")
        except Exception as e:
            print(f"{generate_timestamp()}: {fw}: Running routine...")

        routine_results[fw] = {}

        # Run the routine with simplified parameter passing
        res, res_msg = routine(target, target_numbers=(target_index+1, len(targets)), silent=a.silent)

        if not res:
            print(f"({target_index+1}/{len(targets)}) {generate_timestamp()}: Error: Routine failed. Result message: {res_msg}")

        print(f"({target_index+1}/{len(targets)}) {generate_timestamp()}: Target {target_index+1}/{len(targets)} - {fw}: Done.\n{'='*60}\n\n")

    print(f"{generate_timestamp()}: ALL DONE")
