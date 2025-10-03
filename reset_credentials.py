# Imports
import json
import csv
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
except ImportError or ModuleNotFoundError:
    pass

@dataclass
class FirewallTarget:
    """Data class to represent a firewall target with all its configuration."""
    firewall: str
    username: Optional[str] = None
    password: Optional[str] = None
    sshport: str = '22'
    enable_totp: bool = False
    enable_botnet_filtering: bool = False
    temp_password: str = ""
    upgrade_firmware: str = ""
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


def normalize_temp_password(password: str) -> str:
    """Normalize temporary password with minimum length validation."""
    if not password or password in ['None', 'false', '']:
        return ""

    if len(password) < 8:
        print(f"{generate_timestamp()}: Warning: Temporary password too short, padding with 'x'")
        password += 'x' * (8 - len(password))

    return password


def normalize_firmware_path(path_str: str) -> str:
    """Normalize and validate firmware upgrade path."""
    if not path_str or path_str.strip(' "\'') in ['None', 'false', '']:
        return ""

    clean_path = path_str.strip(' "\'')
    if not path.exists(clean_path):
        print(f"{generate_timestamp()}: Warning: Firmware file '{clean_path}' not found")
        return ""

    return path.abspath(clean_path)


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
        enable_totp=normalize_boolean(row.get('enable_totp', '')),
        enable_botnet_filtering=normalize_boolean(row.get('enable_botnet_filtering', '')),
        temp_password=normalize_temp_password(row.get('temporary_password', '')),
        upgrade_firmware=normalize_firmware_path(row.get('upgrade_to_firmware_image', '')),
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
        enable_totp=normalize_boolean(row[4]),
        enable_botnet_filtering=normalize_boolean(row[5]),
        temp_password=normalize_temp_password(row[6]),
        upgrade_firmware=normalize_firmware_path(row[7]),
        unbind_totp=normalize_boolean(row[8]) if len(row) > 8 else False,
        force_password_change=normalize_boolean(row[9]) if len(row) > 9 else False
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
            enable_totp=a.enable_totp,
            enable_botnet_filtering=a.enable_botnet_filtering,
            temp_password=normalize_temp_password(a.temp_password),
            upgrade_firmware=normalize_firmware_path(a.upgrade_firmware),
            unbind_totp=normalize_boolean(a.unbind_totp),
            force_password_change=normalize_boolean(a.force_password_change)
        )]


# Argument parsing
arg_description = """SonicWall Cloud Backup Configuration Remediation Script.
This tool automates remediation tasks such as forcing all local users to change their password on next login. Please refer to the README for more detailed help."""
a = get_parser(arg_set="remediation", description=arg_description)
# TODO: some arguments from 'snwlid-2024-0015' will apply here.


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
    enable_totp = kwargs.get('enable_totp', target.enable_totp)
    enable_botnet_filtering = kwargs.get('enable_botnet_filtering', target.enable_botnet_filtering)
    temp_password = kwargs.get('temp_password', target.temp_password)
    upgrade_firmware = kwargs.get('upgrade_firmware', target.upgrade_firmware)
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
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Enable TOTP on 'SSLVPN Services' group: {enable_totp}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Enable Botnet Filtering service: {enable_botnet_filtering}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Temporary Password for users: {temp_password}")
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Firmware upgrade file: {upgrade_firmware}")
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


def gather_firewall_info(api_session, api_base: str, target_numbers: tuple):
    """Gather firewall information including version, model, serial number, and HA status."""
    firewall_generation = None
    firmware_version = None
    device_model = None
    serial_number = None
    ha_status = None
    ha_primary_state = None
    ha_secondary_state = None
    ha_uptime = None

    # Determine firewall generation and get basic info
    if isinstance(api_session, Login):
        try:
            info = api_session.get_firewall_info()
            if info.get('firmware_version', None):
                firmware_version = info['firmware_version']
                device_model = info['model']
                serial_number = info['serial_number']
                ha_status = info.get('ha_status', "")
                ha_primary_state = info.get('ha_primary_state', "")
                ha_secondary_state = info.get('ha_secondary_state', "")
                ha_uptime = info.get('ha_uptime', "")
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
            info = get_request(api_base, api_session, '/api/sonicos/version')

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

        # Get HA information for non-GEN5 firewalls
        try:
            ha_info = get_request(api_base, api_session, '/api/sonicos/reporting/high-availability')

            if ha_info.get('status', None):
                ha_status = ha_info.get('status', "")
                ha_primary_state = ha_info.get('primary_state', "")
                ha_secondary_state = ha_info.get('secondary_state', "")
                ha_uptime = ha_info.get('active_up_time', "")

            if ha_status:
                ha_status = ha_status.upper()
            if ha_primary_state:
                ha_primary_state = ha_primary_state.upper()
            if ha_secondary_state:
                ha_secondary_state = ha_secondary_state.upper()
            if ha_uptime:
                ha_uptime = ha_uptime.upper()
        except KeyboardInterrupt:
            print(f"\nStopped!")
            exit()
        except Exception as e:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting HA information: {e}")
            return None, f"Error getting HA information: {e}"

    return {
        'firewall_generation': firewall_generation,
        'firmware_version': firmware_version,
        'device_model': device_model,
        'serial_number': serial_number,
        'ha_status': ha_status,
        'ha_primary_state': ha_primary_state,
        'ha_secondary_state': ha_secondary_state,
        'ha_uptime': ha_uptime
    }, None


def export_tsr_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict):
    """Export TSR if enabled in arguments."""
    result = {'tsr_downloaded': False}

    if not args.export_tsr:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TSR download disabled.")
        return result

    print(f"{generate_timestamp()}: Downloading TSR...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    tsr_file_name = f"{dm}-{sn}-tsr.wri"

    tsr_downloaded = download_tsr(api_base,
                                  api_session,
                                  filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tsr_file_name}",
                                  firewall_generation=firewall_info['firewall_generation'])

    if tsr_downloaded:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TSR downloaded to {tsr_file_name}")
        result['tsr_downloaded'] = True

    return result


def export_tracelogs_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict):
    """Export trace logs if enabled in arguments."""
    result = {'trace_logs_downloaded': False}

    if not args.export_tracelogs:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Trace log download disabled.")
        return result

    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Downloading trace logs...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    tracelog_filename = f"{dm}-{sn}-tracelog-current.txt"

    trace_logs_downloaded = download_tracelog(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tracelog_filename}",
                                              log_selection="current",
                                              firewall_generation=firewall_info['firewall_generation'])

    if trace_logs_downloaded:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Trace logs downloaded.")
        result['trace_logs_downloaded'] = True

    return result


def export_settings_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, username: str, password: str):
    """Export settings if enabled in arguments."""
    result = {'settings_exported': False}

    if not args.export_settings:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings export disabled.")
        return result

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
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Successfully logged in to the firewall for settings export.")
            prefs_downloaded = export_preferences(api_base,
                                                  alternate_session,
                                                  filepath=f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}",
                                                  firewall_generation=firewall_generation)
    else:
        # GEN5 and GEN7 use existing session
        prefs_downloaded = export_preferences(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}",
                                              firewall_generation=firewall_generation)

    if prefs_downloaded:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings exported.")
        result['settings_exported'] = True

    return result


def check_ha_upgrade_eligibility(ha_status: str, ha_primary_state: str, ha_secondary_state: str, ha_uptime: str, target_numbers: tuple):
    """Check if the firewall is eligible for upgrade operations based on HA status."""
    if not ha_status:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: HA status not available. Skipping upgrade.")
        return False, "HA status not available"

    # When the secondary shows active or primary shows standby, the upgrade is skipped
    if ha_status == "SECONDARY ACTIVE" or ha_status == "PRIMARY STANDBY":
        msg = f"HA Status: {ha_status} | HA Primary State: {ha_primary_state} | HA Secondary State: {ha_secondary_state} | Skipping upgrade."
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: {msg}")
        return False, msg

    # When HA is disabled, proceed with upgrade
    elif ha_status == "PRIMARY DISABLED" or ha_uptime == "HIGH AVAILABILITY DISABLED":
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: HA status: {ha_status} | HA Primary State: {ha_primary_state} | HA Secondary State: {ha_secondary_state} | Proceeding with upgrade.")
        return True, "HA disabled, proceeding"

    # When the primary is active and the secondary is standby, allow upgrade
    elif ha_status == "PRIMARY ACTIVE":
        if ha_primary_state == "ACTIVE" and ha_secondary_state == "STANDBY":
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: HA status: {ha_status} | {ha_primary_state} | {ha_secondary_state}. Proceeding with upgrade.")
            return True, "Primary active with standby secondary"
        else:
            msg = f"HA status: {ha_status} | P:{ha_primary_state} | S:{ha_secondary_state}. Skipping upgrade."
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: {msg}")
            return False, msg

    return False, f"Unknown HA status: {ha_status}"


def get_local_users(api_session, api_base: str, firewall_generation: int, firewall: str, sshport: str, username: str, password: str, target_numbers: tuple):
    """Retrieve local users from the firewall."""
    users = None

    try:
        if firewall_generation == 7:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users')
        elif firewall_generation == 6:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users')
        elif firewall_generation == 5:
            users = get_users_ssh(firewall, sshport, username, password)

            if users:
                print(f"{generate_timestamp()}: Users retrieved from SSH.")
            else:
                print(f"{generate_timestamp()}: Error getting users from SSH.")
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting users from API: {e}")
        return None

    # Handle bytes response and JSON parsing for GEN6
    if isinstance(users, bytes):
        users = users.replace(b': expired', b': "expired"')
        users = json.loads(users.decode('utf-8'))

    # Validate users data
    if isinstance(users, dict):
        if users.get('user', {}).get('local', {}).get('user', None) is None:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: No local users found.")
            return None
    elif isinstance(users, bool):
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error: Unable to get users.")
        return None

    return users


def process_password_changes(users: dict, api_session, api_base: str, temp_password: str, firewall_generation: int,
                           firewall: str, sshport: str, username: str, password: str, target_numbers: tuple, args):
    """Process password changes for all eligible local users."""
    if not users:
        return []

    user_results = []
    users_list = users['user']['local']['user']

    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Updating the force password reset flag for all local users...")
    if temp_password != "":
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Passwords will be reset to '{temp_password}'")

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
            "commit_successful": False
        }

        if firewall_generation != 5:
            print(f"\nUpdating '{uname}'", end='')
        else:
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
                                      data=data_structure)
        elif firewall_generation == 6:
            update_resp = put_request(api_base, api_session,
                                    api_path=f"/api/sonicos/user/local/user/uuid/{uuid}",
                                    data=data_structure)
        elif firewall_generation == 5:
            update_resp = force_password_change_ssh(ssh_session, ssh_connection, data=usr)

        if update_resp['status']['success'] is False:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error updating user: {uname}")
            input("Press Enter to continue or CTRL+C to exit.")

        routine_result_temp['user_update_successful'] = True

        # Commit changes (GEN5 already committed via SSH)
        if firewall_generation != 5:
            commit_pending(api_base, api_session)
        routine_result_temp['commit_successful'] = True

        user_results.append(routine_result_temp)
        sleep(1)
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
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Retrieving users for TOTP unbind...")
        try:
            if firewall_generation == 7:
                totp_users = get_request(api_base, api_session, '/api/sonicos/user/local/users')
            elif firewall_generation == 6:
                totp_users = get_request(api_base, api_session, '/api/sonicos/user/local/users')
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unbinding TOTP for user '{uname}'...")

                totp_unbound = post_request(api_base, api_session, data=None,
                                          api_path=f"/api/sonicos/user/local/unbind-totp-key/{uname}")

                if totp_unbound:
                    api_result = totp_unbound.get('status', {}).get('info', [{}])[-1].get('message', 'No message returned.')
                    success = api_result.lower() == "changes made."
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Committing TOTP unbind changes...")
                commit_pending(api_base, api_session)

            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TOTP unbind complete - {result['totp_unbind_successful_count']} successful, {result['totp_unbind_failed_count']} failed")
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No local users found for TOTP unbind.")
            result['totp_unbind_no_users'] = True
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unable to retrieve users for TOTP unbind.")
        result['totp_unbind_get_users_failed'] = True

    return result


def manage_botnet_filtering(api_session, api_base: str, enable_botnet_filtering: bool, firewall_generation: int, target_numbers: tuple, args):
    """Check and manage botnet filtering configuration."""
    result = {
        'botnet_filtering_licensed': None,
        'botnet_filtering_enabled': None,
        'botnet_filtering_autoenabled': False
    }

    if not enable_botnet_filtering:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: Botnet Filtering logic is disabled. Enable it with -eb.")
        result['botnet_filtering_disabled'] = True
        return result

    try:
        print()
        botnet_status = check_botnet_status(api_base, api_session, firewall_generation=firewall_generation)

        if botnet_status["license_status"] == "not_licensed":
            result['botnet_filtering_licensed'] = False
            msg = botnet_status.get("message", "")
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Botnet Filtering is not licensed. {msg}")
            return result
        elif botnet_status["license_status"] == "licensed":
            result['botnet_filtering_licensed'] = True
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Botnet Filtering is licensed.")

        if botnet_status["status"] == "enabled":
            result['botnet_filtering_enabled'] = True
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Botnet Filtering is enabled.")
            return result
        elif botnet_status["status"] == "disabled":
            result['botnet_filtering_enabled'] = False
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Botnet Filtering is not enabled.")

        # Enable botnet filtering if licensed but not enabled
        if (result['botnet_filtering_licensed'] and not result['botnet_filtering_enabled'] and
            (enable_botnet_filtering or args.enable_botnet_filtering)):

            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Enabling Botnet Filtering for all connections.")
            botnet_status_response = botnet_status['response']
            botnet_status_response['botnet']['logging'] = True

            enable_botnet_resp = {}
            if firewall_generation == 7:
                botnet_status_response['botnet']['block']['connections'] = {'enable': True, 'mode': 'all'}
                enable_botnet_resp = put_request(api_base, api_session, '/api/sonicos/botnet/base', data=botnet_status_response)
            elif firewall_generation == 6:
                botnet_status_response['botnet']['block']['connections'] = {'all': True}
                # Remove problematic keys that can cause out of bounds errors
                botnet_status_response['botnet'].pop('dynamic_list', None)
                botnet_status_response['botnet'].pop('exclude', None)
                botnet_status_response['botnet'].pop('include', None)
                enable_botnet_resp = put_request(api_base, api_session, '/api/sonicos/botnet/global', data=botnet_status_response)
            elif firewall_generation == 5:
                enable_botnet_resp = api_session.enable_botnet_filtering()

            if enable_botnet_resp.get('status', {}).get('success', False) is False:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error enabling Botnet Filtering.")
            else:
                result['botnet_filtering_autoenabled'] = True

            # Commit changes
            if firewall_generation != 5:
                commit_pending(api_base, api_session)

    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error managing botnet filtering: {e}")
        result['botnet_filtering_error'] = str(e)

    return result


def enable_totp_on_sslvpn_group(api_session, api_base: str, enable_totp: bool, firewall_generation: int,
                               firewall: str, sshport: str, username: str, password: str, target_numbers: tuple):
    """Check and enable TOTP on SSLVPN Services group."""
    result = {
        'sslvpn_services_totp_enabled': None,
        'sslvpn_services_totp_autoenabled': None
    }

    if not enable_totp:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: TOTP logic is disabled. Enable it with -et.")
        result['totp_disabled'] = True
        return result

    try:
        print()

        # Check TOTP status based on firewall generation
        if firewall_generation != 5:
            totp_status = check_totp_status(api_base, api_session, group_name="SSLVPN Services",
                                          enable_totp=enable_totp, firewall_generation=firewall_generation)
        else:
            # GEN5 does not support TOTP
            totp_status = {
                "status": "disabled",
                "mode": "",
                "autoenabled": False,
                "message": "GEN5 firewalls do not support TOTP. Consider enabling Email-based OTP manually.",
                "try_ssh": False
            }
            if enable_totp:
                print("TOTP is not available on GEN5 firewalls. Only Email-based OTP, which requires an email address configured for each user.")
                print("Please consider enabling Email-based OTP manually after configuring an email address for each user.")

        # Update results based on TOTP status
        if totp_status["status"] == "enabled":
            result['sslvpn_services_totp_enabled'] = True
            result['sslvpn_services_totp_mode'] = totp_status.get("mode", "")
            result['sslvpn_services_totp_autoenabled'] = totp_status.get("autoenabled", False)
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: {totp_status.get('mode', '')} is enabled on the SSLVPN Services group.")
        elif totp_status["status"] == "disabled":
            result['sslvpn_services_totp_enabled'] = False
            result['sslvpn_services_totp_mode'] = totp_status.get("mode", "")
            result['sslvpn_services_totp_autoenabled'] = totp_status.get("autoenabled", False)
            result['sslvpn_services_totp_error_msg'] = totp_status.get("message", "")

            if firewall_generation == 5:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: {totp_status.get('message', '')}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TOTP/OTP is not enabled on the SSLVPN Services group.")

            if totp_status.get("try_ssh", None):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unable to enable TOTP via API. Trying SSH instead. ({totp_status.get('message', '')})\n")
                enable_totp_ssh(firewall, sshport, username, password, "SSLVPN Services")

    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error managing TOTP: {e}")
        result['totp_error'] = str(e)

    return result


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


def finalize_routine(api_session, api_base: str, firewall: str, firewall_generation: int,
                    sshport: str, username: str, password: str, target_numbers: tuple, firewall_info: dict):
    """Finalize routine by cleaning up, writing results, and logging out."""
    # Sort results for consistency
    routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

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
def routine(target: FirewallTarget, target_numbers=None, **kwargs):
    """
    Main routine - now refactored into smaller, focused functions.

    Args:
        target (FirewallTarget): The firewall target configuration object
        target_numbers (tuple): Current/total target numbers (default: None)
        **kwargs: Additional optional parameters that can override target settings
    """
    # Extract parameters from the target object, with kwargs as overrides
    firewall = target.firewall
    username = kwargs.get('username', target.username)
    password = kwargs.get('password', target.password)
    sshport = kwargs.get('sshport', target.sshport)
    enable_totp = kwargs.get('enable_totp', target.enable_totp)
    enable_botnet_filtering = kwargs.get('enable_botnet_filtering', target.enable_botnet_filtering)
    temp_password = kwargs.get('temp_password', target.temp_password)
    upgrade_firmware = kwargs.get('upgrade_firmware', target.upgrade_firmware)
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

    if upgrade_firmware != "":
        routine_results[firewall]['firmware_upgrade_requested'] = False
        routine_results[firewall]['firmware_image'] = upgrade_firmware

    # Step 1: Print verbose details if enabled
    print_verbose_details(target, target_numbers, a, username=username, password=password,
                         sshport=sshport, enable_totp=enable_totp,
                         enable_botnet_filtering=enable_botnet_filtering,
                         temp_password=temp_password, upgrade_firmware=upgrade_firmware,
                         unbind_totp=unbind_totp)

    # Step 2: Initialize session with the firewall
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

    # Step 3: Gather firewall information
    firewall_info, error_msg = gather_firewall_info(api_session, api_base, target_numbers)
    if firewall_info is None:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error gathering firewall information: {error_msg}")
        return False, f"Error gathering firewall information: {error_msg}"

    # Update routine results with firewall information
    update_routine_results(routine_results, firewall, 'firewall_info', firewall_info)

    # Step 4: Export operations (if enabled)
    tsr_result = export_tsr_if_enabled(api_session, api_base, a, target_numbers, firewall_info)
    update_routine_results(routine_results, firewall, 'tsr_result', tsr_result)
    print()

    tracelog_result = export_tracelogs_if_enabled(api_session, api_base, a, target_numbers, firewall_info)
    update_routine_results(routine_results, firewall, 'tracelog_result', tracelog_result)
    print()

    settings_result = export_settings_if_enabled(api_session, api_base, a, target_numbers,
                                                firewall_info, username, password)
    update_routine_results(routine_results, firewall, 'settings_result', settings_result)
    print()

    # Step 5: Check HA eligibility for upgrade operations
    ha_status = firewall_info['ha_status']
    ha_primary_state = firewall_info['ha_primary_state']
    ha_secondary_state = firewall_info['ha_secondary_state']
    ha_uptime = firewall_info['ha_uptime']

    upgrade_eligible, upgrade_msg = check_ha_upgrade_eligibility(
        ha_status, ha_primary_state, ha_secondary_state, ha_uptime, target_numbers)

    if not upgrade_eligible:
        return "HA_NOT_PRIMARY", upgrade_msg

    print()

    # Step 6: Remediation Playbook -- Checks the items in this KB article:
    # https://www.sonicwall.com/support/knowledge-base/remediation-playbook/250916130050523

    # List LDAP servers
    try:
        ldap_servers = get_request(api_base, api_session, '/api/sonicos/user/ldap/servers')
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
                print(ldap_servers)
                print(type(ldap_servers))

            if ldap_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ldap_count} LDAP servers configured.")
                ldap_servers = ldap_servers['user']['ldap']['server']
                # print(ldap_servers)
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
                    print(f"  - {server_host}, {server_role}: Status: {'enabled' if server_status else 'disabled'}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No LDAP servers found.")

            update_routine_results(routine_results, firewall, 'ldap_servers', ldap_servers)

        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No LDAP servers found")
            print(ldap_servers)
            print(type(ldap_servers))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving LDAP servers: {e}")

    print()

    # List RADIUS servers
    try:
        radius_servers = get_request(api_base, api_session, '/api/sonicos/user/radius/servers')
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
                print(radius_servers)
                print(type(radius_servers))

            if radius_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {radius_count} RADIUS servers configured.")
                radius_servers = radius_servers['user']['radius']['server']
                print("RADIUS Servers:")
                for server in radius_servers:
                    server_host = server.get('host', '')
                    server_port = server.get('port', '')
                    server_status = server.get('enable', '')
                    print(f"  - {server_host}, port {server_port}: Status: {'enabled' if server_status else 'disabled'}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS servers found.")

            update_routine_results(routine_results, firewall, 'radius_servers', radius_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS servers found")
            print(radius_servers)
            print(type(radius_servers))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving RADIUS servers: {e}")

    print()

    # List TACACS servers
    try:
        tacacs_servers = get_request(api_base, api_session, '/api/sonicos/user/tacacs/servers')
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining TACACS server count.")
                print(tacacs_servers)
                print(type(tacacs_servers))

            if tacacs_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {tacacs_count} TACACS servers configured.")
                tacacs_servers = tacacs_servers['user']['tacacs']['server']
                print("TACACS Servers:")
                for server in tacacs_servers:
                    server_host = server.get('host', '')
                    server_port = server.get('port', '')
                    server_status = server.get('enable', '')
                    print(f"  - {server_host}, port {server_port}: Status: {'enabled' if server_status else 'disabled'}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS servers found.")

            update_routine_results(routine_results, firewall, 'tacacs_servers', tacacs_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS servers found")
            print(tacacs_servers)
            print(type(tacacs_servers))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving TACACS servers: {e}")

    print()

    # List VPN policies
    try:
        vpn_policies = get_request(api_base, api_session, '/api/sonicos/vpn/policies/all')
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining VPN policy count.")
                print(vpn_policies)
                print(type(vpn_policies))

            if vpn_policy_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vpn_policy_count} VPN policies configured.")
                # print(vpn_policies)
                print("VPN Policies:")
                for policy in vpn_policies['vpn'].get('policy', []):
                    policy_name = policy.get('ipv4', {}).get('group_vpn', {}).get('name') or policy.get('ipv4', {}).get('site_to_site', {}).get('name') or policy.get('ipv4', {}).get('tunnel_interface', {}).get('name')
                    policy_status = policy.get('ipv4', {}).get('group_vpn', {}).get('enable', False) or policy.get('ipv4', {}).get('site_to_site', {}).get('enable', False) or policy.get('ipv4', {}).get('tunnel_interface', {}).get('enable', False)
                    print(f"  - {policy_name}: {'enabled' if policy_status else 'disabled'}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No VPN policies found.")

            update_routine_results(routine_results, firewall, 'vpn_policies', vpn_policies)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No VPN policies found")
            print(vpn_policies)
            print(type(vpn_policies))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving VPN policies: {e}")

    print()

    # List WAN interfaces (check for L2TP/PPTP/PPPoE/WWAN)
    try:
        interfaces = get_request(api_base, api_session, '/api/sonicos/interfaces/ipv4')
        # print(interfaces)
        if interfaces:
            wan_interfaces = []
            for intf in interfaces.get('interfaces', []):
                if intf.get('ipv4', {}).get('ip_assignment', {}).get('zone', '') == 'WAN':
                    wan_interfaces.append(intf)

            if len(wan_interfaces) > 0:
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
                        print(f"  - {intf_name} ({intf_type})")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No WAN interfaces found.")

            update_routine_results(routine_results, firewall, 'wan_interfaces', wan_interfaces)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No interfaces found")
            print(interfaces)
            print(type(interfaces))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving interfaces: {e}")

    print()

    # Check AWS API status (log/aws)
    try:
        aws_api = get_request(api_base, api_session, '/api/sonicos/log/aws')
        if aws_api:
            aws_enabled = aws_api.get('log', {}).get('aws', {}).get('enable', False)
            if aws_enabled:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AWS API is enabled. Please update the secret key.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AWS API is not enabled.")

            update_routine_results(routine_results, firewall, 'aws_api', aws_api)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No AWS API information found")
            print(aws_api)
            print(type(aws_api))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving AWS API information: {e}")

    print()

    # List dynamic DNS services
    try:
        ddns_services_v4 = get_request(api_base, api_session, '/api/sonicos/dynamic-dns/profiles/ipv4')
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining IPv4 dynamic DNS service count.")
                print(ddns_services_v4)
                print(type(ddns_services_v4))

            if ddns_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ddns_count} IPv4 dynamic DNS services configured.")
                print("IPv4 Dynamic DNS Services:")
                for service in ddns_services_v4:
                    service_name = service.get('profile', {}).get('ipv4', {}).get('profile_name', '')
                    service_provider = service.get('profile', {}).get('ipv4', {}).get('provider', '')
                    service_status = service.get('profile', {}).get('ipv4', {}).get('enable', False)
                    service_domain = service.get('profile', {}).get('ipv4', {}).get('domain', '')
                    print(f"  - Profile Name: {service_name}, Domain: {service_domain}, Provider: {service_provider}: {'enabled' if service_status else 'disabled'}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv4 dynamic DNS services found.")

            update_routine_results(routine_results, firewall, 'ddns_services_v4', ddns_services_v4)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv4 dynamic DNS services found")
            print(ddns_services_v4)
            print(type(ddns_services_v4))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving IPv4 dynamic DNS services: {e}")

    try:
        ddns_services_v6 = get_request(api_base, api_session, '/api/sonicos/dynamic-dns/profiles/ipv6')
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining IPv6 dynamic DNS service count.")
                print(ddns_services_v6)
                print(type(ddns_services_v6))

            if ddns_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ddns_count} IPv6 dynamic DNS services configured.")
                print("IPv6 Dynamic DNS Services:")
                for service in ddns_services_v6:
                    service_name = service.get('profile', {}).get('ipv6', {}).get('profile_name', '')
                    service_provider = service.get('profile', {}).get('ipv6', {}).get('provider', '')
                    service_status = service.get('profile', {}).get('ipv6', {}).get('enable', False)
                    service_domain = service.get('profile', {}).get('ipv6', {}).get('domain', '')
                    print(f"  - Profile Name: {service_name}, Domain: {service_domain}, Provider: {service_provider}: {'enabled' if service_status else 'disabled'}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv6 dynamic DNS services found.")

            update_routine_results(routine_results, firewall, 'ddns_services_v6', ddns_services_v6)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No IPv6 dynamic DNS services found")
            print(ddns_services_v6)
            print(type(ddns_services_v6))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving IPv6 dynamic DNS services: {e}")

    print()

    # Check Clearpass/NAC status
    try:
        clearpass_base = get_request(api_base, api_session, '/api/sonicos/network-access-control/clearpass/base')
        if clearpass_base:
            clearpass_enabled = clearpass_base.get('network_access_control', {}).get('clearpass', {}).get('enable', False)
            if clearpass_enabled:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is enabled. Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is not enabled.")

            update_routine_results(routine_results, firewall, 'clearpass_base', clearpass_base)

        clearpass_servers = get_request(api_base, api_session, '/api/sonicos/network-access-control/clearpass/servers')
        if clearpass_servers:
            update_routine_results(routine_results, firewall, 'clearpass_servers', clearpass_servers)
            print("Clearpass/NAC Servers:")
            for server in clearpass_servers.get('network_access_control', {}).get('clearpass', {}).get('server', []):
                server_host = server.get('name', '')
                server_port = server.get('port', '')
                print(f"  - {server_host}, port {server_port}")
        elif not clearpass_servers:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is enabled but no servers found.")
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Clearpass/NAC information: {e}")


    # List SNMPv3 users
    try:
        snmpv3_users = get_request(api_base, api_session, '/api/sonicos/snmp/users')
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SNMP user count.")
                print(snmpv3_users)
                print(type(snmpv3_users))

            if snmpv3_user_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {snmpv3_user_count} SNMP users configured.")
                print("SNMPv3 Users:")
                for user in snmpv3_users['snmp'].get('user', []):
                    user_name = user.get('name', '')
                    user_level = user.get('security_level', {}).get('authentication_only', None) or user.get('security_level', {}).get('authentication_and_privacy', None) or None
                    user_level_key = list(user.get('security_level', {}).keys())
                    user_level_key = user_level_key[0] if user_level_key else None
                    print(f"  - {user_name}, Security Level: {user_level_key if user_level else None}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SNMP users found.")

            update_routine_results(routine_results, firewall, 'snmp_users', snmpv3_users)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SNMP users found")
            print(snmpv3_users)
            print(type(snmpv3_users))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SNMP users: {e}")

    print()

    # Cloud Secure Edge (CSE)
    try:
        cse_info = get_request(api_base, api_session, '/api/sonicos/cloud-secure-edge/base')
        if cse_info:
            cse_enabled = cse_info.get('cloud_secure_edge', {}).get('created', False)
            if cse_enabled:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is enabled. Reset the Cloud Secure Edge connector authentication key.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is not enabled.")

            update_routine_results(routine_results, firewall, 'cse_info', cse_info)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No CSE information found")
            print(cse_info)
            print(type(cse_info))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving CSE information: {e}")

    print()

    # Email Logging
    try:
        email_logging = get_request(api_base, api_session, '/api/sonicos/log/automation')
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

            if pop3_password or smtp_password or (ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None):
                print("Log Automation:")
            if pop3_password:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: POP3 password is set for {pop3_username}@{pop3_server}. Please update the account's password, then update it in SonicOS.")

            if smtp_password:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: SMTP password is set for {smtp_user}@{mail_server}. Please update the account's password, then update it in SonicOS.")

            if ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")

            update_routine_results(routine_results, firewall, 'email_logging', email_logging)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No log automation information found")
            print(email_logging)
            print(type(email_logging))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving log automation information: {e}")

    print()

    # Packet Monitor FTP Logging.
    try:
        pktmon_settings = get_request(api_base, api_session, '/api/sonicos/packet-monitor/base')
        if pktmon_settings:
            pktmon_ftp = pktmon_settings.get('packet_monitor', {}).get('ftp', None)
            if pktmon_ftp:
                ftp_server = pktmon_ftp.get('server', None)
                ftp_username = pktmon_ftp.get('login', None)
                ftp_password = pktmon_ftp.get('password', None)

                if ftp_password and ftp_server != "0.0.0.0" and ftp_server != "" and ftp_server is not None:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Packet Monitor FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Could not retrieve the Packet Monitor FTP settings.")
            update_routine_results(routine_results, firewall, 'packetmonitor_ftp', pktmon_ftp)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Packet Monitor information found")
            print(pktmon_settings)
            print(type(pktmon_settings))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Packet Monitor information: {e}")

    print()

    # Settings/TSR scheduled exports
    try:
        scheduled_exports = get_request(api_base, api_session, '/api/sonicos/ftp/base')
        if scheduled_exports:
            ftp_server = scheduled_exports.get('server', None)
            ftp_username = scheduled_exports.get('user', None)
            ftp_password = scheduled_exports.get('password', None)

            if ftp_password and ftp_server != "0.0.0.0" and ftp_server != "" and ftp_server is not None:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings/TSR scheduled export FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")
            update_routine_results(routine_results, firewall, 'scheduled_exports', scheduled_exports)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No settings/TSR scheduled exports information found")
            print(scheduled_exports)
            print(type(scheduled_exports))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving settings/TSR scheduled exports information: {e}")

    print()

    # Dynamic Address External Objects
    try:
        dynamic_address_objects = get_request(api_base, api_session, '/api/sonicos/dynamic-external-objects')
        # print(dynamic_address_objects)
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
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining dynamic address object count.")
                print(dynamic_address_objects)
                print(type(dynamic_address_objects))

            if dynamic_object_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {dynamic_object_count} dynamic address objects configured.")
                print("Dynamic Address Objects:")
                for obj in dynamic_address_objects.get('dynamic_external_objects', []):
                    obj_name = obj.get('name', '')
                    obj_protocol = obj.get('protocol', '')
                    obj_server = obj.get('server', {}).get('value', '')
                    obj_username = obj.get('login', '')
                    obj_url = obj.get('url', '')
                    if obj_protocol == 'https':
                        print(f"  - {obj_name}: Protocol: {obj_protocol}, URL: {obj_url}")
                    elif obj_protocol == 'ftp':
                        print(f"  - {obj_name}: Protocol: {obj_protocol}, Server: {obj_server}, Username: {obj_username}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No dynamic address objects found.")

            update_routine_results(routine_results, firewall, 'dynamic_address_objects', dynamic_address_objects)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No dynamic address objects found")
            print(dynamic_address_objects)
            print(type(dynamic_address_objects))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving dynamic address objects: {e}")

    print()


    # Dynamic Botnet List
    try:
        dynamic_botnet_list = get_request(api_base, api_session, '/api/sonicos/botnet/base')
        # print(dynamic_botnet_list)
        if dynamic_botnet_list:
            botnet_dynlist_enabled = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('enable', False)
            botnet_dynlist_protocol = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('protocol', None)
            botnet_dynlist_ftp_server = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp', {}).get('server_ip_address', None)
            botnet_dynlist_ftp_username = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp', {}).get('login', None)
            botnet_dynlist_ftp_password = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp', {}).get('password', None)
            botnet_dynlist_https_username = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('https', {}).get('login', None)
            botnet_dynlist_https_password = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('https', {}).get('password', None)
            botnet_dynlist_https_url = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('https', {}).get('url_name', None)
            if botnet_dynlist_protocol == 'ftp':
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: A Dynamic Botnet List Server is configured. Protocol: {botnet_dynlist_protocol}, {botnet_dynlist_ftp_username}@{botnet_dynlist_ftp_server}. Please update the password on the server, then update it in SonicOS.")
            elif botnet_dynlist_protocol == 'https':
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: A Dynamic Botnet List Server is configured. Protocol: {botnet_dynlist_protocol}, URL: {botnet_dynlist_https_url}, Login: {botnet_dynlist_https_username}. Please update the password on the server, then update it in SonicOS.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Dynamic Botnet List Server is not configured.")

            update_routine_results(routine_results, firewall, 'dynamic_botnet_list_server', dynamic_botnet_list)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No dynamic botnet list information found")
            print(dynamic_botnet_list)
            print(type(dynamic_botnet_list))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving dynamic botnet list information: {e}")

    print()

    # Extended Switches
    try:
        ext_switches = get_request(api_base, api_session, '/api/sonicos/switch-controller/switch-info')
        if ext_switches:
            ext_switch_count = 0
            try:
                ext_switch_key = ext_switches.get('switch_controller', {}).get('switch_info', {})
                if isinstance(ext_switch_key, list):
                    ext_switch_count = len(ext_switch_key)
                elif isinstance(ext_switch_key, dict) and ext_switch_count == {}:
                    ext_switch_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining extended switch count.")
                print(ext_switches)
                print(type(ext_switches))

            if ext_switch_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ext_switch_count} extended switches configured.")
                print("Extended Switches:")
                for switch in ext_switches.get('switch_controller', {}).get('switch_info', []):
                    switch_id = switch.get('id', None)
                    switch_name = switch.get('name', '')
                    switch_serial = switch.get('serial', '')
                    if switch_id:
                        print(f"  - {switch_name} ({switch_serial})")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switches found.")

            update_routine_results(routine_results, firewall, 'extended_switches', ext_switches)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switches found")
            print(ext_switches)
            print(type(ext_switches))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switches: {e}")

    print()

    # Extended Switches - Users
    try:
        switch_users = get_request(api_base, api_session, '/api/sonicos/switch-controller/user')
        if switch_users:
            switch_user_count = 0
            try:
                switch_user_key = switch_users.get('switch_controller', {}).get('user', {})
                if isinstance(switch_user_key, list):
                    switch_user_count = len(switch_user_key)
                elif isinstance(switch_user_key, dict) and switch_user_key == {}:
                    switch_user_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining extended switch user count.")
                print(switch_users)
                print(type(switch_users))

            if switch_user_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {switch_user_count} extended switch users configured.")
                print("Extended Switch Users:")
                for user in switch_users.get('switch_controller', {}).get('user', []):
                    user_name = user.get('user_name', '')
                    user_switch = user.get('switch', '')
                    user_priv = user.get('privilege_type', '')
                    print(f"  - {user_name} on switch {user_switch}, Privilege: {user_priv}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch users found.")

            update_routine_results(routine_results, firewall, 'extended_switch_users', switch_users)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch users found")
            print(switch_users)
            print(type(switch_users))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switch users: {e}")

    print()

    # Extended Switches - RADIUS Servers
    try:
        switch_radius = get_request(api_base, api_session, '/api/sonicos/switch-controller/radius')
        if switch_radius:
            switch_radius_count = 0
            try:
                switch_radius_key = switch_radius.get('switch_controller', {}).get('radius', {})
                if isinstance(switch_radius_key, list):
                    switch_radius_count = len(switch_radius_key)
                elif isinstance(switch_radius_key, dict) and switch_radius_key == {}:
                    switch_radius_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining extended switch RADIUS server count.")
                print(switch_radius)
                print(type(switch_radius))

            if switch_radius_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {switch_radius_count} extended switch RADIUS servers configured.")
                print("Extended Switch RADIUS Servers:")
                for server in switch_radius.get('switch_controller', {}).get('radius', []):
                    server_ip = server.get('server_ip', '')
                    server_switch = server.get('switch', '')
                    print(f"  - {server_ip} a {server_switch}")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch RADIUS servers found.")

            update_routine_results(routine_results, firewall, 'extended_switch_radius_servers', switch_radius)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No extended switch RADIUS servers found")
            print(switch_radius)
            print(type(switch_radius))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switch RADIUS servers: {e}")

    print()

    # Zone Objects: WLAN RADIUS Server
    try:
        all_zone_objects = get_request(api_base, api_session, '/api/sonicos/zones')
        zone_objects = [z for z in all_zone_objects.get('zones', []) if z.get('security_type', '').lower() == 'wireless']
        if zone_objects:
            if len(zone_objects) > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: WLAN Local RADIUS Server:")
            try:
                for zone in zone_objects:
                    if zone.get('security_type', '').lower() == 'wireless':
                        radius_server_enabled = zone.get('local_radius_server', {}).get('enable', False)
                        ldap_server_enabled = zone.get('local_radius_server', {}).get('ldap_server', {}).get('enable', False)
                        ldap_server_host = zone.get('local_radius_server', {}).get('ldap_server', {}).get('server', None)
                        if radius_server_enabled:
                            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}:  - Local RADIUS server is enabled on Zone {zone.get('name', '')}. Please update the RADIUS server client password.")
                        if ldap_server_enabled or ldap_server_host:
                            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}:  - LDAP server is enabled on Zone {zone.get('name', '')}, Host: {ldap_server_host}. Please update the LDAP server password, then update it in SonicOS.")
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving WLAN RADIUS Server configuration from zone objects.")
                print(zone_objects)
                print(type(zone_objects))

            update_routine_results(routine_results, firewall, 'wlan_radius_servers', zone_objects)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No zone objects found")
            print(zone_objects)
            print(type(zone_objects))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving zone objects: {e}")

    print()

    # Guest Services External Guest Authentication (Message Authentication)
    # This flags when the Message Authentication option is enabled under Guest Services > External Guest Authentication
    try:
        guest_zones = [z for z in all_zone_objects.get('zones', []) if z.get('guest_services', {}).get('external_auth', {}).get('message_auth', {}).get('enable', False)]
        if guest_zones:
            if len(guest_zones) > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Guest Services External Guest Authentication (Message Authentication):")
            try:
                for zone in guest_zones:
                    guest_auth_ext_enabled = zone.get('guest_services', {}).get('external_auth', {}).get('message_auth', {}).get('enable', False)
                    if guest_auth_ext_enabled:
                        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}:  - External Guest Authentication is enabled on Zone {zone.get('name', '')}. Please update the message authentication shared secret.")
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Guest Services External Guest Authentication configuration from zone objects.")
                print(guest_zones)
                print(type(guest_zones))

            update_routine_results(routine_results, firewall, 'guest_services_external_auth', guest_zones)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No zone objects with Guest Services External Guest Authentication found")
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving zone objects for Guest Services: {e}")

    print()

    # SSO Agents
    try:
        sso_agents = get_request(api_base, api_session, '/api/sonicos/user/sso/agents')
        if sso_agents:
            sso_agent_count = 0
            try:
                sso_agent_key = sso_agents.get('user', {}).get('sso', {}).get('agent', {})
                if isinstance(sso_agent_key, list):
                    sso_agent_count = len(sso_agent_key)
                elif isinstance(sso_agent_key, dict) and sso_agent_key == {}:
                    sso_agent_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SSO agent count.")
                print(sso_agents)
                print(type(sso_agents))

            if sso_agent_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sso_agent_count} SSO Agent(s) configured.")
                print("SSO Agents:")
                for agent in sso_agents.get('user', {}).get('sso', {}).get('agent', []):
                    agent_status = agent.get('enable', '')
                    agent_host = agent.get('host', '')
                    agent_port = agent.get('port', '')
                    agent_shared_secret = agent.get('shared_key', None)
                    if agent_shared_secret:
                        print(f"  - {agent_host}, port {agent_port} ({'enabled' if agent_status else 'disabled'}): Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO agents found.")

            update_routine_results(routine_results, firewall, 'sso_agents', sso_agents)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO Agents found")
            print(sso_agents)
            print(type(sso_agents))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO Agents: {e}")

    print()

    # Terminal Server Agent (TSA)
    try:
        ts_agents = get_request(api_base, api_session, '/api/sonicos/user/sso/terminal-services-agents')
        if ts_agents:
            ts_agent_count = 0
            try:
                ts_agent_key = ts_agents.get('user', {}).get('sso', {}).get('terminal_services_agent', {})
                if isinstance(ts_agent_key, list):
                    ts_agent_count = len(ts_agent_key)
                elif isinstance(ts_agent_key, dict) and ts_agent_key == {}:
                    ts_agent_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining TS Agent count.")
                print(ts_agents)
                print(type(ts_agents))

            if ts_agent_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ts_agent_count} TS Agent(s) configured.")
                print("Terminal Services Agents:")
                for agent in ts_agents.get('user', {}).get('sso', {}).get('terminal_services_agent', []):
                    agent_status = agent.get('enable', '')
                    agent_host = agent.get('host', '')
                    agent_port = agent.get('port', '')
                    agent_shared_secret = agent.get('shared_key', None)
                    if agent_shared_secret:
                        print(f"  - {agent_host}, port {agent_port} ({'enabled' if agent_status else 'disabled'}): Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TS agents found.")

            update_routine_results(routine_results, firewall, 'tsa_agents', ts_agents)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TS agents found")
            print(ts_agents)
            print(type(ts_agents))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving TSA agents: {e}")

    print()

    # SSO RADIUS Accounting Clients
    try:
        sso_radius_clients = get_request(api_base, api_session, '/api/sonicos/user/sso/radius-accounting-clients')
        if sso_radius_clients:
            sso_radius_client_count = 0
            try:
                sso_radius_client_key = sso_radius_clients.get('user', {}).get('sso', {}).get('radius_accounting_client', {})
                if isinstance(sso_radius_client_key, list):
                    sso_radius_client_count = len(sso_radius_client_key)
                elif isinstance(sso_radius_client_key, dict) and sso_radius_client_key == {}:
                    sso_radius_client_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SSO RADIUS client count.")
                print(sso_radius_clients)
                print(type(sso_radius_clients))

            if sso_radius_client_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sso_radius_client_count} SSO RADIUS Client(s) configured.")
                print("SSO RADIUS Clients:")
                for client in sso_radius_clients.get('user', {}).get('sso', {}).get('radius_accounting_client', []):
                    client_host = client.get('host', '')
                    client_shared_secret = client.get('shared_secret', None)
                    if client_shared_secret:
                        print(f"  - {client_host}: Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO RADIUS clients found.")

            update_routine_results(routine_results, firewall, 'sso_radius_clients', sso_radius_clients)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO RADIUS clients found")
            print(sso_radius_clients)
            print(type(sso_radius_clients))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO RADIUS clients: {e}")

    print()

    # 3rd Party SSO API Clients
    try:
        sso_api_clients = get_request(api_base, api_session, '/api/sonicos/user/sso/third-party-api/clients')
        if sso_api_clients:
            sso_api_client_count = 0
            try:
                sso_api_client_key = sso_api_clients.get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', {})
                if isinstance(sso_api_client_key, list):
                    sso_api_client_count = len(sso_api_client_key)
                elif isinstance(sso_api_client_key, dict) and sso_api_client_key == {}:
                    sso_api_client_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SSO API client count.")
                print(sso_api_clients)
                print(type(sso_api_clients))

            if sso_api_client_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {sso_api_client_count} SSO API Client(s) configured.")
                print("SSO API Clients:")
                for client in sso_api_clients.get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []):
                    client_host = client.get('host', '')
                    client_shared_secret = client.get('shared_secret', None)
                    if client_host and not client_shared_secret:
                        print(f"  - {client_host}: Please consider setting a shared secret.")
                    elif client_shared_secret:
                        print(f"  - {client_host}: Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO API clients found.")

            update_routine_results(routine_results, firewall, 'sso_api_clients', sso_api_clients)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SSO API clients found")
            print(sso_api_clients)
            print(type(sso_api_clients))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO API clients: {e}")

    print()

    # RADIUS Accounting Servers (Users > Settings > Accounting > RADIUS Accounting)
    try:
        acct_servers = get_request(api_base, api_session, '/api/sonicos/user/radius/accounting/servers')
        if acct_servers:
            acct_server_count = 0
            try:
                acct_server_key = acct_servers.get('user', {}).get('radius', {}).get('accounting', {}).get('server', {})
                if isinstance(acct_server_key, list):
                    acct_server_count = len(acct_server_key)
                elif isinstance(acct_server_key, dict) and acct_server_key == {}:
                    acct_server_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining RADIUS accounting server count.")
                print(acct_servers)
                print(type(acct_servers))

            if acct_server_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {acct_server_count} RADIUS Accounting Server(s) configured.")
                print("RADIUS Accounting Servers:")
                for server in acct_servers.get('user', {}).get('radius', {}).get('accounting', {}).get('server', []):
                    server_host = server.get('host', '')
                    server_port = server.get('port', 0)
                    server_status = server.get('enable', False)
                    server_shared_secret = server.get('shared_secret', None)
                    if server_shared_secret:
                        print(f"  - {server_host}, port {server_port} ({'enabled' if server_status else 'disabled'}): Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS accounting servers found.")

            update_routine_results(routine_results, firewall, 'radius_accounting_servers', acct_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No RADIUS accounting servers found")
            print(acct_servers)
            print(type(acct_servers))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving RADIUS accounting servers: {e}")

    print()

    # TACACS+ Servers (Users > Settings > Accounting > TACACS+)
    try:
        tacacs_servers = get_request(api_base, api_session, '/api/sonicos/user/tacacs/accounting/servers')
        if tacacs_servers:
            tacacs_server_count = 0
            try:
                tacacs_server_key = tacacs_servers.get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', {})
                if isinstance(tacacs_server_key, list):
                    tacacs_server_count = len(tacacs_server_key)
                elif isinstance(tacacs_server_key, dict) and tacacs_server_key == {}:
                    tacacs_server_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining TACACS+ server count.")
                print(tacacs_servers)
                print(type(tacacs_servers))

            if tacacs_server_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {tacacs_server_count} TACACS+ Server(s) configured.")
                print("TACACS+ Servers:")
                for server in tacacs_servers.get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []):
                    server_host = server.get('host', '')
                    server_port = server.get('port', '')
                    server_status = server.get('enable', '')
                    server_shared_secret = server.get('shared_secret', None)
                    if server_shared_secret:
                        print(f"  - {server_host}, port {server_port} ({'enabled' if server_status else 'disabled'}): Please update the shared secret.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS+ servers found.")

            update_routine_results(routine_results, firewall, 'tacacs_accounting_servers', tacacs_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No TACACS+ servers found")
            print(tacacs_servers)
            print(type(tacacs_servers))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving TACACS+ servers: {e}")

    print()

    # AppFlow SFR Reporting
    try:
        sfr = get_request(api_base, api_session, '/api/sonicos/appflow/sfr-mailing/base')
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

            if sfr_server != "" and sfr_server is not None and sfr_password:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AppFlow SFR Mailing SMTP server is configured to use {sfr_username}@{sfr_server}. Please update the account's password, then update it in SonicOS.")

            if sfr_server_pop != "" and sfr_server_pop is not None and sfr_password_pop:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: AppFlow SFR Mailing POP server is configured to use {sfr_username_pop}@{sfr_server_pop}. Please update the account's password, then update it in SonicOS.")
            update_routine_results(routine_results, firewall, 'sfr_reporting', sfr)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No AppFlow SFR reporting information found")
            print(sfr)
            print(type(sfr))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving AppFlow SFR reporting information: {e}")

    print()

    # Custom NTP Servers
    try:
        ntp_servers = get_request(api_base, api_session, '/api/sonicos/time/ntp-servers')
        if ntp_servers:
            ntp_server_count = 0
            try:
                ntp_server_key = ntp_servers.get('time', {}).get('ntp_server', {})
                if isinstance(ntp_server_key, list):
                    ntp_server_count = len([x for x in ntp_server_key if x.get('no_auth', False) is False])
                elif isinstance(ntp_server_key, dict) and ntp_server_key == {}:
                    ntp_server_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining NTP server count.")
                print(ntp_servers)
                print(type(ntp_servers))

            if ntp_server_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {ntp_server_count} NTP Server(s) with authentication configured.")
                print("NTP Servers with authentication:")
                for server in ntp_servers.get('time', {}).get('ntp_server', {}):
                    server_host = server.get('name', '')
                    server_auth = server.get('no_auth', False)
                    if server_host and server_auth is False:
                        print(f"  - {server_host} ({'auth disabled' if server_auth else 'auth enabled'}): Please update the password at the server, then update it in SonicOS.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No NTP servers found.")

            update_routine_results(routine_results, firewall, 'ntp_servers', ntp_servers)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No NTP servers found")
            print(ntp_servers)
            print(type(ntp_servers))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving NTP servers: {e}")

    print()

    # Security Services Signature Proxy
    try:
        security_services = get_request(api_base, api_session, '/api/sonicos/security-services/base')
        if security_services:
            sig_proxy_enabled = security_services.get('security_services', {}).get('proxy_server', {}).get('enable', False)
            sig_proxy_auth = security_services.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False)
            sig_proxy_host = security_services.get('security_services', {}).get('proxy_server', {}).get('host', '')
            sig_proxy_username = security_services.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', '')
            sig_proxy_password = security_services.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('password', None)

            if sig_proxy_auth or sig_proxy_username:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Security Services Signature Proxy authentication is configured with user '{sig_proxy_username}', host '{sig_proxy_host}'. Please update the account's password, then update it in SonicOS.")

            update_routine_results(routine_results, firewall, 'security_services_signature_proxy', security_services)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Security Services Signature Proxy information found")
            print(security_services)
            print(type(security_services))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Security Services Signature Proxy information: {e}")

    print()

    # GMS IPsec Management Tunnel
    try:
        gms_config = get_request(api_base, api_session, '/api/sonicos/administration/global')
        gms_config = gms_config.get('administration', {}).get('gms_management', {})
        if gms_config:
            ipsec_management = gms_config.get('ipsec_tunnel', False)
            if ipsec_management:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: GMS Management:")
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: - GMS IPSec Management Tunnel is configured. Please ensure the encryption/authentication keys are updated.")
            update_routine_results(routine_results, firewall, 'gms_ipsec_management_tunnel', gms_config)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No GMS IPsec Management Tunnel information found")
            print(gms_config)
            print(type(gms_config))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving GMS IPsec Management Tunnel information: {e}")

    print()

    # Advanced Routing Protocols (RIP, OSPFv2, BGP)
    routing_adv_data = get_request(api_base, api_session, '/api/sonicos/dynamic-file/getAdvancedRoutingData.json')
    if routing_adv_data:
        try:
            adv_routing_enabled = routing_adv_data.get('data', {}).get('ipv4', {}).get('advancedRoutingEnabled', False)
            bgp_enabled = routing_adv_data.get('data', {}).get('ipv4', {}).get('isBGPEnabled', False)
            routing_interfaces = routing_adv_data.get('data', {}).get('ipv4', {}).get('interfaces', [])
            for intf in routing_interfaces:
                intf_name = intf.get('name', '')
                intf_zone = intf.get('zone', '')
                intf_rip = intf.get('RIP', {}).get('status', '')
                intf_rip_password = intf.get('RIP', {}).get('password', '')
                intf_ospfv2 = intf.get('OSPFv2', {}).get('status', False)
                intf_ospfv2_authentication = intf.get('OSPFv2', {}).get('authentication', False)
                intf_ospfv2_password = intf.get('OSPFv2', {}).get('password', '')

                if intf_rip == 'disabled':
                    intf_rip = False
                else:
                    intf_rip = True

                if intf_ospfv2 == 'disabled':
                    intf_ospfv2 = False
                else:
                    intf_ospfv2 = True

                if intf_ospfv2_authentication == 'disabled':
                    intf_ospfv2_authentication = False
                else:
                    intf_ospfv2_authentication = True

                if intf_rip or intf_rip_password != '':
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Routing - RIP is enabled or password is set on interface {intf_name}. Please ensure any RIP passwords are updated.")
                if intf_ospfv2 or intf_ospfv2_authentication or intf_ospfv2_password != '':
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Routing - OSPFv2 is enabled or password is set on interface {intf_name}. Please ensure any OSPFv2 passwords are updated.")
                if bgp_enabled:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Routing - BGP is enabled on interface {intf_name}. Please ensure any BGP passwords are updated.")
            update_routine_results(routine_results, firewall, 'advanced_routing_protocols', routing_adv_data)
        except (KeyError, TypeError) as e:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Advanced Routing Protocols configuration.")
            print(routing_adv_data)
            print(type(routing_adv_data))
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Advanced Routing Protocols information found")
        print(routing_adv_data)
        print(type(routing_adv_data))

    print()

    # Cellular WWAN
    cellular = get_request(api_base, api_session, '/api/sonicos/reporting/wwan')
    if isinstance(cellular, list) and len(cellular) > 0:
        try:
            for wwan in cellular:
                wwan_attached = wwan.get('modem_attached', 0)
                wwan_name = wwan.get('vendor_name', None)

                if wwan_attached != 0 or wwan_name is not None:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: WWAN modem attached: {wwan_attached}/'{wwan_name}'. Please update the account's password, then update it in SonicOS.")
            update_routine_results(routine_results, firewall, 'cellular_wwan', cellular)
        except (KeyError, TypeError) as e:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving WWAN modem configuration.")
            print(cellular)
            print(type(cellular))

    # Wireless SonicPoint/SonicWave/Virtual Access Points. Preshared keys, RADIUS shared secrets, etc.
    # Virtual Access Points and Virtual Access Point Profiles
    try:
        vaps = get_request(api_base, api_session, '/api/sonicos/wireless/virtual-access-point/objects')
        if vaps.get('status', {}).get('info', None):
            msg = vaps.get('status', {}).get('info', None)[0]['message']
            code = vaps.get('status', {}).get('info', None)[0]['code']
            if code == "E_NOT_FOUND":
                vaps = get_request(api_base, api_session, '/api/sonicos/sonicpoint/virtual-access-point/objects')

        if vaps:
            vap_count = 0
            try:
                vap_key = vaps.get('wireless', {}).get('virtual_access_point', {}).get('object', {}) or vaps.get('sonicpoint', {}).get('virtual_access_point', {}).get('object', {})
                if isinstance(vap_key, list):
                    vap_count = len(vap_key)
                elif isinstance(vap_key, dict) and vap_key == {}:
                    vap_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining VAP count.")
                print(vaps)
                print(type(vaps))

            if vap_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vap_count} Virtual Access Point(s) configured.")
                print("Virtual Access Points:")
                all_vaps = vaps.get('wireless', {}).get('virtual_access_point', {}).get('object', []) or vaps.get('sonicpoint', {}).get('virtual_access_point', {}).get('object', [])
                for vap in all_vaps:
                    vap_name = vap.get('name', '')
                    vap_ssid = vap.get('ssid', '')
                    vap_vlan = vap.get('vlan', '')
                    vap_status = vap.get('enable', '')
                    vap_security = vap.get('authentication_type', {})
                    vap_radius = vap.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    vap_accounting = vap.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or vap.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    if vap_name:
                        print(f"  - {vap_name}, SSID: {vap_ssid}, VLAN: {vap_vlan} ({'enabled' if vap_status else 'disabled'}): Please update the pre-shared key.")
                        if vap_radius:
                            print(f"    - RADIUS is configured on the VAP. Please ensure the RADIUS server shared secret is updated.")
                        if vap_accounting:
                            print(f"    - RADIUS Accounting is configured on the VAP. Please ensure the RADIUS Accounting server shared secret is updated.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Virtual Access Points found.")

            update_routine_results(routine_results, firewall, 'virtual_access_points', vaps)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Virtual Access Points found")
            print(vaps)
            print(type(vaps))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Virtual Access Points: {e}")

    print()

    # Virtual Access Point Profiles
    try:
        vap_profiles = get_request(api_base, api_session, '/api/sonicos/wireless/virtual-access-point/profiles')
        if vap_profiles.get('status', {}).get('info', None):
            msg = vap_profiles.get('status', {}).get('info', None)[0]['message']
            code = vap_profiles.get('status', {}).get('info', None)[0]['code']
            if code == "E_NOT_FOUND":
                vap_profiles = get_request(api_base, api_session, '/api/sonicos/sonicpoint/virtual-access-point/profiles')

        if vap_profiles:
            vap_profile_count = 0
            try:
                vap_profile_key = vap_profiles.get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', {})
                if isinstance(vap_profile_key, list):
                    vap_profile_count = len(vap_profile_key)
                elif isinstance(vap_profile_key, dict) and vap_profile_key == {}:
                    vap_profile_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining VAP profile count.")
                print(vap_profiles)
                print(type(vap_profiles))

            if vap_profile_count > 0:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {vap_profile_count} Virtual Access Point Profile(s) configured.")
                print("Virtual Access Point Profiles:")
                all_vap_profiles = vap_profiles.get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', [])
                for profile in all_vap_profiles:
                    profile_name = profile.get('name', '')
                    profile_security = profile.get('authentication_type', {})
                    profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                    profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                    if profile_name:
                        print(f"  - {profile_name}: Please update the pre-shared key.")
                        if profile_radius:
                            print(f"    - RADIUS is configured on the VAP Profile. Please ensure the RADIUS server shared secret is updated.")
                        if profile_accounting:
                            print(f"    - RADIUS Accounting is configured on the VAP Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Virtual Access Point Profiles found.")
            update_routine_results(routine_results, firewall, 'virtual_access_point_profiles', vap_profiles)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No Virtual Access Point Profiles found")
            print(vap_profiles)
            print(type(vap_profiles))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving Virtual Access Point Profiles: {e}")

    print()

    # Wireless Access Points (SonicPoint/SonicWave Profiles and Objects
    # SonicPoint/SonicWave Profiles
    try:
        sp_profiles = get_request(api_base, api_session, '/api/sonicos/sonicpoint/profiles')
        if sp_profiles:
            sp_profile_count = 0
            try:
                sp_profile_key = sp_profiles.get('sonicpoint', {}).get('profile', {})
                if isinstance(sp_profile_key, list):
                    sp_profile_count = len(sp_profile_key)
                elif isinstance(sp_profile_key, dict) and sp_profile_key == {}:
                    sp_profile_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave profile count.")
                print(sp_profiles)
                print(type(sp_profiles))

            if sp_profile_count > 0:
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
                    if profile_name:
                        print(f"  - {profile_name}: Please update the pre-shared key.")
                        if profile_radius and (profile_radius != '' and profile_radius != '0.0.0.0'):
                            print(f"    - RADIUS is configured on the SonicPoint/SonicWave Profile. Please ensure the RADIUS server shared secret is updated.")
                        if profile_accounting and (profile_accounting != '' and profile_accounting != '0.0.0.0'):
                            print(f"    - RADIUS Accounting is configured on the SonicPoint/SonicWave Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
                        if profile_administrator:
                            print(f"    - Administrator account '{profile_administrator}' is set on the SonicPoint/SonicWave Profile. Please ensure the administrator account password is updated.")
                        if profile_sslvpn_server or profile_sslvpn_user:
                            print(f"    - L3 SSLVPN Management is configured on the SonicPoint/SonicWave Profile ({profile_sslvpn_user}@{profile_sslvpn_server}). Please ensure the SSLVPN server and user account password is updated.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Profiles found.")

            update_routine_results(routine_results, firewall, 'sonicpoint_sonicwave_profiles', sp_profiles)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Profiles found")
            print(sp_profiles)
            print(type(sp_profiles))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Profiles: {e}")

    print()

    # SonicPoint/SonicWave Objects
    try:
        sp_objects = get_request(api_base, api_session, '/api/sonicos/sonicpoint/sonicpoints')
        if sp_objects:
            sp_object_count = 0
            try:
                sp_object_key = sp_objects.get('sonicpoint', {}).get('sonicpoint', {})
                if isinstance(sp_object_key, list):
                    sp_object_count = len(sp_object_key)
                elif isinstance(sp_object_key, dict) and sp_object_key == {}:
                    sp_object_count = 0
            except (KeyError, TypeError):
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave object count.")
                print(sp_objects)
                print(type(sp_objects))

            if sp_object_count > 0:
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
                    if obj:
                        print(f"  - {obj}: Please update the pre-shared key.")
                        if obj_radius and (obj_radius != '' and obj_radius != '0.0.0.0'):
                            print(f"    - RADIUS is configured on the SonicPoint/SonicWave Object. Please ensure the RADIUS server shared secret is updated.")
                        if obj_accounting and (obj_accounting != '' and obj_accounting != '0.0.0.0'):
                            print(f"    - RADIUS Accounting is configured on the SonicPoint/SonicWave Object. Please ensure the RADIUS Accounting server shared secret is updated.")
                        if obj_administrator:
                            print(f"    - Administrator account '{obj_administrator}' is set on the SonicPoint/SonicWave Object. Please ensure the administrator account password is updated.")
                        if obj_sslvpn_server or obj_sslvpn_user:
                            print(f"    - L3 SSLVPN Management is configured on the SonicPoint/SonicWave Object ({obj_sslvpn_user}@{obj_sslvpn_server}). Please ensure the SSLVPN server and user account password is updated.")
            else:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Objects found.")

            update_routine_results(routine_results, firewall, 'sonicpoint_sonicwave_objects', sp_objects)
        else:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Objects found")
            print(sp_objects)
            print(type(sp_objects))
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Objects: {e}")

    print()

    # TODO: The checks above need to be compiled into functions to reduce the size of this routine function.
    # TODO: The checks need a summary/report in a friendly table.

    # Step 6: Process user operations (if enabled)
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
            users, api_session, api_base, temp_password, firewall_info['firewall_generation'],
            firewall, sshport, username, password, target_numbers, a)

        routine_results[firewall]['users'] = user_results
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: Force password change logic is disabled. Enable it with -fpc.")
        routine_results[firewall]['force_password_change_disabled'] = True

    # Step 7: Handle TOTP unbind operations (if enabled)
    if unbind_totp or a.unbind_totp:
        totp_result = unbind_totp_from_users(api_session, api_base, firewall_info['firewall_generation'],
                                           users, target_numbers)
        update_routine_results(routine_results, firewall, 'totp_unbind', totp_result)
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: TOTP unbind logic is disabled. Enable it with -ut.")
        routine_results[firewall]['totp_unbind_disabled'] = True

    print()

    # TODO: Things to add.
    #   Force password change. - need to make sure arguments work as expected.
    #   Randomize password based on configured temporary password. Will have to provide a list of user/pass combos.

    # Step 8: Manage botnet filtering (if enabled)
    botnet_result = manage_botnet_filtering(api_session, api_base, enable_botnet_filtering,
                                          firewall_info['firewall_generation'], target_numbers, a)
    update_routine_results(routine_results, firewall, 'botnet_filtering', botnet_result)

    # Step 9: Enable TOTP on SSLVPN Services group (if enabled)
    totp_sslvpn_result = enable_totp_on_sslvpn_group(api_session, api_base, enable_totp,
                                                    firewall_info['firewall_generation'],
                                                    firewall, sshport, username, password, target_numbers)
    update_routine_results(routine_results, firewall, 'totp_sslvpn', totp_sslvpn_result)

    # Step 10: Calculate routine statistics
    calculate_routine_statistics(routine_results, firewall)

    # Step 11: Finalize routine (cleanup, write results, logout)
    finalize_routine(api_session, api_base, firewall, firewall_info['firewall_generation'],
                    sshport, username, password, target_numbers, firewall_info)

    return "ROUTINE_COMPLETE", "Routine completed successfully."


# Main function
if __name__ == "__main__":
    banner_info = [
        "This tool automates some remediation tasks such as:",
        "  - Includes checks from the 'Essential Credential Reset' KB article: https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590"
        "  - Forces all local users to update their password",
        "  - Reset TOTP binding for all users",
        "  - ...",
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
        res, res_msg = routine(target, target_numbers=(target_index+1, len(targets)))

        if not res:
            print(f"({target_index+1}/{len(targets)}) {generate_timestamp()}: Error: Routine failed. Result message: {res_msg}")

        print(f"({target_index+1}/{len(targets)}) {generate_timestamp()}: Target {target_index+1}/{len(targets)} - {fw}: Done.\n{'='*60}\n\n")

    print(f"{generate_timestamp()}: ALL DONE")
