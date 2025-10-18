import random
import string
from common.utils import generate_timestamp
from credential_reset.firewall import FirewallTarget


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


def update_routine_results(routine_results: dict, firewall: str, section: str, data):
    """Centralized function to update the routine result dictionary. If a firewall entry does not exist, it creates one.
    Args:
        routine_results (dict): The main results dictionary to update.
        firewall (str): The firewall identifier (IP or hostname).
        section (str): The section/key under which to store the data.
        data (str, list, or dict): The data to store, can be a dictionary or any other type.
    """
    if firewall not in routine_results:
        routine_results[firewall] = {}

    # If data is a dictionary, merge it; if it's a list, extend it; otherwise, set it directly.
    if isinstance(data, dict):
        routine_results[firewall].update(data)

    # Else if the section already exists and is a list, extend it; otherwise, create a new list.
    elif isinstance(data, list):
        if section in routine_results[firewall] and isinstance(routine_results[firewall][section], list):
            routine_results[firewall][section].extend(data)
        else:
            routine_results[firewall][section] = data

    # Otherwise, just set the data directly.
    else:
        routine_results[firewall][section] = data


def normalize_boolean(value: str) -> bool:
    """Convert string values to boolean."""
    if value is None:
        return False

    if isinstance(value, bool):
        return value

    if not value or str(value.lower()) in ['none', 'false', '']:
        return False

    return str(value.lower()) in ['true', 'yes', '1', 'y']


def normalize_password(password: str) -> str:
    """Normalize password, handling special comma encoding."""
    if not password or password == 'None':
        return ""
    return password.replace("<comma>", ",")


def normalize_temp_password(password: str, randomize: bool, silent: bool = False) -> str:
    """Normalize temporary password with minimum length and password complexity validation."""
    if randomize:
        password = create_random_password(length=12)
        return password

    if not password or password in ['None', 'false', '']:
        return ""

    # Make sure the password meets minimum complexity requirements.
    # Enforce minimum length of 12 characters
    if len(password) < 12:
        if not silent:
            print(f"{generate_timestamp()}: Warning: Temporary password too short, padding with 'x'")
        password += 'x' * (12 - len(password))

    # Make sure there is at least 1 uppercase character
    if not any(c.isupper() for c in password):
        if not silent:
            print(f"{generate_timestamp()}: Warning: Temporary password missing uppercase character, adding 'X'")
        password += 'X'

    # Make sure there is at least 1 lowercase character
    if not any(c.islower() for c in password):
        if not silent:
            print(f"{generate_timestamp()}: Warning: Temporary password missing lowercase character, adding 'x'")
        password += 'x'

    # Make sure there is at least 1 digit
    if not any(c.isdigit() for c in password):
        if not silent:
            print(f"{generate_timestamp()}: Warning: Temporary password missing digit, adding '1'")
        password += '1'

    # Replace any spaces with underscores
    if ' ' in password:
        if not silent:
            print(f"{generate_timestamp()}: Warning: Temporary password contains spaces, replacing with underscores")
        password = password.replace(' ', '_')

    # Replaces # with dashes to avoid errors setting password via API/CLI
    if '#' in password:
        if not silent:
            print(f"{generate_timestamp()}: Warning: Temporary password contains '#', replacing with dashes")
        password = password.replace('#', '-')

    # Replaces | with underscores to avoid errors setting password via API/CLI
    if '|' in password:
        if not silent:
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


# Severity configuration for security checks
SECURITY_CHECK_SEVERITIES = {
    # Critical severity checks
    'ldap_servers': 'critical',
    'radius_servers': 'critical',
    'tacacs_servers': 'critical',
    'vpn_policies': 'critical',
    'wan_interfaces': 'critical',
    'aws_api': 'critical',
    'cloud_secure_edge': 'critical',

    # High severity checks
    'ddns_services': 'high',
    'snmp_users': 'high',
    'clearpass_nac': 'high',
    'cellular_wwan': 'high',
    'dynamic_address_objects': 'high',

    # Medium severity checks
    'email_logging': 'medium',
    'packet_monitor_ftp': 'medium',
    'scheduled_exports': 'medium',
    'guest_services_auth': 'medium',
    'wlan_radius_servers': 'medium',
    'internal_wlan_radio': 'medium',
    'internal_wlan_vaps': 'medium',
    'internal_wlan_vap_profiles': 'medium',
    'sonicpoint_objects': 'medium',
    'sonicpoint_profiles': 'medium',
    'sonicpoint_vaps': 'medium',
    'sonicpoint_vap_profiles': 'medium',

    # Low severity checks
    'dynamic_botnet_list_server': 'low',
    'extended_switches': 'low',
    'extended_switch_users': 'low',
    'extended_switch_radius': 'low',
    'sso_agents': 'low',
    'ts_agents': 'low',
    'sso_radius_clients': 'low',
    'sso_api_clients': 'low',
    'radius_accounting_servers': 'low',
    'tacacs_accounting_servers': 'low',
    'sfr_reporting': 'low',
    'ntp_servers': 'low',
    'security_services_proxy': 'low',
    'gms_ipsec_tunnel': 'low',
    'advanced_routing': 'low'
}


def should_run_check(check_name: str, target_severity: str) -> bool:
    """
    Determine if a security check should be run based on the target severity.

    Args:
        check_name (str): Name of the security check
        target_severity (str): Target severity level ('all', 'critical', 'high', 'medium', 'low')

    Returns:
        bool: True if the check should be run, False otherwise
    """
    if target_severity == 'all':
        return True

    check_severity = SECURITY_CHECK_SEVERITIES.get(check_name)
    if check_severity is None:
        # If severity is not defined, default to running it for 'all'
        return target_severity == 'all'

    return check_severity == target_severity


def get_check_severity(check_name: str) -> str:
    """Get the severity level of a given security check."""
    return SECURITY_CHECK_SEVERITIES.get(check_name, 'unknown')

