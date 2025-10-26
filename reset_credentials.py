# Imports
import json
from typing import Optional, List
from os import path, mkdir
from common.banner import print_banner
from common.utils import (
    generate_timestamp,
    write_to_file,
)
from common.arguments import get_parser
from sonicos.api import (
    get_request,
    post_request,
    commit_pending,
    logout,
    disable_sonicos_api_ssh,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh,
    post_request_direct_cli,
)
import common.constants as constants
from sonicos.api2 import Login
from credential_reset.utils import (
    update_routine_results,
    print_verbose_details,
    normalize_password,
    normalize_temp_password,
    normalize_boolean,
    create_random_password,
    should_run_check,
    get_check_severity
)
from credential_reset.firewall import (
    FirewallTarget,
    gather_firewall_info,
    initialize_session,
    get_local_users,
)
from credential_reset.firewall_actions import unbind_totp_from_users, process_password_changes
from credential_reset.csv_helper import parse_csv_targets
from credential_reset.export_helper import (
    export_tsr_if_enabled,
    export_tracelogs_if_enabled,
    export_settings_if_enabled
)
from credential_reset.report_console import generate_summary_table
from credential_reset.report_markdown import generate_markdown_summary
from credential_reset.playbook import Playbook
from credential_reset.report_helper import (
    calculate_routine_statistics,
)
from rich import print


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


def print_and_save_summary(results: dict, firewall: str, firewall_info: dict, output_folder: str):
    """Print summary table to console and save markdown report to file."""
    try:
        if not a.no_summary:
            generate_summary_table(results, a)
    except Exception as e:
        print(f"Error printing summary table: {e}")

    try:
        # Generate and save markdown report
        md_content = generate_markdown_summary(results, firewall, firewall_info, a)

        dm = firewall_info['device_model'].replace(" ", "")
        sn = firewall_info['serial_number']
        md_filename = f"{output_folder}/{dm}-{sn}-summary.md"

        try:
            write_to_file(md_content, filename=md_filename)
            print(f"\n{generate_timestamp()}: Summary report saved to {md_filename}\n")
        except Exception as e:
            print(f"Error writing markdown summary to file: {e}")

    except Exception as err:
        print(f"Error generating markdown summary: {err}")


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
        args: Additional arguments object (default: None)
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

    if firewall_info['firewall_generation'] == 6:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Establishing an alternate API session.")

        # Create a Login object and log into the firewall using the alternate API method
        if a.verbose:
            verbose_int = 1
        else:
            verbose_int = 0

        alt_session = Login(
            ipaddress=api_base,
            userid=username,
            passwd=password,
            admin_mode="config",
            http_type="https",
            brwsr_cache=0,
            verbose=verbose_int,
            sessIdRef=0
        )

        logged_in, rmsg = alt_session.login2()
        if logged_in == 1:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Successfully logged into alternate API session for GEN6 firewall.")
    else:
        alt_session = None

    # Initialize the playbook class
    pb = Playbook(target=target,
                  target_numbers=target_numbers,
                  silent=silent,
                  api_base=api_base,
                  alt_session=alt_session,
                  api_session=api_session,
                  args=a,
                  routine_results=routine_results,
                  firewall_info=firewall_info)

    # List LDAP servers
    pb.list_ldap_servers()

    if not silent:
        print()

    # List RADIUS servers
    pb.list_radius_servers()

    if not silent:
        print()

    # List TACACS servers
    pb.list_tacacs_servers()

    if not silent:
        print()

    # List VPN policies
    pb.list_vpn_policies()

    if not silent:
        print()

    # List WAN interfaces (check for L2TP/PPTP/PPPoE/WWAN)
    pb.check_wan_interfaces()

    if not silent:
        print()

    # Check AWS API status (log/aws)
    pb.check_aws_api()

    if not silent:
        print()

    # List dynamic DNS services
    pb.list_dynamic_dns()

    if not silent:
        print()

    # Check Clearpass/NAC status
    pb.check_clearpass_nac()

    if not silent:
        print()

    # List SNMPv3 users
    pb.list_snmpv3_users()

    if not silent:
        print()

    # Cloud Secure Edge (CSE)
    pb.check_cloud_secure_edge()

    if not silent:
        print()

    # Email Logging
    pb.check_email_logging()

    if not silent:
        print()

    # Packet Monitor FTP Logging.
    pb.check_packet_monitor_ftp_logging()

    if not silent:
        print()

    # Settings/TSR scheduled exports
    pb.check_tsr_exp_scheduled_exports()

    if not silent:
        print()

    # Dynamic External Address Objects
    pb.check_deao()

    if not silent:
        print()

    # Dynamic Botnet List
    pb.check_dyn_botnet_list_server()

    if not silent:
        print()

    # Extended Switches
    pb.check_extended_switches()

    if not silent:
        print()

    # Extended Switches - Users
    pb.check_extended_switch_users()

    if not silent:
        print()

    # Extended Switches - RADIUS Servers
    pb.check_extended_switch_radius()

    if not silent:
        print()

    # Zone Objects: WLAN RADIUS Server
    pb.check_wlan_radius_servers()

    if not silent:
        print()

    # Guest Services External Guest Authentication (Message Authentication)
    # This flags when the Message Authentication option is enabled under Guest Services > External Guest Authentication
    pb.check_ext_guest_auth()

    if not silent:
        print()

    # SSO Agents
    pb.list_sso_agents()

    if not silent:
        print()

    # Terminal Server Agent (TSA)
    pb.list_ts_agents()

    if not silent:
        print()

    # SSO RADIUS Accounting Clients
    pb.list_sso_radius_clients()

    if not silent:
        print()

    # 3rd Party SSO API Clients
    pb.list_sso_api_clients()

    if not silent:
        print()

    # RADIUS Accounting Servers (Users > Settings > Accounting > RADIUS Accounting)
    pb.list_radius_accounting_servers()

    if not silent:
        print()

    # TACACS+ Accounting Servers (Users > Settings > Accounting > TACACS+)
    pb.list_tacacs_accounting_servers()

    if not silent:
        print()

    # AppFlow SFR Reporting
    pb.check_appflow_sfr_reporting()

    if not silent:
        print()

    # Custom NTP Servers
    pb.list_custom_ntp_servers()

    if not silent:
        print()

    # Security Services Signature Proxy
    pb.check_sec_services_proxy()

    if not silent:
        print()

    # GMS IPsec Management Tunnel
    pb.check_gms_ipsec_tunnel()

    if not silent:
        print()

    # Advanced Routing Protocols (RIP, OSPFv2, BGP)
    pb.list_advanced_routing_protocols()

    if not silent:
        print()

    # Cellular WWAN
    pb.check_cellular_wwan()

    if not silent:
        print()

    # Internal Wireless Radio (preshared key and/or RADIUS)
    pb.check_internal_wlan_radio()

    if not silent:
        print()

    # Internal Wireless Virtual Access Points
    pb.check_internal_wlan_vaps()

    if not silent:
        print()

    # Internal Wireless Virtual Access Point Profiles
    pb.check_internal_wlan_vap_profiles()

    if not silent:
        print()

    # Wireless SonicPoint/SonicWave/Virtual Access Points. Preshared keys, RADIUS shared secrets, etc.
    # SonicPoint/SonicWave Virtual Access Point Objects
    pb.check_sonicpoint_vaps()

    if not silent:
        print()

    # SonicPoint/SonicWave Virtual Access Point Profiles
    pb.check_sonicpoint_vap_profiles()

    if not silent:
        print()

    # Wireless Access Points (SonicPoint/SonicWave Profiles and Objects)
    # SonicPoint/SonicWave Profiles
    pb.check_sonicpoint_profiles()

    if not silent:
        print()

    # SonicPoint/SonicWave Access Point Objects
    pb.check_sonicpoint_objects()

    # REMEDIATION CHECKS END
    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Completed remediation playbook checks.")

    if not silent:
        print()

    # Process user operations (if enabled)
    print()
    users = None
    if force_password_change or a.force_password_change:
        # Get local users
        users = get_local_users(api_session, api_base, firewall_info['firewall_generation'], firewall, sshport, username, password, target_numbers, silent=silent)

        if users is None:
            return "UNABLE_TO_GET_USERS", "Unable to get users"

        routine_results[firewall]['got_users'] = True
        routine_results[firewall]['total_user_count'] = len(users['user']['local']['user'])

        # Process password changes
        user_results = process_password_changes(users,
                                                api_session,
                                                api_base,
                                                temp_password,
                                                randomize_temp_password or a.randomize_password,
                                                firewall_info['firewall_generation'],
                                                firewall,
                                                sshport,
                                                username,
                                                password,
                                                target_numbers,
                                                a)

        routine_results[firewall]['users'] = user_results

    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: Force password change logic is disabled. Enable it with -fpc or in the input CSV.")
        routine_results[firewall]['force_password_change_disabled'] = True

    # Handle TOTP unbind operations (if enabled)
    if unbind_totp or a.unbind_totp:
        totp_result = unbind_totp_from_users(api_session, api_base, firewall_info['firewall_generation'], users, target_numbers, silent=silent)
        update_routine_results(routine_results, firewall, 'totp_unbind', totp_result)
    else:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: INFO: TOTP unbind logic is disabled. Enable it with -ut or in the input CSV.")
        routine_results[firewall]['totp_unbind_disabled'] = True

    # Export operations after making user changes (if force-password-change or unbind-totp were enabled)
    if (force_password_change or a.force_password_change) or (unbind_totp or a.unbind_totp):
        tsr_result = export_tsr_if_enabled(api_session, api_base, a, target_numbers, firewall_info, silent=silent, tag="post-user-changes")
        update_routine_results(routine_results, firewall, 'tsr_result', tsr_result)
        if not silent:
            print()

        tracelog_result = export_tracelogs_if_enabled(api_session, api_base, a, target_numbers, firewall_info, silent=silent, tag="post-user-changes")
        update_routine_results(routine_results, firewall, 'tracelog_result', tracelog_result)
        if not silent:
            print()

        settings_result = export_settings_if_enabled(api_session, api_base, a, target_numbers,
                                                    firewall_info, username, password, silent=silent, tag="post-user-changes")
        update_routine_results(routine_results, firewall, 'settings_result', settings_result)
        if not silent:
            print()

    # Calculate routine statistics
    calculate_routine_statistics(routine_results, firewall)

    # Finalize routine (cleanup, write results, logout)
    finalize_routine(api_session,
                     api_base,
                     firewall,
                     firewall_info['firewall_generation'],
                     sshport,
                     username,
                     password,
                     target_numbers,
                     firewall_info)

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
        "  - Optionally resets local user passwords to a specified temporary password or randomized passwords",
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
