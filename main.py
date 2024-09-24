# Imports
import json
from os import listdir, path, mkdir
from time import sleep
from getpass import getpass
from common.banner import print_banner
from common.constants import get_fw_model
#from common.constants import get_autoenabled_sonicos_api, set_autoenabled_sonicos_api
from common.utils import generate_timestamp, tprint, write_to_file
from common.notice import notice_check
from common.arguments import a
from sonicos.api import (
    create_admin_session,
    create_admin_session_chap,
    hide_certificate_warnings,
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
    download_tracelog
)
from sonicos.utils import (
    ensure_admin_api_session,
    firmware_upgrade_prompt
)
import common.constants as constants
import tsr.parser as tsrparser


# This variable stores the results of the routine for each firewall.
routine_results = {}


# The routine function will get the list of users, update the force password reset flag, and commit the changes.
def routine(firewall, username=None, password=None, sshport='22', enable_totp=False, enable_botnet_filtering=False, temp_password=""):
    """
    Main routine.
    """
    # This resets the auto-enabled SonicOS API flag for each new firewall.
    if constants.get_autoenabled_sonicos_api() is True:
        constants.set_autoenabled_sonicos_api(False)

    if "https://" in firewall:
        api_base = f"{firewall}"
    else:
        api_base = f"https://{firewall}"

    while username is None or username == "":
        username = input(f"Enter the username for {firewall}: ")

    while password is None or password == "":
        password = getpass(f"Enter the password for {username}@{firewall}: ")

    if a.verbose:
        print(f"{generate_timestamp()}: --- Routine Details ---")
        print(f"{generate_timestamp()}: Verbose output enabled.")
        print(f"{generate_timestamp()}: Firewall: {firewall}")
        print(f"{generate_timestamp()}: Administrative username: {username}")
        print(f"{generate_timestamp()}: Administrative password length: {len(password)}")
        print(f"{generate_timestamp()}: API Base URL: {api_base}")
        print(f"{generate_timestamp()}: SSH Management Port: {sshport}")
        print(f"{generate_timestamp()}: Enable TOTP on 'SSLVPN Services' group: {enable_totp}")
        print(f"{generate_timestamp()}: Enable Botnet Filtering service: {enable_botnet_filtering}")
        print(f"{generate_timestamp()}: Temporary Password for users: {temp_password}")
        print(f"{generate_timestamp()}: ----------------------")

    routine_results[firewall]['api_base'] = api_base
    routine_results[firewall]['api_session_successful'] = False
    routine_results[firewall]['firewall_generation'] = None
    routine_results[firewall]['firmware_version'] = None
    routine_results[firewall]['device_model'] = None

    try:
        api_session = ensure_admin_api_session(api_base, api_user=username, api_password=password, sshport=sshport)
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"{generate_timestamp()}: Error creating admin session: {e}")
        return False

    if api_session is None or api_session is False:
        print(f"{generate_timestamp()}: Error: Unable to create an admin session.")

        # Sorting the keys in the results dictionary for consistency and readability.
        routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

        # Convert the results dictionary/json to string.
        results_str = json.dumps(routine_results[firewall], indent=4)
        results_str = "\n" + results_str + "\n"

        # Write the results to a file
        write_to_file(results_str, filename=f"{constants.START_TIMESTAMP_FOLDER}/results.txt")

        return False

    routine_results[firewall]['api_session_successful'] = True

    firewall_generation = None
    firmware_version = None
    device_model = None
    serial_number = None
    # Determine if this is a GEN7 firewall or a GEN6 firewall, as they have different endpoints.
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
        print(f"{generate_timestamp()}: Error getting version information: {e}")
        exit()

    routine_results[firewall]['firewall_generation'] = firewall_generation
    routine_results[firewall]['firmware_version'] = firmware_version
    routine_results[firewall]['device_model'] = device_model
    routine_results[firewall]['serial_number'] = serial_number

    # Download the TSR from the firewall.
    print(f"{generate_timestamp()}: Downloading TSR...")
    routine_results[firewall]['tsr_downloaded'] = False
    dm = routine_results[firewall]['device_model'].replace(" ", "")
    sn = routine_results[firewall]['serial_number']
    tsr_file_name = f"{dm}-{sn}-tsr.wri"
    tsr_downloaded = download_tsr(api_base,
                 api_session,
                 filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tsr_file_name}",
                 firewall_generation=firewall_generation)

    if tsr_downloaded:
        print(f"{generate_timestamp()}: TSR downloaded to {tsr_file_name}")
        routine_results[firewall]['tsr_downloaded'] = True

    # Download the trace logs.
    print(f"{generate_timestamp()}: Downloading trace logs...")
    routine_results[firewall]['trace_logs_downloaded'] = False
    tracelog_filename = f"{dm}-{sn}-tracelog-current.txt"
    trace_logs_downloaded = download_tracelog(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tracelog_filename}",
                                              log_selection="current",
                                              firewall_generation=firewall_generation)

    if trace_logs_downloaded:
        print(f"{generate_timestamp()}: Trace logs downloaded.")
        routine_results[firewall]['trace_logs_downloaded'] = True

    print()

    # TODO: Firmware version override for testing
    # firmware_version = "6.5.4.15-114"
    # firmware_version = "7.0.0-1234"

    # Alert the user if their firmware version is currently vulnerable to CVE-2024-40766 / SNWLID-2024-0015.
    v = notice_check(firmware_version, device_model)
    if v:
        routine_results[firewall]['vulnerable'] = [
            {
                "CVE": "CVE-2024-40766",
                "SNWLID": "SNWLID-2024-0015",
                "vulnerable": True,
                "next_action": "Review the SonicWall Security Advisory and upgrade the firmware.",
                "advisory_url": "https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015"
            }
        ]
        print(f"{generate_timestamp()}: Warning: This firmware version is vulnerable to CVE-2024-40766 / SNWLID-2024-0015.")
        print("Please upgrade the firmware per the SonicWall Security Advisory and re-run this script against the target firewall.")

        routine_results[firewall]['prompted_to_upgrade'] = True
        routine_results[firewall]['upgraded_firmware'] = False
        routine_results[firewall]['completed_routine_successfully'] = False

        # API is not available on GEN5 firewalls.
        if firewall_generation == 5:
            print(f"{generate_timestamp()}: SonicOS API is not available on GEN5 firewalls. Please upgrade the firmware manually.")
            routine_results[firewall]['upgrade_via_api_supported'] = False

        # API endpoint is not available on GEN6 firewalls.
        elif firewall_generation == 6:
            # print(f"{generate_timestamp()}: The API endpoint is not available on GEN6 firewalls. Please upgrade the firmware manually.")
            routine_results[firewall]['upgrade_via_api_supported'] = False

        # API endpoint is available on GEN7 firewalls.
        elif firewall_generation == 7:
            routine_results[firewall]['upgrade_via_api_supported'] = True
            upgraded = firmware_upgrade_prompt(api_base, api_session)
            if upgraded:
                print(f"{generate_timestamp()}: The firmware upgrade was initiated. Please re-run this script against the target firewall once it is done booting.")
                routine_results[firewall]['upgraded_firmware'] = True

                # Sorting the keys in the results dictionary for consistency and readability.
                routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

                # Convert the results dictionary/json to string.
                results_str = json.dumps(routine_results[firewall], indent=4)
                results_str = "\n" + results_str + "\n"

                # Write the results to a file
                write_to_file(results_str, filename=f"{constants.START_TIMESTAMP_FOLDER}/results.txt")

                # Script will not wait for the upgrade. This return will end the routine.
                return "UPGRADED_FIRMWARE"

        # If the user chose not to upgrade the firmware, the script will not proceed.
        # Sorting the keys in the results dictionary for consistency and readability.
        routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

        # Convert the results dictionary/json to string.
        results_str = json.dumps(routine_results[firewall], indent=4)
        results_str = "\n" + results_str + "\n"

        # Write the results to a file
        write_to_file(results_str, filename=f"{constants.START_TIMESTAMP_FOLDER}/results.txt")

        return "NOT_UPGRADING_FIRMWARE"

    routine_results[firewall]['got_users'] = False

    users = None
    try:
        # Get the list of users
        if firewall_generation == 7:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users')
        elif firewall_generation == 6:
            users = get_request(api_base, api_session, '/api/sonicos/user/local/users')
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"{generate_timestamp()}: Error getting users from API: {e}")
        exit()

    if isinstance(users, bytes):
        # There may be expired users pulled from a GEN6 firewall. Expired users will have "expired" in the JSON
        # unquoted and will cause a JSON error.
        # Replaces b": expired\n" with b": \"expired\"\n" to make the JSON valid.
        users = users.replace(b': expired', b': "expired"')

        # Converts the bytes to a string and then to a JSON object.
        users = json.loads(users.decode('utf-8'))

    if users.get('user', {}).get('local', {}).get('user', None) is None:
        print(f"{generate_timestamp()}: Error: No local users found.")
        return "NO_LOCAL_USERS"

    routine_results[firewall]['got_users'] = True
    routine_results[firewall]['total_user_count'] = len(users['user']['local']['user'])
    routine_results[firewall]['users'] = []

    # Update the force password reset flag
    print(f"{generate_timestamp()}: Updating the force password reset flag for all local users...")
    if temp_password != "":
        print(f"{generate_timestamp()}: Passwords will be reset to '{temp_password}'")
    for usr in users['user']['local']['user']:
        # Skip these users
        skip_users = ['All LDAP Users', 'All RADIUS Users']
        if usr['name'] in skip_users:
            routine_results[firewall]['users'].append({
                "name": usr['name'],
                "forced_password_change": False,
                "skipped": True,
                "reason": "Special user entry",
                "commit_successful": None
            })
            continue

        # Skipping expired users.
        # GEN6: usr['account_lifetime']['lifetime'] is "expired"
        # GEN7: usr['account_lifetime']['expired'] is True
        if (
                usr.get('account_lifetime', {}).get('lifetime', "") == "expired" or
                usr.get('account_lifetime', {}).get('expired', False) is True
        ):
            print(f"{generate_timestamp()}: Skipping {usr['name']} (expired user)")
            routine_results[firewall]['users'].append({
                "name": usr['name'],
                "forced_password_change": False,
                "skipped": True,
                "reason": "Expired user",
                "commit_successful": None
            })
            continue

        if firewall_generation == 7:
            # Domain users have a domain key.
            # Local users and users associated with any domain do not have a domain key.
            if usr.get('domain', None) is not None:
                print(f"{generate_timestamp()}: GEN7: Skipping {usr['name']} (domain user)")
                routine_results[firewall]['users'].append({
                    "name": usr['name'],
                    "forced_password_change": False,
                    "skipped": True,
                    "reason": "Domain user",
                    "domain": usr.get('domain', ''),
                    "commit_successful": None
                })
                if a.verbose:
                    print(usr)
                continue

        if firewall_generation == 6:
            # Skip domain users, imported LDAP users, etc.
            # Domain users have a domain name.
            # Users associated with a domain but without a domain component will have a domain name of 'any'.
            if usr.get('domain', {}).get('name', None) is not None:
                print(f"{generate_timestamp()}: GEN6: Skipping {usr['name']} (domain user)")
                routine_results[firewall]['users'].append({
                    "name": usr['name'],
                    "forced_password_change": False,
                    "skipped": True,
                    "reason": "Domain user",
                    "domain": usr.get('domain', {}).get('name', ''),
                    "commit_successful": None
                })
                if a.verbose:
                    print(usr)
                continue

        # Update the force password reset flag
        usr['force_password_change'] = True

        # Update the password if a temporary password is set.
        if temp_password != "":
            if firewall_generation == 7:
                usr['password'] = temp_password
            elif firewall_generation == 6:
                usr['password']["pwd"] = temp_password

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

        print(f"\nUpdating '{uname}' ({uuid})", end='')

        # Creates the expected JSON structure
        data_structure = {
            "user": {
                "local": {
                    "user": [
                        usr
                    ]
                }
            }
        }

        # Update the user
        if firewall_generation == 7:
            update_resp = patch_request(api_base,
                                        api_session,
                                        api_path=f"/api/sonicos/user/local/users/uuid/{uuid}",
                                        data=data_structure)
        elif firewall_generation == 6:
            update_resp = put_request(api_base,
                                      api_session,
                                      api_path=f"/api/sonicos/user/local/user/uuid/{uuid}",
                                      data=data_structure)

        if update_resp['status']['success'] is False:
            print(f"{generate_timestamp()}: Error updating user: {uname}")
            input("Press Enter to continue or CTRL+C to exit.")

        routine_result_temp['user_update_successful'] = True

        # Commit the changes.
        commit_pending(api_base, api_session)
        routine_result_temp['commit_successful'] = True

        routine_results[firewall]['users'].append(routine_result_temp)
        sleep(1)
        print()
        # End of the user loop

    # The following occurs after the user loop ends.

    # At this point, we will ask the user if they would like to do some extra stuff like enabling botnet filtering or TOTP.
    routine_results[firewall]['botnet_filtering_licensed'] = None
    routine_results[firewall]['botnet_filtering_enabled'] = None

    routine_results[firewall]['sslvpn_services_totp_enabled'] = None
    routine_results[firewall]['sslvpn_services_totp_autoenabled'] = None

    # Check if Botnet Filtering is licensed and enabled.
    try:
        print()
        if firewall_generation == 5:
            print("Not implemented for GEN5 firewalls.")

        botnet_status = check_botnet_status(api_base, api_session, firewall_generation=firewall_generation)

        if botnet_status["license_status"] == "not_licensed":
            routine_results[firewall]['botnet_filtering_licensed'] = False
            routine_results[firewall]['botnet_filtering_autoenabled'] = False
            msg = botnet_status.get("message", "")
            print(f"{generate_timestamp()}: Botnet Filtering is not licensed. {msg}")
            enable_botnet_filtering = False
        elif botnet_status["license_status"] == "licensed":
            routine_results[firewall]['botnet_filtering_licensed'] = True
            print(f"{generate_timestamp()}: Botnet Filtering is licensed.")

        if botnet_status["status"] == "enabled":
            routine_results[firewall]['botnet_filtering_enabled'] = True
            routine_results[firewall]['botnet_filtering_autoenabled'] = False
            enable_botnet_filtering = False
            print(f"{generate_timestamp()}: Botnet Filtering is enabled.")
        elif botnet_status["status"] == "disabled":
            routine_results[firewall]['botnet_filtering_enabled'] = False
            print(f"{generate_timestamp()}: Botnet Filtering is not enabled.")

    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"{generate_timestamp()}: Error getting botnet status (0): {e}")

    # This is the JSON response from the check_botnet_status function.
    botnet_status_response = botnet_status['response']

    # The idea is to enable Botnet if configured to do so or if argument is set, but to ask the user if they want to enable it if licensed but not enabled.
    if enable_botnet_filtering or (
            routine_results[firewall]['botnet_filtering_licensed'] and
            not routine_results[firewall]['botnet_filtering_enabled']
    ):
        # If Botnet Filtering is licensed but not enabled, and the argument to enable it is not set.
        if routine_results[firewall]['botnet_filtering_enabled'] is False:
            if a.enable_botnet_filtering:
                enable_botnet_filtering = True

            # if not enable_botnet_filtering and a.enable_botnet_filtering is False:
            #     print(f"{generate_timestamp()}: Botnet Filtering is licensed but not enabled. Would you like to enable it?")
            #     routine_results[firewall]['prompted_to_enable_botnet_filtering'] = True
            #     enable_botnet = input("Enter 'y' to enable Botnet Filtering or 'n' to skip [y/N]: ")
            #     if enable_botnet.lower() == 'y' or enable_botnet.lower() == 'yes':
            #         enable_botnet_filtering = True

        # If Botnet Filtering is licensed but not enabled, and the argument to enable it is set.
        enable_botnet_resp = {}
        if (enable_botnet_filtering and routine_results[firewall]['botnet_filtering_enabled'] is False and
                routine_results[firewall]['botnet_filtering_licensed'] is True):
            print(f"{generate_timestamp()}: Enabling Botnet Filtering for all connections.")
            botnet_status_response['botnet']['logging'] = True
            try:
                if firewall_generation == 7:
                    # I have not encountered any GEN7 issue with the dynamic list key, so I've left it in.
                    botnet_status_response['botnet']['block']['connections'] = {'enable': True, 'mode': 'all'}
                    enable_botnet_resp = put_request(api_base, api_session, '/api/sonicos/botnet/base',
                                                     data=botnet_status_response)
                elif firewall_generation == 6:
                    botnet_status_response['botnet']['block']['connections'] = {'all': True}
                    # print(botnet_status_response)

                    # I noticed some out of bounds errors when including the dynamic_list key in the JSON.
                    # Since we're enabling Botnet, it is safe to assume the dynamic list was not in use.
                    botnet_status_response['botnet'].pop('dynamic_list', None)
                    botnet_status_response['botnet'].pop('exclude', None)
                    botnet_status_response['botnet'].pop('include', None)

                    enable_botnet_resp = put_request(api_base, api_session, '/api/sonicos/botnet/global',
                                                     data=botnet_status_response)
            except KeyboardInterrupt:
                print(f"\nStopped!")
                exit()
            except Exception as e:
                print(f"{generate_timestamp()}: Error enabling Botnet Filtering: {e}")

            if enable_botnet_resp.get('status', {}).get('success', False) is False:
                print(f"{generate_timestamp()}: Error enabling Botnet Filtering.")

            # Commit the changes.
            commit_pending(api_base, api_session)
            routine_results[firewall]['botnet_filtering_autoenabled'] = True
        else:
            routine_results[firewall]['botnet_filtering_autoenabled'] = False

    # Check if MFA is enabled on the SSLVPN Services group.
    try:
        print()
        if firewall_generation == 5:
            print("Not implemented for GEN5 firewalls.")

        totp_status = check_totp_status(api_base,
                                        api_session,
                                        group_name="SSLVPN Services",
                                        enable_totp=enable_totp,
                                        firewall_generation=firewall_generation
                                        )

        if totp_status["status"] == "enabled":
            routine_results[firewall]['sslvpn_services_totp_enabled'] = True
            routine_results[firewall]['sslvpn_services_totp_mode'] = totp_status.get("mode", "")
            routine_results[firewall]['sslvpn_services_totp_autoenabled'] = totp_status.get("autoenabled", False)
            print(f"{generate_timestamp()}: {totp_status.get('mode', '')} is enabled on the SSLVPN Services group.")
        elif totp_status["status"] == "disabled":
            routine_results[firewall]['sslvpn_services_totp_enabled'] = False
            routine_results[firewall]['sslvpn_services_totp_mode'] = totp_status.get("mode", "")
            routine_results[firewall]['sslvpn_services_totp_autoenabled'] = totp_status.get("autoenabled", False)
            routine_results[firewall]['sslvpn_services_totp_error_msg'] = totp_status.get("message", "")
            print(f"{generate_timestamp()}: TOTP/OTP is not enabled on the SSLVPN Services group.")
            if totp_status.get("try_ssh", None):
                print(f"{generate_timestamp()}: Unable to enable TOTP via API. Trying SSH instead. ({totp_status.get('message', '')})\n")
                enable_totp_ssh(firewall, sshport, username, password, "SSLVPN Services")


    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"{generate_timestamp()}: Error getting MFA status or setting new MFA configuration (0): {e}")

    # Stats (such as users that were/were not updated).
    routine_results[firewall]['total_users_forced_to_update_password'] = len([u for u in routine_results[firewall]['users'] if u['commit_successful'] is True])
    routine_results[firewall]['commit_possibly_failed_count'] = len([u for u in routine_results[firewall]['users'] if u['commit_successful'] is False])
    routine_results[firewall]['skipped_user_count'] = len([u for u in routine_results[firewall]['users'] if u['skipped'] is True])
    routine_results[firewall]['total_postprocess_user_count'] = len(routine_results[firewall]['users'])
    routine_results[firewall]['completed_routine_successfully'] = True

    # Sorting the keys in the results dictionary for consistency and readability.
    routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

    # Convert the results dictionary/json to string.
    results_str = json.dumps(routine_results[firewall], indent=4)
    results_str = "\n" + results_str + "\n"

    # Write the results to a file
    write_to_file(results_str, filename=f"{constants.START_TIMESTAMP_FOLDER}/results.txt")

    # At this point, the routine is complete. If the script auto-enabled SonicOS API, we need to disable it.
    if constants.get_autoenabled_sonicos_api():
        disable_sonicos_api_ssh(firewall, sshport, username, password)

    # Done with the routine.
    logout(api_base, api_session)


# Main function
if __name__ == "__main__":
    # Print information
    print_banner()

    # Creates the folders for any output.
    if path.exists(constants.RUNS_FOLDER) is False:
        mkdir(constants.RUNS_FOLDER)

    # The -target argument could be an IP, hostname, or a CSV file containing 'ip,username,password,sshport' for each firewall.
    # If the -target argument is a CSV file, read the file and process each line.
    targets = []
    if path.isfile(a.target):
        try:
            with open(a.target, 'r') as f:
                for line in f:
                    # Skips the header in the CSV file, if it is present.
                    if "target_fw,admin_user," in line:
                        continue
                    # Enables commenting lines to skip an entry.
                    elif line.startswith("#"):
                        continue

                    # target_fw,admin_user,admin_password,target_ssh_mgmt_port,enable_totp,enable_botnet_filtering
                    # When the CSV file has less than 6 columns, we'll fill the missing columns with 'None'.
                    # Handles empty lines, ip and user (no password, etc), and missing columns (for users of previous versions)
                    item_count = len(line.strip().split(','))
                    if item_count == 0:
                        continue
                    if item_count <= 2:
                        print(f"{generate_timestamp()}: Error: Cannot add this entry. Please review this entry: '{line}'.")
                        continue
                    if item_count < 7:
                        line = line.strip() + (7 - item_count) * ',None'

                    fw, user, pw, ssh_port, enable_totp, enable_botnet_filtering, temp_password = line.strip().split(',')

                    # This normalizes the Nones to expected values or default values.
                    if ssh_port == 'None' or ssh_port == 'false':
                        ssh_port = '22'
                    if enable_totp == 'None' or enable_totp == 'false':
                        enable_totp = False
                    if enable_botnet_filtering == 'None' or enable_botnet_filtering == 'false':
                        enable_botnet_filtering = False
                    if temp_password == 'None' or temp_password == 'false' or temp_password == '':
                        temp_password = ""
                    if len(temp_password) < 8 and temp_password != "":
                        print(f"{generate_timestamp()}: Error: The temporary password for {fw} is less than 8 characters. Padding the password with 'x'.")
                        temp_password = temp_password + 'x' * (8 - len(temp_password))
                    targets.append((fw, user, pw, ssh_port, enable_totp, enable_botnet_filtering, temp_password))
        except KeyboardInterrupt:
            print("\nStopped!")
            exit()
        except Exception as e:
            print(f"{generate_timestamp()}: Error opening/parsing input file: {e}")
            exit()
    else:
        targets.append((a.target, None, None, a.sshport, a.enable_totp, a.enable_botnet_filtering, a.temp_password))

    print(f"{generate_timestamp()}: Target Count: {len(targets)}\n")

    if len(targets) > 0:
        if path.exists(constants.START_TIMESTAMP_FOLDER) is False:
            mkdir(constants.START_TIMESTAMP_FOLDER)

    for target in targets:
        # If the target is a CSV file, the target will be a tuple (ip, user, password)
        if isinstance(target, tuple):
            fw, user, pw, ssh_port, enable_totp, enable_botnet_filtering, temp_password = target
        # When it's not a CSV file, the target will be a string (ip). The user and password will be None.
        # User/password will be prompted later.
        else:
            fw, user, pw, ssh_port, enable_totp, enable_botnet_filtering, temp_password = target, None, None, a.sshport, a.enable_totp, a.enable_botnet_filtering, temp_password

        if fw == "" or fw is None:
            print(f"{generate_timestamp()}: Error: The target firewall is empty.")
            exit(1)

        # Print the target information
        print(f"{generate_timestamp()}: {fw}: Running routine...")

        routine_results[fw] = {}

        # Run the routine
        res = routine(fw, username=user, password=pw, sshport=ssh_port, enable_totp=enable_totp, enable_botnet_filtering=enable_botnet_filtering, temp_password=temp_password)

        print(f"{generate_timestamp()}: {get_fw_model()} - {fw}: Done.\n\n")