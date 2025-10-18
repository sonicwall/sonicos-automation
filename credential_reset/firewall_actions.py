import json
from time import sleep
from common.utils import generate_timestamp
from sonicos.api import (
    get_request,
    post_request,
    put_request,
    patch_request,
    commit_pending,
    logout,
    disable_sonicos_api_ssh,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh,
    post_request_direct_cli,
)
from credential_reset.utils import create_random_password


def unbind_totp_from_users(api_session, api_base: str, firewall_generation: int, users: dict, target_numbers: tuple, silent: bool = False):
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
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Retrieving users for TOTP unbind...")
        try:
            if firewall_generation == 7:
                totp_users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=silent)
            elif firewall_generation == 6:
                totp_users = get_request(api_base, api_session, '/api/sonicos/user/local/users', silent=silent)
        except KeyboardInterrupt:
            print(f"\nStopped!")
            exit()
        except Exception as err:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error getting users for TOTP unbind: {err}")
            result['totp_unbind_get_users_error'] = str(err)
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
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unbinding TOTP for user '{uname}'...")

                if firewall_generation == 6:
                    commands = f"user local\nuser {uname}\nunbind-totp-key\nexit\nexit"
                    totp_unbound = post_request_direct_cli(api_base,
                                                           api_session,
                                                           command=commands,
                                                           silent=silent)

                else:
                    totp_unbound = post_request(api_base,
                                                api_session,
                                                data=None,
                                                api_path=f"/api/sonicos/user/local/unbind-totp-key/{uname}",
                                                silent=silent)

                if totp_unbound:
                    success = False
                    api_result = totp_unbound.get('status', {}).get('info', [{}])[-1].get('message', 'No message returned.')
                    if api_result.lower() == "changes made." or api_result.lower() == "success.":
                        success = True
                    if not silent:
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
                    if not silent:
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
                if not silent:
                    print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Committing TOTP unbind changes...")
                commit_pending(api_base, api_session, silent=silent)

            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TOTP unbind complete - {result['totp_unbind_successful_count']} successful, {result['totp_unbind_failed_count']} failed")
        else:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: No local users found for TOTP unbind.")
            result['totp_unbind_no_users'] = True
    else:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Unable to retrieve users for TOTP unbind.")
        result['totp_unbind_get_users_failed'] = True

    return result


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

        # When temp password is not blank and randomization is not requested, we'll use the provided temp password.
        # This temp password should already be validated and padded if necessary.
        if temp_password != "" and not randomize_temp_password:
            if not args.silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Using configured temporary password for {usr['name']}.")

        # Overrides any configured temp password and generates a random one instead if randomization is requested or
        # if the temp password is blank.
        elif randomize_temp_password or temp_password == "":
            if not args.silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Generating random temporary password for {usr['name']}.")
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
            if not args.silent:
                # print(f"\nUpdating '{uname}'", end='')
                print(f"\nUpdating '{uname}'")
        else:
            if not args.silent:
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
                                      data=data_structure, silent=args.silent)
        elif firewall_generation == 6:
            update_resp = put_request(api_base, api_session,
                                    api_path=f"/api/sonicos/user/local/user/uuid/{uuid}",
                                    data=data_structure, silent=args.silent)
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
            commit_pending(api_base, api_session, silent=args.silent)
        routine_result_temp['commit_successful'] = True

        user_results.append(routine_result_temp)
        sleep(1)
        if not args.silent:
            print()

    return user_results

