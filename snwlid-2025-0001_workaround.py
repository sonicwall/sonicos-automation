# Imports
import json
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


# Argument parser
arg_description = """Workaround/mitigation for SNWLID-2025-0001.
This tool automates the task of deleting domain-associated users, re-creating LDAP server entries, and modifying the SSLVPN User Domain.
Please refer to the README for more detailed help."""
args = get_parser(arg_set="snwlid-2025-0001", description=arg_description, parse=False)
args.add_argument("-rupn", "--restore_upn", action='store_true', help="If set, restores the qualified login name to userPrincipalName if it isn't already.")
args.add_argument("-dr", "--dont_reboot", action='store_true', help="If set, the firewall will not be rebooted. We suggest allowing the firewall to reboot. (NOT RECOMMENDED)")
args.add_argument("-du", "--delete_users", action='store_true', help="If set, deletes domain-associated local users. Disabled by default as a safety feature. We strongly recommend deleting the domain-associated local users. (STRONGLY RECOMMENDED)")
a = args.parse_args()


def routine(fw):
    # This resets the auto-enabled SonicOS API flag for each new firewall.
    if constants.get_autoenabled_sonicos_api() is True:
        constants.set_autoenabled_sonicos_api(False)

    logged_in = fw.login()
    if not logged_in:
        print(f"{generate_timestamp()}: ERROR: Could not log into the firewall.")
        return

    print()

    # Export settings and a TSR.
    if a.export_tsr:
        print(f"{generate_timestamp()}: INFO: Exporting settings and TSR.")
        tsr_filename = f"{constants.START_TIMESTAMP_FOLDER}/{fw.serial}_tsr.wri"
        tsr_downloaded = fw.download_tsr(tsr_filename)

        if tsr_downloaded:
            print(f"{generate_timestamp()}: INFO: TSR downloaded successfully.")

    print()

    # Export preferences.
    if a.export_settings:
        print(f"{generate_timestamp()}: INFO: Exporting preferences.")
        export_filename = f"{constants.START_TIMESTAMP_FOLDER}/{fw.serial}_preferences.exp"
        exported_prefs = fw.export_preferences(export_filename)

        if exported_prefs:
            print(f"{generate_timestamp()}: INFO: Preferences exported successfully.")

    print()

    # LDAP Server configuration
    primary_domain = None
    ldap_servers_config = fw.get_request("user/ldap/servers")
    if ldap_servers_config:
        print(f"{generate_timestamp()}: INFO: LDAP servers config retrieved successfully.")
        if a.verbose:
            print(json.dumps(ldap_servers_config, indent=4))

        # Save the LDAP server configuration to a file.
        ldap_config_file = f"{constants.START_TIMESTAMP_FOLDER}/{fw.serial}_ldap_config.json"
        with open(ldap_config_file, "w") as f:
            json.dump(ldap_servers_config, f, indent=4)
        print(f"{generate_timestamp()}: INFO: LDAP server configuration saved to {ldap_config_file}")

    if len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
        print(f"{generate_timestamp()}: INFO: {len(ldap_servers_config['user']['ldap'].get('server', []))} LDAP server(s) configured.")
        # Finds the primary LDAP server and extracts the primary domain.
        for inx, srv in enumerate(ldap_servers_config["user"]["ldap"].get("server", [])):
            if srv["role"]["primary"]:
                primary_domain = srv["directory"]["primary_domain"]
                break
        if primary_domain:
            print(f"{generate_timestamp()}: INFO: Primary domain: {primary_domain}")
        else:
            print(f"{generate_timestamp()}: WARNING: Primary domain not found in the LDAP server configuration.")

    else:
        print(f"{generate_timestamp()}: INFO: No LDAP servers configured. No changes needed.")
        return

    # Modify the LDAP server config. Removes userPrincipalName from the Qualified login name field and replaces it with sAMAccountName.
    # After the reboot, this configuration will be reapplied to the firewall.
    # Newer firmware versions create the LDAP server without userPrincipalName in the Qualified login name field.
    # This modification is only needed for older firmware versions, but works for newer firmware too.
    qualified_logon_name = "sAMAccountName"
    if a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
        print(f"{generate_timestamp()}: INFO: Restoring userPrincipalName as the qualified login name.")
        qualified_logon_name = "userPrincipalName"
    elif not a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
        print(f"{generate_timestamp()}: INFO: Modifying the LDAP server configuration in memory.")
        qualified_logon_name = "sAMAccountName"

    try:
        for inx, srv in enumerate(ldap_servers_config["user"]["ldap"].get("server", [])):
            # ldap_servers_config["user"]["ldap"]["server"][inx]["user_attribute"]["qualified_logon_name"] = ""
            ldap_servers_config["user"]["ldap"]["server"][inx]["user_attribute"]["qualified_logon_name"] = qualified_logon_name
    except KeyError:
        print(f"{generate_timestamp()}: ERROR: Unable to modify the LDAP server configuration.")
        return

    if len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
        # Delete the existing LDAP server configuration where userPrincipalName is used in the Qualified login name field.
        # (Device > Users > Settings > Authentication > Configure LDAP)
        print(f"{generate_timestamp()}: INFO: Deleting the current LDAP server configuration.")
        for inx, srv in enumerate(ldap_servers_config["user"]["ldap"].get("server", [])):
            srv_name = srv["host"]
            deleted_ldap_servers_config = None
            if fw.gen == 6:
                deleted_ldap_servers_config = fw.delete_request(f"user/ldap/server/{srv_name}")
            elif fw.gen == 7 or fw.gen == 8:
                deleted_ldap_servers_config = fw.delete_request(f"user/ldap/servers/name/{srv_name}")
            if deleted_ldap_servers_config:
                print(f"{generate_timestamp()}: INFO: LDAP server configuration deleted successfully.")
                if a.verbose:
                    print(json.dumps(deleted_ldap_servers_config, indent=4))

                # Commit the changes.
                print(f"{generate_timestamp()}: INFO: Committing the changes.")
                commit_success, response_message = fw.commit_pending()
                if commit_success:
                    print(f"{generate_timestamp()}: INFO: {response_message}")
                else:
                    print(f"{generate_timestamp()}: WARNING: {response_message}")

    if a.delete_users:
        if not a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
            # Delete locally listed LDAP users. (Device > Local Users & Groups > Local Users)
            user_list = fw.get_request("user/local/users")
            if user_list:
                print(f"{generate_timestamp()}: INFO: Local users retrieved successfully.")
                if a.verbose:
                    print(json.dumps(user_list, indent=4))
        elif a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
            print(f"{generate_timestamp()}: INFO: Restoring userPrincipalName in LDAP server configuration. Skipping the deletion of local users.")

        if not a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
            # This section handles the deletion of domain-associated local users.
            # Skip these special user entries.
            skip_users = ['All LDAP Users', 'All RADIUS Users']
            deleted_count = 0
            skipped_count = 0
            for usr in user_list["user"]["local"]["user"]:
                # Skip special user entries
                if usr["name"] in skip_users:
                    skipped_count += 1
                    continue

                # Skip non-domain users
                if usr.get("domain", None) is None or usr.get("domain", None) == {}:
                    skipped_count += 1
                    continue

                # Delete domain-associated users
                deleted_user = None
                if fw.gen == 6:
                    deleted_user = fw.delete_request(f"user/local/user/uuid/{usr['uuid']}")
                elif fw.gen == 7 or fw.gen == 8:
                    deleted_user = fw.delete_request(f"user/local/users/uuid/{usr['uuid']}")
                if deleted_user:
                    print(f"{generate_timestamp()}: INFO: User {usr['name']} deleted successfully.")
                    if a.verbose:
                        print(json.dumps(deleted_user, indent=4))
                    commit_success, response_message = fw.commit_pending()
                    if commit_success:
                        print(f"{generate_timestamp()}: INFO: {response_message}")
                    else:
                        print(f"{generate_timestamp()}: WARNING: {response_message}")
                    deleted_count += 1

            if deleted_count > 0:
                print(f"{generate_timestamp()}: INFO: All domain-associated local users have been deleted.")
            print(f"{generate_timestamp()}: INFO: {deleted_count} entries deleted. {skipped_count} entries skipped.")
        elif a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
            print(f"{generate_timestamp()}: INFO: Skipped the deletion of local users.")


    if not a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
        # Remove the User Domain from SSL VPN Server Settings (it will revert to the default LocalDomain).
        # (Network > SSL VPN > Server Settings > SSL VPN Server Settings > User Domain)
        ssl_vpn_server_settings = {}
        if fw.gen == 6:
            ssl_vpn_server_settings = fw.get_request("ssl-vpn/server")
        elif fw.gen == 7 or fw.gen == 8:
            ssl_vpn_server_settings = fw.get_request("ssl-vpn/server/base")
        if ssl_vpn_server_settings:
            print(f"{generate_timestamp()}: INFO: SSL VPN server settings retrieved successfully.")
            if a.verbose:
                print(json.dumps(ssl_vpn_server_settings, indent=4))

        user_domain = ssl_vpn_server_settings.get("ssl_vpn", {}).get("server", {}).get("user_domain", "")

        # Checks if the user domain is already set to LocalDomain. If so, no change is needed.
        if user_domain == "LocalDomain":
            print(f"{generate_timestamp()}: INFO: No change needed. User domain: {user_domain}, Primary domain: {primary_domain}")

        elif user_domain == "":
            print(f"{generate_timestamp()}: WARNING: User domain not found in the SSL VPN server settings.")

        # When the user domain matches the LDAP primary domain, no change is needed.
        elif user_domain.lower() == primary_domain.lower():
            print(f"{generate_timestamp()}: INFO: User domain matches the LDAP primary domain. No change needed. User domain: {user_domain}, Primary domain: {primary_domain}")

        # When the user domain is a short record from the primary domain, no change is needed.
        elif user_domain.lower() == primary_domain.split(".")[0].lower():
            print(f"{generate_timestamp()}: INFO: User domain is a short record of the primary domain. No change needed. User domain: {user_domain}, Primary domain: {primary_domain}")

        # When the user domain differs from the primary domain and does not contain its short record, update the user domain.
        else:
            print(f"{generate_timestamp()}: INFO: Updating the SSL VPN server settings. User domain: {user_domain}, Primary domain: {primary_domain}")
            ssl_vpn_server_settings["ssl_vpn"]["server"]["user_domain"] = "LocalDomain"
            updated_ssl_vpn_server_settings = {}
            if fw.gen == 6:
                updated_ssl_vpn_server_settings = fw.put_request("ssl-vpn/server", ssl_vpn_server_settings)
            elif fw.gen == 7 or fw.gen == 8:
                updated_ssl_vpn_server_settings = fw.put_request("ssl-vpn/server/base", ssl_vpn_server_settings)
            if updated_ssl_vpn_server_settings:
                print(f"{generate_timestamp()}: INFO: SSL VPN server settings updated successfully. User domain has been changed to LocalDomain")
                if a.verbose:
                    print(json.dumps(updated_ssl_vpn_server_settings, indent=4))
                commit_success, response_message = fw.commit_pending()
                if commit_success:
                    print(f"{generate_timestamp()}: INFO: {response_message}")
                else:
                    print(f"{generate_timestamp()}: WARNING: {response_message}")

        # Reboot the firewall.
        if not a.dont_reboot:
            print(f"{generate_timestamp()}: INFO: Rebooting the firewall.")
            response = fw.restart_sonicos()
            if response:
                print(f"{generate_timestamp()}: INFO: Firewall rebooted successfully.")

            # Wait for the firewall to come back online.
            response = fw.wait_for_reboot()
            if response:
                print(f"{generate_timestamp()}: INFO: Firewall is back online.")
                fw.login()
            else:
                print(f"{generate_timestamp()}: ERROR: Firewall is not back online. Exiting script.")
                exit()
        else:
            print(f"{generate_timestamp()}: WARNING: Part of the recommended process is to reboot the firewall. We recommend rebooting manually.")

    elif a.restore_upn and len(ldap_servers_config["user"]["ldap"].get("server", [])) > 0:
        print(f"{generate_timestamp()}: INFO: Restoring userPrincipalName in LDAP server configuration. Skipped SSLVPN User Domain logic.")


    # Create a new LDAP server configuration without userPrincipalName in the Qualified login name field.
    # The LDAP configuration was modified earlier and will now be reapplied to the firewall.
    # (Device > Users > Settings > Authentication > Configure LDAP)
    # Update/re-push the LDAP server config.
    if len(ldap_servers_config["user"]["ldap"].get("server", [])) == 0:
        print(f"{generate_timestamp()}: INFO: LDAP server configuration is empty.")
    else:
        print(f"{generate_timestamp()}: INFO: Updating the LDAP server configuration.")
        updated_ldap_servers_config = None
        if fw.gen == 6:
            updated_ldap_servers_config = fw.post_request("user/ldap/servers", ldap_servers_config)
        elif fw.gen == 7 or fw.gen == 8:
            updated_ldap_servers_config = fw.put_request("user/ldap/servers", ldap_servers_config)
        if updated_ldap_servers_config:
            print(f"{generate_timestamp()}: INFO: LDAP server configuration updated successfully.")
            if a.verbose:
                print(json.dumps(updated_ldap_servers_config, indent=4))
            print(f"{generate_timestamp()}: INFO: Committing the changes.")
            commit_success, response_message = fw.commit_pending()
            if commit_success:
                print(f"{generate_timestamp()}: INFO: {response_message}")
            else:
                print(f"{generate_timestamp()}: WARNING: {response_message}")

    # If we auto-enabled SonicOS API, disable it.
    if constants.get_autoenabled_sonicos_api():
        print(f"{generate_timestamp()}: INFO: SonicOS API was auto-enabled. Re-disabling SonicOS API.")
        if fw.gen == 6:
            sonicos_api_disabled = disable_sonicos_api_ssh(fw.host, fw.ssh_port, fw.username, fw.password)
            if sonicos_api_disabled:
                print(f"{generate_timestamp()}: INFO: SonicOS API disabled successfully.")
            else:
                print(f"{generate_timestamp()}: WARNING: Unable to disable SonicOS API. Please check the firewall manually.")
        elif fw.gen == 7:
            # Retrieves the current SonicOS API configuration.
            sonicosapi_config = fw.get_request("administration/global/sonicos-api")
            if sonicosapi_config:
                print(f"{generate_timestamp()}: INFO: SonicOS API configuration retrieved successfully.")
                if a.verbose:
                    print(json.dumps(sonicosapi_config, indent=4))

            # Disables SonicOS API.
            sonicosapi_config["administration"]["sonicos_api"]["enable"] = False
            updated_sonicosapi_config = fw.put_request("administration/global/sonicos-api", sonicosapi_config)
            if updated_sonicosapi_config:
                print(f"{generate_timestamp()}: INFO: SonicOS API disabled successfully.")
                if a.verbose:
                    print(json.dumps(updated_sonicosapi_config, indent=4))
                fw.commit_pending()
                fw.logout()
        else:
            print(f"{generate_timestamp()}: WARNING: Unable to disable SonicOS API. Please check the firewall manually.")

    try:
        fw.logout()
    except KeyboardInterrupt:
        print(f"\nKeyboard interrupt detected. Exiting script.")
        exit()

    print(f"{generate_timestamp()}: INFO: Script completed successfully.")


if __name__ == "__main__":
    banner_info = [
        "       --  Workaround/mitigation for SNWLID-2025-0001  --\n",
        "This tool automates the following tasks:",
        " - Optionally exporting settings (-es argument) and a TSR (-etsr argument) prior to making changes.",
        " - Deleting domain-associated users (use the -du argument to enable this).",
        "   - This is disabled by default as a safety feature.",
        "   - We strongly recommend deleting the domain-associated local users as recommended in the PSIRT Advisory.",
        " - Re-creating LDAP server entries with userPrincipalName replaced by sAMAccountName",
        "   - Optionally restoring userPrincipalName if requested with the '-rupn' argument",
        " - Modifying the SSLVPN User Domain (if needed)",
        "Refer to the README for more detailed help.",
        "Visit https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0001 for the latest information.",
        "\n\nIMPORTANT NOTES:",
        " - This script will reboot the firewall.",
        " - The only change made to the LDAP server entries is replacing userPrincipalName with sAMAccountName.",
    ]
    print_banner(info=banner_info)

    # Creates the folders for any output.
    if path.exists(constants.RUNS_FOLDER) is False:
        mkdir(constants.RUNS_FOLDER)

    if path.exists(constants.START_TIMESTAMP_FOLDER) is False:
        mkdir(constants.START_TIMESTAMP_FOLDER)

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

    fw = Firewall(url=a.target,
                  username=api_username,
                  password=api_password,
                  sshport=a.sshport)

    routine(fw)

#     logged_in = fw.login()
#     if logged_in:
#         with open("runs/2025-03-10_08-12-11/C0EA-E481-8676_ldap_config.json", 'r') as f:
#             ldap_servers_config = json.load(f)
#
#         _ = None
#         if fw.gen == 6:
#             _ = fw.post_request("user/ldap/servers", ldap_servers_config)
#         elif fw.gen == 7 or fw.gen == 8:
#             _ = fw.put_request("user/ldap/servers", ldap_servers_config)
#         if _:
#             print(f"{generate_timestamp()}: INFO: LDAP server configuration updated successfully.")
#             print(json.dumps(_, indent=4))
#             print(f"{generate_timestamp()}: INFO: Committing the changes.")
#             commit_success, response_message = fw.commit_pending()
#             if commit_success:
#                 print(f"{generate_timestamp()}: INFO: {response_message}")
#             else:
#                 print(f"{generate_timestamp()}: WARNING: {response_message}")

