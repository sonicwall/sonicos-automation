from common.utils import generate_timestamp
from credential_reset.utils import should_run_check
from rich import print


def generate_markdown_summary(results: dict, firewall: str, firewall_info: dict, args):
    """Generate a markdown summary report of all checks and findings."""
    md_lines = []

    try:
        # Header
        sev_filter = f"(Severity Filter: {args.severity.upper()})" if args.severity != "all" else ""
        md_lines.append(f"# Remediation Playbook Summary Report {sev_filter}")
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
    except Exception as err:
        print(f"Error generating markdown header: {err}")
        return None

    try:
        # Exports
        md_lines.append(f"### Log and Configuration Exports")
        md_lines.append(f"")
        tsr_location = f"[{results.get('tsr_file_name', '')}]({results.get('tsr_file_name', '')})"
        settings_location = f"[{results.get('prefs_file_name', '')}]({results.get('prefs_file_name', '')})"

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
    except Exception as err:
        print(f"Error generating markdown exports section: {err}")
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

    # LDAP Servers
    if should_run_check('ldap_servers', args.severity):
        if get_count(results.get('ldap_servers', {})) > 0:
            action_items.append(f"| Critical | {get_count(results.get('ldap_servers', {}))} Server(s) Configured | LDAP server(s) require bind password updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_LDAP_Authentication) |")

    # RADIUS/TACACS Servers
    if should_run_check('radius_servers', args.severity):
        if get_count(results.get('radius_servers', {})) > 0:
            action_items.append(f"| Critical | {get_count(results.get('radius_servers', {}))} Server(s) Configured | RADIUS server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Authentication) |")

    # TACACS Servers
    if should_run_check('tacacs_servers', args.severity):
        if get_count(results.get('tacacs_servers', {})) > 0:
            action_items.append(f"| Critical | {get_count(results.get('tacacs_servers', {}))} Server(s) Configured | TACACS server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_TACACS__Authentication) |")

    # VPN Policies
    if should_run_check('vpn_policies', args.severity):
        if get_count(results.get('vpn', {}).get('policy', [])) > 0:
            # Counts the number of GroupVPN, Site-to-Site, and Tunnel Interface policies
            s2s_count = len([p for p in results.get('vpn', {}).get('policy', []) if p.get('ipv4', {}).get('site_to_site', {}).get('name')])
            s2s_disabled_count = len([p for p in results.get('vpn', {}).get('policy', []) if p.get('ipv4', {}).get('site_to_site', {}).get('enable', False)])
            groupvpn_count = len([p for p in results.get('vpn', {}).get('policy', []) if p.get('ipv4', {}).get('group_vpn', {}).get('name')])
            groupvpn_disabled_count = len([p for p in results.get('vpn', {}).get('policy', []) if p.get('ipv4', {}).get('group_vpn', {}).get('enable', False)])
            tunnelint_count = len([p for p in results.get('vpn', {}).get('policy', []) if p.get('ipv4', {}).get('tunnel_interface', {}).get('name')])
            tunnelint_disabled_count = len([p for p in results.get('vpn', {}).get('policy', []) if p.get('ipv4', {}).get('tunnel_interface', {}).get('enable', False)])
            action_items.append(f"| Critical | {get_count(results.get('vpn', {}).get('policy', []))} Policies Found<br>- {groupvpn_count} GroupVPN, {groupvpn_disabled_count} Disabled<br> - {s2s_count} Site-to-Site, {s2s_disabled_count} Disabled<br>- {tunnelint_count} Tunnel Interface, {tunnelint_disabled_count} Disabled | VPN policies require pre-shared key, authentication/encryption key updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared) |")

    # Dynamic DNS
    if should_run_check('ddns_services', args.severity):
        ddns_v4 = get_count(results.get('ddns_services_v4', []))
        ddns_v6 = get_count(results.get('ddns_services_v6', []))
        if ddns_v4 + ddns_v6 > 0:
            action_items.append(f"| High | {ddns_v4 + ddns_v6} Profile(s) | Dynamic DNS profile(s) require credential updates | [Link](https://www.sonicwall.com/support/knowledge-base/how-to-configure-dynamic-dns-for-a-particular-interface/170504323594835) |")

    # WAN Interfaces (L2TP/PPPoE/PPTP)
    if should_run_check('wan_interfaces', args.severity):
        interesting_wan_ints = [i for i in results.get('interesting_wan_list', [])]
        if len(interesting_wan_ints) > 0:
            action_items.append(f"| Critical | {len(interesting_wan_ints)} WAN interface(s) | {', '.join(interesting_wan_ints)} require credential updates for L2TP/PPPoE/PPTP connections | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a) |")

    # AWS API Logging
    if should_run_check('aws_api', args.severity):
        if results.get('log', {}).get('aws', {}).get('enable', False):
            action_items.append(f"| Critical | Enabled | AWS API Logging is enabled - Update the secret key in the AWS Console | [Link](https://www.sonicwall.com/support/knowledge-base/aws-integration-with-sonicwall-sonicos-6-5-x/181024232124532) |")

    # Cloud Secure Edge
    if should_run_check('cloud_secure_edge', args.severity):
        if results.get('cloud_secure_edge', {}).get('created', False):
            action_items.append(f"| Critical | Enabled | Cloud Secure Edge is enabled - Reset the CSE connector's API token | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_CSE) |")

    # Email logging actions
    if should_run_check('email_logging', args.severity):
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

    if should_run_check('packet_monitor_ftp', args.severity):
        try:
            # Packet Monitor FTP action
            if results.get('packet_monitor_ftp_set', False):
                action_items.append(f"| Medium | Configured | Packet Monitor FTP credentials require updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Reset_any_passwords:~:text=for%20more%20information.-,FTP/Web%20Passwords,-Reset%20the%20password) |")
        except Exception as e:
            print(f"Error checking packet monitor FTP setting: {e}")

    if should_run_check('scheduled_exports', args.severity):
        try:
            # Scheduled Exports FTP action
            if results.get('scheduled_exports_ftp_set', False):
                action_items.append(f"| Medium | Configured | TSR/EXP Scheduled Exports credentials require updates | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-device_settings/Content/Topics/Firmware_Settings/firmware-backup-configuring.htm) |")
        except Exception as e:
            print(f"Error checking scheduled exports FTP setting: {e}")

    # SNMPv3 Users
    if should_run_check('snmp_users', args.severity):
        if get_count(results.get('snmp', {}).get('user', [])) > 0:
            action_items.append(f"| High | {get_count(results.get('snmp', {}).get('user', []))} Users Found | SNMPv3 user(s) require authentication/privacy password updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_SNMP_-_SNMP) |")

    # ClearPass/Network Access Control (NAC)
    if should_run_check('clearpass_nac', args.severity):
        try:
            if results.get('clearpass_enabled', False):
                clearpass_server_count = len(results.get('clearpass_servers', []))
                action_items.append(f"| High | Enabled ({clearpass_server_count} Servers) | ClearPass/Network Access Control (NAC) is enabled with {clearpass_server_count} server(s) - {'update the shared secret on each configured entry' if clearpass_server_count > 0 else 'configure NAC entries or disable the feature if not in use'} | [Link](https://www.sonicwall.com/support/knowledge-base/how-to-add-a-clearpass-server-on-a-sonicwall-firewall/240523045608440) |")
        except Exception as e:
            print(f"Error checking ClearPass setting: {e}")

    # Cellular WWAN
    if should_run_check('cellular_wwan', args.severity):
        if results.get('cellular_attached', False):
            action_items.append(f"| High | Modem Found | Cellular WWAN is enabled - Update the cellular provider credentials | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a) |")

    # Wireless: Guest Services External Authentication
    if should_run_check('guest_services_auth', args.severity):
        try:
            guest_auth = results.get('guest_zone_data', [])
            if guest_auth:
                action_items.append(f"| Medium | {len(guest_auth)} Zone(s) Found | Wireless Guest Services External Authentication is enabled - Update the shared secret on each configured entry | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Reset_any_passwords:~:text=more%20information.-,Guest%20Services,-Reset%20the%20shared) |")
        except Exception as e:
            print(f"Error checking Wireless Guest Services setting: {e}")

    # Wireless: Local RADIUS Servers on Wireless type Zones
    if should_run_check('wlan_radius_servers', args.severity):
        try:
            wireless_radius_count = get_count(results.get('wlan_zone_data', []))
            if wireless_radius_count > 0:
                action_items.append(f"| Medium | {wireless_radius_count} Zone(s) Found | {wireless_radius_count} Wireless Zone(s) configured with Local RADIUS Servers - Update the shared secret on each configured entry | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-0-0-0-access_points/Content/Access_Points_Settings/access-point-settings-about-local-radius-servers.htm) |")
        except Exception as e:
            print(f"Error checking Wireless Local RADIUS Servers: {e}")

    # Wireless: Internal WLAN Radio
    if should_run_check('internal_wlan_radio', args.severity):
        try:
            radio_radius = results.get('internal_wlan', {}).get('wireless', {}).get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
            radio_psk = results.get('internal_wlan', {}).get('wireless', {}).get('wpa', {}).get('passphrase', None)
            if radio_radius or radio_psk:
                action_items.append(f"| Medium | Configured | Internal WLAN Radio is enabled - Update the pre-shared keys, RADIUS, and RADIUS Accounting secrets on the server, then in SonicOS | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking Internal WLAN Radio setting: {e}")

    # Wireless: Internal WLAN Virtual Access Points (VAPs) Objects
    if should_run_check('internal_wlan_vaps', args.severity):
        try:
            vap_count = get_count(results.get('internal_wlan_vaps', {}).get('wireless', {}).get('virtual_access_point', {}).get('object', []))
            if vap_count > 0:
                action_items.append(f"| Medium | {vap_count} Internal WLAN Virtual Access Point(s) Found | Update the WLAN password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking Internal WLAN VAPs: {e}")

    # Wireless: Internal WLAN Virtual Access Points (VAPs) Profiles
    if should_run_check('internal_wlan_vap_profiles', args.severity):
        try:
            vap_profile_count = get_count(results.get('internal_wlan_vap_profiles', {}).get('wireless', {}).get('virtual_access_point', {}).get('profile', []))
            if vap_profile_count > 0:
                action_items.append(f"| Medium | {vap_profile_count} Profile(s) Found | Update the WLAN Virtual Access Point Profile(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking Internal WLAN VAP Profiles: {e}")

    # Wireless: SonicPoint/SonicWave Access Point Objects
    if should_run_check('sonicpoint_objects', args.severity):
        try:
            ap_count = get_count(results.get('sonicpoint_objects', {}).get('sonicpoint', {}).get('sonicpoint', []))
            if ap_count > 0:
                action_items.append(f"| Medium | {ap_count} Ojects Found | Update the WLAN SonicPoint/SonicWave Access Point(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking SonicPoint/SonicWave Access Points: {e}")

    # Wireless: SonicPoint/SonicWave Access Point Profiles
    if should_run_check('sonicpoint_profiles', args.severity):
        try:
            ap_profile_count = len(results.get('sonicpoint_profiles', {}).get('sonicpoint', {}).get('profile', []))
            if ap_profile_count > 0:
                action_items.append(f"| Medium | {ap_profile_count} Profile(s) Found | Update the WLAN SonicPoint/SonicWave Access Point Profile(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking SonicPoint/SonicWave Access Point Profiles: {e}")

    # Wireless: SonicPoint/SonicWave Virtual Access Points (VAPs) Objects
    if should_run_check('sonicpoint_vaps', args.severity):
        try:
            sp_vap_count = get_count(results.get('sonicpoint_vaps', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('object', []))
            if sp_vap_count > 0:
                action_items.append(f"| Medium | {sp_vap_count} Objects Found | Update the WLAN SonicPoint/SonicWave Virtual Access Point(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking SonicPoint/SonicWave VAPs: {e}")

    # Wireless: SonicPoint/SonicWave Virtual Access Points (VAPs) Profiles
    if should_run_check('sonicpoint_vap_profiles', args.severity):
        try:
            sp_vap_profile_count = get_count(results.get('sonicpoint_vap_profiles', {}).get('sonicpoint', {}).get('virtual_access_point', {}).get('profile', []))
            if sp_vap_profile_count > 0:
                action_items.append(f"| Medium | {sp_vap_profile_count} Profile(s) Found | Update the WLAN SonicPoint/SonicWave Virtual Access Point Profile(s) password(s) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Wireless_-_Wi-Fi) |")
        except Exception as e:
            print(f"Error checking SonicPoint/SonicWave VAP Profiles: {e}")

    # Dynamic External Address Objects
    if should_run_check('dynamic_address_objects', args.severity):
        try:
            dynamic_address_count = results.get('dynamic_ao_count', 0)
            if dynamic_address_count > 0:
                action_items.append(f"| High | {dynamic_address_count} Object(s) Found | Review and update credentials for Dynamic External Address Object(s) | [Link](https://www.sonicwall.com/support/knowledge-base/what-are-dynamic-external-objects-groups-and-how-can-we-configure-it/200507105852280) |")
        except Exception as e:
            print(f"Error checking Dynamic External Address Objects: {e}")

    # Dynamic Botnet List Server (FTP/HTTPS)
    if should_run_check('dynamic_botnet_list_server', args.severity):
        try:
            botnet_data = results.get('botnet_data', {})
            if botnet_data.get('protocol', False):
                action_items.append(f"| Low | Configured ({botnet_data.get('protocol', '').upper()}) | Review and update Dynamic Botnet List Server credentials | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-rules_policies_policy/Content/Settings/settings-botnet-dynamic-botnet-list-server-config.htm) |")
        except Exception as e:
            print(f"Error checking Dynamic Botnet List Server: {e}")

    # Extended Switches
    if should_run_check('extended_switches', args.severity):
        try:
            if firewall_info['firewall_generation'] == 6:
                ext_switch_count = get_count(results.get('switch_controller', {}).get('switch', []))
            else:
                ext_switch_count = get_count(results.get('switch_controller', {}).get('switch_info', []))
            if ext_switch_count > 0:
                action_items.append(f"| Low | {ext_switch_count} Extended Switch(es) Found | Review and update credentials on the switch(es) | [Link](https://www.sonicwall.com/support/knowledge-base/how-to-change-the-password-for-sonicwall-switch/200607142015373) |")
        except Exception as e:
            print(f"Error checking Extended Switches: {e}")

    # Extended Switch Users
    if should_run_check('extended_switch_users', args.severity):
        try:
            ext_switch_user_count = get_count(results.get('extended_switch_users', []))
            if ext_switch_user_count > 0:
                action_items.append(f"| Low | {ext_switch_user_count} Extended Switch User(s) Found | Review and update credentials on the switch(es) | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=and%20Backup%20Settings)-,Extended%20Switches,-Reset%20the%20password) |")
        except Exception as e:
            print(f"Error checking Extended Switch Users: {e}")

    # Extended Switch RADIUS Servers
    if should_run_check('extended_switch_radius', args.severity):
        try:
            ext_switch_radius_count = get_count(results.get('extended_switch_radius_servers', []))
            if ext_switch_radius_count > 0:
                action_items.append(f"| Low | {ext_switch_radius_count} Extended Switch RADIUS Server(s) Found | Review and update shared secrets on the switch(es) and in SonicOS | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=and%20Backup%20Settings)-,Extended%20Switches,-Reset%20the%20password) |")
        except Exception as e:
            print(f"Error checking Extended Switch RADIUS Servers: {e}")

    # SSO Agents
    if should_run_check('sso_agents', args.severity):
        if get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', []))} Agents Found | SSO agent(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # Terminal Services Agents
    if should_run_check('ts_agents', args.severity):
        if get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', []))} Agents Found | Terminal Services agent(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # RADIUS Accounting Clients
    if should_run_check('sso_radius_clients', args.severity):
        if get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', []))} RA Clients Found | SSO RADIUS Accounting client(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # 3rd Party API Clients
    if should_run_check('sso_api_clients', args.severity):
        if get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []))} API Clients Found | SSO 3rd Party API client(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets) |")

    # RADIUS Accounting Servers
    if should_run_check('radius_accounting_servers', args.severity):
        if get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', []))} Servers Found | RADIUS Accounting server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries) |")

    # TACACS Accounting Servers
    if should_run_check('tacacs_accounting_servers', args.severity):
        if get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []))} Servers Found | TACACS Accounting server(s) require shared secret updates | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries) |")

    # AppFlow SFR Mailing
    if should_run_check('sfr_reporting', args.severity):
        if results.get('sfr_data', {}).get('smtp_configured', False) or results.get('sfr_data', {}).get('pop_configured', False):
            action_items.append(f"| Low | Configured | AppFlow SFR Mailing is configured - Update the email server credentials | [Link](https://www.sonicwall.com/support/technical-documentation/docs/sonicos-7-1-appflow_device/Content/appflow-d-flow-reporting-sfr-mailing.htm) |")

    # Custom NTP Servers
    if should_run_check('ntp_servers', args.severity):
        if get_count(results.get('ntp_data', [])) > 0:
            action_items.append(f"| Low | {get_count(results.get('ntp_data', []))} Servers Found | Custom NTP server(s) require authentication password updates | [Link](https://www.sonicwall.com/support/knowledge-base/service-configuration-how-to-configure-ntp-and-snmp-services/210715103828777) |")

    # Security Services Signature Proxy
    if should_run_check('security_services_proxy', args.severity):
        if results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False) or results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', ''):
            action_items.append(f"| Low | Configured | Security Services Proxy is configured - Update the proxy server credentials | [Link](https://www.sonicwall.com/support/knowledge-base/signature-downloads-through-a-proxy-server/170503292286520) |")

    # GMS IPSec Management Tunnel
    if should_run_check('gms_ipsec_tunnel', args.severity):
        if results.get('gms', {}).get('ipsec_tunnel', False):
            action_items.append(f"| Low | Configured | GMS IPSec Management Tunnel is configured - Update the encryption/authentication keys | [Link](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared) |")

    # Advanced Routing Protocols
    if should_run_check('advanced_routing', args.severity):
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
    md_lines.append(f"3. **Distribute** the temporary password to each user, if one was set. If randomized passwords were enabled, refer to table at the end of this report for the assigned passwords")
    md_lines.append(f"")
    md_lines.append(f"---")
    md_lines.append(f"")

    # Detailed Findings
    md_lines.append(f"## Detailed Findings {sev_filter}")
    md_lines.append(f"The following sections provide detailed information on the findings and actions taken during the remediation playbook execution.")
    md_lines.append(f"")

    # Authentication
    md_lines.append(f"### Authentication")
    md_lines.append(f"")

    # LDAP Servers
    if should_run_check('ldap_servers', args.severity):
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
    if should_run_check('radius_servers', args.severity):
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
    if should_run_check('tacacs_servers', args.severity):
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
    if should_run_check('sso_agents', args.severity):
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
    if should_run_check('ts_agents', args.severity):
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
    if should_run_check('sso_radius_clients', args.severity):
        try:
            radius_acct_count = get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', []))
            md_lines.append(f"- **RADIUS Accounting Clients:** {radius_acct_count}")
            if radius_acct_count > 0:
                md_lines.append(f"  - **Action:** Update shared secrets")
                md_lines.append(f"  - **Priority:** Low")
                md_lines.append(f"  - **Reference:** [RADIUS Accounting Clients](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#:~:text=External%20Guest%20Authentication-,SSO,-Reset%20shared%20secrets)")
        except Exception as e:
            print(f"Error generating RADIUS Accounting section: {e}")
            md_lines.append(f"- **RADIUS Accounting Clients:** Error retrieving information")

    # 3rd Party API Clients
    if should_run_check('sso_api_clients', args.severity):
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
    if should_run_check('radius_accounting_servers', args.severity):
        try:
            radius_acct_server_count = get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', []))
            md_lines.append(f"- **RADIUS Accounting Servers:** {radius_acct_server_count}")
            if radius_acct_server_count > 0:
                md_lines.append(f"  - **Action:** Update shared secrets")
                md_lines.append(f"  - **Priority:** Low")
                md_lines.append(f"  - **Reference:** [RADIUS Accounting Servers](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_RADIUS_Accounting_Servers:~:text=Reset%20RADIUS/TACACS%2B%20shared%20secrets%20used%20for%20Accounting%20server%20entries)")
        except Exception as e:
            print(f"Error generating RADIUS Accounting Servers section: {e}")
            md_lines.append(f"- **RADIUS Accounting Servers:** Error retrieving information")

    # TACACS Accounting Servers
    if should_run_check('tacacs_accounting_servers', args.severity):
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
    if should_run_check('vpn_policies', args.severity):
        md_lines.append(f"### VPN")
        md_lines.append(f"")
        try:
            vpn_count = get_count(results.get('vpn', {}).get('policy', []))
            md_lines.append(f"- **VPN Policies:** {vpn_count}")
            if vpn_count > 0:
                md_lines.append(f"  - **Action:** Review and update pre-shared keys and authentication/encryption keys")
                md_lines.append(f"  - **Priority:** Critical")
                md_lines.append(f"  - **Reference:** [IPSec VPN pre-shared keys](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_IPSec_VPN_pre-shared)")
            md_lines.append(f"  - **Enabled Policies:**")
            for policy in results.get('vpn', {}).get('policy', []):
                policy_name = policy.get('ipv4', {}).get('group_vpn', {}).get('name') or policy.get('ipv4', {}).get('site_to_site', {}).get('name') or policy.get('ipv4', {}).get('tunnel_interface', {}).get('name')
                policy_status = policy.get('ipv4', {}).get('group_vpn', {}).get('enable', False) or policy.get('ipv4', {}).get('site_to_site', {}).get('enable', False) or policy.get('ipv4', {}).get('tunnel_interface', {}).get('enable', False)
                if policy_status:
                    md_lines.append(f"    - **{policy_name}**")
            md_lines.append(f"  - **Disabled Policies:**")
            for policy in results.get('vpn', {}).get('policy', []):
                policy_name = policy.get('ipv4', {}).get('group_vpn', {}).get('name') or policy.get('ipv4', {}).get('site_to_site', {}).get('name') or policy.get('ipv4', {}).get('tunnel_interface', {}).get('name')
                policy_status = policy.get('ipv4', {}).get('group_vpn', {}).get('enable', False) or policy.get('ipv4', {}).get('site_to_site', {}).get('enable', False) or policy.get('ipv4', {}).get('tunnel_interface', {}).get('enable', False)
                if not policy_status:
                    md_lines.append(f"    - **{policy_name}**")
        except Exception as e:
            print(f"Error processing VPN policies: {e}")
            md_lines.append(f"- **VPN Policies:** Error retrieving count")
        md_lines.append(f"")

    # Network Services
    md_lines.append(f"### Network Services")
    md_lines.append(f"")

    # WAN Interfaces (PPPoE/PPTP/L2TP)
    if should_run_check('wan_interfaces', args.severity):
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
    if should_run_check('cellular_wwan', args.severity):
        try:
            wwan_attached = results.get('cellular_attached', False)
            if wwan_attached:
                md_lines.append(f"- **Cellular WWAN Model Detected:**")
                md_lines.append(f"  - **Action:** Update cellular provider credentials at the provider's website, then update in SonicOS")
                if firewall_info['firewall_generation'] == 6:
                    md_lines.append(f"  - **GEN6 Notice:** For GEN6 firewalls, this check found cellular model connection profiles. Please ensure to update credentials for each profile as applicable.")
                md_lines.append(f"  - **Priority:** High")
                md_lines.append(f"  - **Reference:** [Cellular WWAN Configuration](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590#_Interface_L2TP/PPPoE/PPTP%C2%A0password(s)_a)")
        except Exception as e:
            print(f"Error processing Cellular WWAN: {e}")
            md_lines.append(f"- **Cellular WWAN Interfaces:** Error retrieving information")

    # Dynamic DNS
    if should_run_check('ddns_services', args.severity):
        md_lines.append(f"- **Dynamic DNS (IPv4) Profiles:** {ddns_v4}")
        md_lines.append(f"- **Dynamic DNS (IPv6) Profiles:** {ddns_v6}")
        if ddns_v4 + ddns_v6 > 0:
            md_lines.append(f"  - **Action:** Update DDNS provider credentials for each configured entry at the provider's website, then update in SonicOS")
            md_lines.append(f"  - **Priority:** High")
            md_lines.append(f"  - **Reference:** [Dynamic DNS Configuration](https://www.sonicwall.com/support/knowledge-base/how-to-configure-dynamic-dns-for-a-particular-interface/170504323594835)")

    # ClearPass/NAC
    if should_run_check('clearpass_nac', args.severity):
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
    if should_run_check('dynamic_address_objects', args.severity):
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
    if should_run_check('dynamic_botnet_list_server', args.severity):
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
    if should_run_check('ntp_servers', args.severity):
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
    if should_run_check('security_services_proxy', args.severity):
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
    if should_run_check('guest_services_auth', args.severity):
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
    if should_run_check('wlan_radius_servers', args.severity):
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
    if should_run_check('internal_wlan_radio', args.severity):
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
    if should_run_check('internal_wlan_vaps', args.severity):
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
    if should_run_check('internal_wlan_vap_profiles', args.severity):
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
    if should_run_check('sonicpoint_objects', args.severity):
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
    if should_run_check('sonicpoint_profiles', args.severity):
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
    if should_run_check('sonicpoint_vaps', args.severity):
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
    if should_run_check('sonicpoint_vap_profiles', args.severity):
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

    if should_run_check('extended_switches', args.severity):
        try:
            if firewall_info['firewall_generation'] == 6:
                switch_count = get_count(results.get('switch_controller', {}).get('switch', []))
            else:
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
    if should_run_check('extended_switch_users', args.severity):
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
    if should_run_check('extended_switch_radius', args.severity):
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
    if should_run_check('gms_ipsec_tunnel', args.severity):
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
    if should_run_check('advanced_routing', args.severity):
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
    if should_run_check('snmp_users', args.severity):
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
    if should_run_check('email_logging', args.severity):
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
    if should_run_check('packet_monitor_ftp', args.severity):
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
    if should_run_check('scheduled_exports', args.severity):
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
    if should_run_check('sfr_reporting', args.severity):
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
    if should_run_check('aws_api', args.severity):
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
    if should_run_check('cloud_secure_edge', args.severity):
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
    # fpc_results = results.get('users', [])
    # fpc_results = results.get('users', {}).get('user', {}).get('local', {}).get('user', [])
    fpc_results = results.get('credential_reset', {}).get('results', [])
    totp_results = results.get('totp_unbind', {}).get('results', {}).get('totp_unbind_results', [])

    # Combine the dictionaries within fpc_results and totp_results lists
    combined_user_results = {}

    # Process force password change results
    for user_result in fpc_results:
        username = user_result.get('name', 'Unknown')
        combined_user_results[username] = {
            'name': username,
            'forced_password_change': user_result.get('forced_password_change', False),
            'skipped': user_result.get('skipped', False),
            'reason': user_result.get('reason', ''),
            'user_update_successful': user_result.get('user_update_successful', False),
            'commit_successful': user_result.get('commit_successful', False),
            'new_password': user_result.get('new_password', ''),
            'totp_unbound': False,
            'totp_skipped': False,
            'totp_reason': '',
            'domain': user_result.get('domain', None),
            'api_response': user_result.get('api_response', None),
            'totp_unbind_attempted': False
        }

    # Process TOTP unbind results and merge with password change results
    for totp_result in totp_results:
        username = totp_result.get('name', 'Unknown')
        if username in combined_user_results:
            combined_user_results[username]['totp_unbound'] = totp_result.get('totp_unbound', False)
            combined_user_results[username]['totp_skipped'] = totp_result.get('skipped', False)
            combined_user_results[username]['totp_reason'] = totp_result.get('reason', '')
            combined_user_results[username]['domain'] = totp_result.get('domain', None)
            combined_user_results[username]['api_response'] = totp_result.get('api_response', None)
            combined_user_results[username]['totp_unbind_attempted'] = totp_result.get('totp_unbind_attempted', False)
        else:
            combined_user_results[username] = {
                'name': username,
                'forced_password_change': False,
                'skipped': False,
                'reason': '',
                'user_update_successful': False,
                'commit_successful': False,
                'new_password': '',
                'totp_unbound': totp_result.get('totp_unbound', False),
                'totp_skipped': totp_result.get('skipped', False),
                'totp_reason': totp_result.get('reason', ''),
                'domain': totp_result.get('domain', None),
                'api_response': totp_result.get('api_response', None),
                'totp_unbind_attempted': totp_result.get('totp_unbind_attempted', False)
            }

    # Change some key named to avoid collision during merge
    # for t in totp_unbind_results:
    #     t['totp_skipped'] = t.pop('skipped', False)
    #     t['totp_reason'] = t.pop('reason', None)
    # totp_lookup = {t["name"]: t for t in totp_unbind_results}

    # Merges the two lists based on username
    # user_list = [{**u, **totp_lookup.get(u["name"], {})} for u in fpc_results]
    user_list = list(combined_user_results.values())

    try:
        if user_list:
            md_lines.append(f"")
            md_lines.append(f"#### User Details")
            md_lines.append(f"")
            md_lines.append(f"| Username | Password Change Forced | Skipped Force Password Change | Reset/Unbind TOTP | Skipped TOTP Binding Reset | New Password |")
            md_lines.append(f"|----------|-----------------------|-------------------------------|-------------------|----------------------------|--------------|")
            for user in user_list:
                force_pass = "Yes" if user.get('commit_successful') else "No"
                skipped = "Yes" if user.get('skipped') else "No"
                unbound_totp = "Yes" if user.get('totp_unbound', False) and not user.get('totp_skipped', False) else ("No" if user.get('totp_unbind_attempted') else "N/A")
                totp_skipped = "Yes" if user.get('totp_skipped', False) else "No"
                new_passwd = user.get('new_password', '')
                md_lines.append(f"| {user.get('name', 'Unknown')} | {force_pass} | {skipped} | {unbound_totp} | {totp_skipped} | {new_passwd} |")
    except Exception as e:
        print(f"Error generating user details table: {e}")

    return "\n".join(md_lines)

