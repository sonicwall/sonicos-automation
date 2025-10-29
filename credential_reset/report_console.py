from rich import print
from rich.table import Table
from rich.console import Console
from rich.text import Text
import common.constants as constants
from credential_reset.utils import (
    should_run_check,
)


def generate_summary_table(results: dict, args):
    """Generate a rich table summarizing all security checks and their findings."""
    try:
        console = Console()

        # Main summary table
        sev_filter = f"(Severity Filter: {args.severity.upper()})" if args.severity != "all" else ""
        table = Table(title=f"Remediation Playbook Summary {sev_filter}",
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
        if should_run_check('ldap_servers', args.severity):
            ldap_count = get_count(results.get('ldap_servers', {}))
            if ldap_count > 0:
                table.add_row("LDAP Servers", "Find configured LDAP servers", "Critical",
                              "[green]Servers Configured[/green]", str(ldap_count), "[red]Update the LDAP bind credentials on the server and in SonicOS.[/red]")
            else:
                table.add_row("LDAP Servers", "Find configured LDAP servers", "Critical",
                              "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        if should_run_check('radius_servers', args.severity):
            radius_count = get_count(results.get('radius_servers', {}))
            if radius_count > 0:
                table.add_row("RADIUS Servers", "Find configured RADIUS servers", "Critical",
                              "[green]Servers Configured[/green]", str(radius_count), "[red]Update the RADIUS shared secret on the server and in SonicOS.[/red]")
            else:
                table.add_row("RADIUS Servers", "Find configured RADIUS servers", "Critical",
                              "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        if should_run_check('tacacs_servers', args.severity):
            tacacs_count = get_count(results.get('tacacs_servers', {}))
            if tacacs_count > 0:
                table.add_row("TACACS Servers", "Find configured TACACS servers", "Critical",
                              "[green]Servers Configured[/green]", str(tacacs_count), "[red]Update the shared secret on the server and in SonicOS.[/red]")
            else:
                table.add_row("TACACS Servers", "Find configured TACACS servers", "Critical",
                              "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        # VPN - /api/sonicos/vpn/policies/all
        if should_run_check('vpn_policies', args.severity):
            vpn_count = get_count(results.get('vpn', {}).get('policy', []))
            if vpn_count > 0:
                table.add_row("VPN Policies", "Find configured VPN policies", "Critical",
                              "[green]Policies Found[/green]", str(vpn_count), "[red]Update the pre-shared secrets and/or encryption and authentication keys on each policy.[/red]")
            else:
                table.add_row("VPN Policies", "Find configured VPN policies", "Critical",
                              "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # WAN Interfaces (PPPoE/PPTP/L2TP) - /api/sonicos/interfaces/ipv4
        if should_run_check('wan_interfaces', args.severity):
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
        if should_run_check('aws_api', args.severity):
            aws_enabled = results.get('log', {}).get('aws', {}).get('enable', False)
            if aws_enabled:
                table.add_row("AWS API Logging", "Check the AWS API integration status", "Critical",
                              "[green]Enabled[/green]", "", "[red]Update the secret key on the AWS Console, then in SonicOS.[/red]")
            else:
                table.add_row("AWS API Logging", "Check the AWS API integration status", "Critical",
                              "[dim]Not Enabled[/dim]", "", "[dim]No action required[/dim]")

        # Network Services - Dynamic DNS - /api/sonicos/dynamic-dns/profiles/ipv6 and /api/sonicos/dynamic-dns/profiles/ipv4
        if should_run_check('ddns_services', args.severity):
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
        if should_run_check('cloud_secure_edge', args.severity):
            cse_enabled = results.get('cloud_secure_edge', {}).get('created', False)
            if cse_enabled:
                table.add_row("Cloud Secure Edge", "Checks Cloud Secure Edge (CSE) status", "Critical",
                              "[green]Enabled[/green]", "", "[red]Reset the CSE connector's API token.[/red]")
            else:
                table.add_row("Cloud Secure Edge", "Checks Cloud Secure Edge (CSE) status", "Critical",
                              "[dim]Not Enabled[/dim]", "", "[dim]No action required[/dim]")

        # Email Logging - /api/sonicos/log/automation
        if should_run_check('email_logging', args.severity):
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
        if should_run_check('packet_monitor_ftp', args.severity):
            pktmon_flagged = results.get('packet_monitor_ftp_set', False)
            if pktmon_flagged:
                table.add_row("Packet Monitor FTP Logging", "Checks for FTP logging configuration", "Medium",
                              "[green]Configured[/green]", "", "[red]Update the FTP credentials on the server and in SonicOS.[/red]")
            else:
                table.add_row("Packet Monitor FTP Logging", "Checks for FTP logging configuration", "Medium",
                              "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Settings/TSR Scheduled Exports - /api/sonicos/ftp/base
        if should_run_check('scheduled_exports', args.severity):
            export_enabled = results.get('scheduled_exports_ftp_set', False)
            if export_enabled:
                table.add_row("TSR/EXP Scheduled Exports", "Checks for FTP configuration", "Medium",
                              "[green]Configured[/green]", "", "[red]Update the FTP credentials on the server and in SonicOS.[/red]")
            else:
                table.add_row("TSR Scheduled Exports", "Checks for FTP configuration", "Medium",
                              "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # SNMP - /api/sonicos/snmp/users
        if should_run_check('snmp_users', args.severity):
            snmp_count = get_count(results.get('snmp', {}).get('user', []))
            if snmp_count > 0:
                table.add_row("SNMPv3 Users", "Find configured SNMP user entries", "High",
                              "[green]Users Found[/green]", str(snmp_count), "[red]Update the password of each SNMP user.[/red]")
            else:
                table.add_row("SNMPv3 Users", "Find configured SNMP user entries", "High",
                              "[dim]No users found[/dim]", "", "[dim]No action required[/dim]")

        # Clearpass/NAC - /api/sonicos/network-access-control/clearpass/base
        # /api/sonicos/network-access-control/clearpass/servers
        if should_run_check('clearpass_nac', args.severity):
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
        if should_run_check('cellular_wwan', args.severity):
            cell_attached = results.get('cellular_attached', False)
            if cell_attached:
                table.add_row("Cellular WWAN", "Checks for an attached modem", "High",
                              "[green]Modem Attached[/green]", "", "[red]Update the credentials with the cellular provider and in SonicOS.[/red]")
            else:
                table.add_row("Cellular WWAN", "Checks for an attached modem", "High",
                              "[dim]Modem not found[/dim]", "", "[dim]No action required[/dim]")

        # Zone Objects: Wireless Guest Services External Guest Authentication (Message Authentication)
        if should_run_check('guest_services_auth', args.severity):
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
        if should_run_check('wlan_radius_servers', args.severity):
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
        if should_run_check('internal_wlan_radio', args.severity):
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
        if should_run_check('internal_wlan_vaps', args.severity):
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
        if should_run_check('internal_wlan_vap_profiles', args.severity):
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
        if should_run_check('sonicpoint_objects', args.severity):
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
        if should_run_check('sonicpoint_profiles', args.severity):
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
        if should_run_check('sonicpoint_vaps', args.severity):
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
        if should_run_check('sonicpoint_vap_profiles', args.severity):
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
        if should_run_check('dynamic_address_objects', args.severity):
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

        # Dynamic Botnet List Server - /api/sonicos/botnet/base
        if should_run_check('dynamic_botnet_list_server', args.severity):
            botnet_data = results.get('botnet_data', {})
            if botnet_data:
                if botnet_data.get('protocol', '') == 'ftp' and botnet_data.get('ftp_server') not in ('0.0.0.0', ''):
                    table.add_row("Botnet List Server (FTP)", "Checks Dynamic Botnet List Server", "Low",
                                  "[green]Configured[/green]", "", "[red]FTP server is configured. Update the FTP credentials on the server and in SonicOS.[/red]")
                elif botnet_data['protocol'] == 'https' and botnet_data['https_url'] != '':
                    table.add_row("Botnet List Server (HTTPS)", "Checks Dynamic Botnet List Server", "Low",
                                  "[green]Configured[/green]", "", "[red]HTTPS URL is set. If credentials were provided, update them on the server and in SonicOS.[/red]")
                else:
                    table.add_row("Botnet List Server", "Checks Dynamic Botnet List Server", "Low",
                                  "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")
            else:
                table.add_row("Botnet List Server", "Checks Dynamic Botnet List Server", "Low",
                              "[dim]No configuration found[/dim]", "", "[dim]No action required[/dim]")

        # Extended Switches
        if should_run_check('extended_switches', args.severity):
            if results['firewall_generation'] == 6:
                switch_count = get_count(results.get('switch_controller', {}).get('switch', []))
            else:
                switch_count = get_count(results.get('switch_controller', {}).get('switch_info', []))
            if switch_count > 0:
                table.add_row("Extended Switches", "Checks for connected switches", "Low",
                              "[green]Switches Found[/green]", str(switch_count), "[red]Update the password for any extended switches.[/red]")
            else:
                table.add_row("Extended Switches", "Checks for connected switches", "Low",
                              "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Extended Switch Users
        if should_run_check('extended_switch_users', args.severity):
            switch_user_count = get_count(results.get('extended_switch_users', []))
            if switch_user_count > 0:
                table.add_row("External Switch Users", "Looks for users in switch config", "Low",
                              "[green]Users Found[/green]", str(switch_user_count), "[red]Update each user's password in the switch configuration.[/red]")
            else:
                table.add_row("External Switch Users", "Looks for users in switch config", "Low",
                              "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Extended Switch RADIUS Servers
        if should_run_check('extended_switch_radius', args.severity):
            switch_radius_count = get_count(results.get('switch_controller', {}).get('radius', []))
            if switch_radius_count > 0:
                table.add_row("External Switch RADIUS Servers", "Looks for RADIUS server config", "Low",
                              "[green]Servers Found[/green]", str(switch_radius_count), "[red]Update the RADIUS shared secret on each server and in the switch configuration.[/red]")
            else:
                table.add_row("External Switch RADIUS Servers", "Looks for RADIUS server config", "Low",
                              "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # SSO Agents - /api/sonicos/user/sso/agents
        if should_run_check('sso_agents', args.severity):
            sso_count = get_count(results.get('sso_agents', {}).get('user', {}).get('sso', {}).get('agent', []))
            if sso_count > 0:
                table.add_row("Single Sign On Agents", "Finds configured SSO Agents", "Low",
                              "[green]Agents Found[/green]", str(sso_count), "[red]Update the shared secrets on each agent.[/red]")
            else:
                table.add_row("Single Sign On Agents", "Finds configured SSO Agents", "Low",
                              "[dim]No agents found[/dim]", "", "[dim]No action required[/dim]")

        # TS Agents - /api/sonicos/user/sso/terminal-services-agents
        if should_run_check('ts_agents', args.severity):
            tsa_count = get_count(results.get('ts_agents', {}).get('user', {}).get('sso', {}).get('terminal_services_agent', []))
            if tsa_count > 0:
                table.add_row("Terminal Services Agents", "Finds configured TS Agents", "Low",
                              "[green]Agents Found[/green]", str(tsa_count), "[red]Update the shared secrets on each agent.[/red]")
            else:
                table.add_row("Terminal Services Agents", "Finds configured TS Agents", "Low",
                              "[dim]No agents found[/dim]", "", "[dim]No action required[/dim]")

        # SSO RADIUS Accounting Clients - /api/sonicos/user/sso/radius-accounting-clients
        if should_run_check('sso_radius_clients', args.severity):
            sso_radius_count = get_count(results.get('sso_radius_clients', {}).get('user', {}).get('sso', {}).get('radius_accounting_client', []))
            if sso_radius_count > 0:
                table.add_row("SSO RADIUS Accounting Clients", "Finds configured SSO RA Clients", "Low",
                              "[green]RA Clients Found[/green]", str(sso_radius_count), "[red]Update the shared secrets on each client and in SonicOS.[/red]")
            else:
                table.add_row("SSO RADIUS Accounting Clients", "Finds configured SSO RA Clients", "Low",
                              "[dim]No RA clients found[/dim]", "", "[dim]No action required[/dim]")

        # SSO 3rd Party API - /api/sonicos/user/sso/third-party-api/clients
        if should_run_check('sso_api_clients', args.severity):
            sso_api_count = get_count(results.get('sso_api_clients', {}).get('user', {}).get('sso', {}).get('third_party_api', {}).get('client', []))
            if sso_api_count > 0:
                table.add_row("SSO 3rd Party API Clients", "Finds SSO API Client entries", "Low",
                              "[green]API Clients Found[/green]", str(sso_api_count), "[red]Update the shared secrets on each client and in SonicOS.[/red]")
            else:
                table.add_row("SSO 3rd Party API Clients", "Finds SSO API Client entries", "Low",
                              "[dim]No API clients found[/dim]", "", "[dim]No action required[/dim]")

        # RADIUS Accounting Servers - /api/sonicos/user/radius/accounting/servers
        if should_run_check('radius_accounting_servers', args.severity):
            acct_count = get_count(results.get('acct_servers', {}).get('user', {}).get('radius', {}).get('accounting', {}).get('server', []))
            if acct_count > 0:
                table.add_row("RADIUS Accounting Servers", "Finds configured RA servers", "Low",
                              "[green]RA Servers Found[/green]", str(acct_count), "[red]Update the shared secrets on each server and in SonicOS.[/red]")
            else:
                table.add_row("RADIUS Accounting Servers", "Finds configured RA servers", "Low",
                              "[dim]No RA servers found[/dim]", "", "[dim]No action required[/dim]")

        # TACACS Accounting Servers - /api/sonicos/user/tacacs/accounting/servers
        if should_run_check('tacacs_accounting_servers', args.severity):
            tacacs_acct_count = get_count(results.get('tacacs_accounting_servers', {}).get('user', {}).get('tacacs', {}).get('accounting', {}).get('server', []))
            if tacacs_acct_count > 0:
                table.add_row("TACACS Accounting Servers", "Finds configured TACACS Acct servers", "Low",
                              "[green]Servers Found[/green]", str(tacacs_acct_count), "[red]Update the shared secrets on each server and in SonicOS.[/red]")
            else:
                table.add_row("TACACS Accounting Servers", "Finds configured TACACS Acct servers", "Low",
                              "[dim]No servers found[/dim]", "", "[dim]No action required[/dim]")

        # AppFlow SFR Mailing - /api/sonicos/appflow/sfr-mailing/base
        if should_run_check('sfr_reporting', args.severity):
            sfr_smtp_configured = results.get('sfr_data', {}).get('smtp_configured', False)
            sfr_pop_configured = results.get('sfr_data', {}).get('pop_configured', False)
            if sfr_smtp_configured or sfr_pop_configured:
                table.add_row("AppFlow SFR Mailing", f"Checks for SMTP/POP configuration", "Low",
                              "[green]Configured[/green]", "", "[red]Update the email server credentials in SonicOS.[/red]")
            else:
                table.add_row("AppFlow SFR Mailing", "Checks for SMTP/POP configuration", "Low",
                              "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Custom NTP Servers - /api/sonicos/time/ntp-servers
        if should_run_check('ntp_servers', args.severity):
            ntp_count = get_count(results.get('ntp_data', []))
            if ntp_count > 0:
                table.add_row("Custom NTP Servers", "Finds NTP entries with auth", "Low",
                              "[green]Entries Found[/green]", str(ntp_count), "[red]Update the credentials on each NTP server and in SonicOS.[/red]")
            else:
                table.add_row("Custom NTP Servers", "Finds NTP entries with auth", "Low",
                              "[dim]None found[/dim]", "", "[dim]No action required[/dim]")

        # Security Services Signature Proxy - /api/sonicos/security-services/base
        if should_run_check('security_services_proxy', args.severity):
            sig_proxy_auth = results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('enable', False)
            sig_proxy_username = results.get('security_services', {}).get('proxy_server', {}).get('authentication', {}).get('user_name', '')
            if sig_proxy_auth or sig_proxy_username:
                table.add_row("Security Services Proxy", "Checks for proxy for signature downloads", "Low",
                              "[green]Configured[/green]", "", "[red]Update the credentials on the proxy server and in SonicOS.[/red]")
            else:
                table.add_row("Security Services Proxy", "Checks for proxy for signature downloads", "Low",
                              "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # GMS IPSec Management Tunnel - /api/sonicos/administration/global
        if should_run_check('gms_ipsec_tunnel', args.severity):
            gms_conf = results.get('gms', {}).get('ipsec_tunnel', False)
            if gms_conf:
                table.add_row("GMS IPSec Management Tunnel", "Checks for GMS IPSec Management Tunnel", "Low",
                                "[green]Configured[/green]", "", "[red]Update the encryption/authentication keys.")

            else:
                table.add_row("GMS IPSec Management Tunnel", "Checks for GMS IPSec Management Tunnel", "Low",
                                "[dim]Not configured[/dim]", "", "[dim]No action required[/dim]")

        # Advanced Routing - /api/sonicos/dynamic-file/getAdvancedRoutingData.json
        if should_run_check('advanced_routing', args.severity):
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

        if args.severity != 'all':
            console.print(f"[yellow]Severity Filter: {args.severity.upper()} - Skipped {len(results.get('skipped_checks', []))} checks due to the set severity filter.[/yellow]")
            console.print("[yellow]Force Password Change and Reset TOTP Binding actions are always shown regardless of severity filter.[/yellow]")

        console.print("\n")

        return table
    except Exception as err:
        print(f"Error generating summary table: {err}")
        return None
