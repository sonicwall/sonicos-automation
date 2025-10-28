from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request


class NetworkingMixin():
    """Mixin for networking-related playbook functionality."""

    # List WAN interfaces (check for L2TP/PPTP/PPPoE/WWAN)
    def check_wan_interfaces(self):
        if should_run_check('wan_interfaces', self.a.severity):
            try:
                interfaces = get_request(self.api_base, self.api_session, '/api/sonicos/interfaces/ipv4', silent=self.silent)
                if interfaces:
                    wan_interfaces = []
                    wan_list = []
                    for intf in interfaces.get('interfaces', []):
                        if intf.get('ipv4', {}).get('ip_assignment', {}).get('zone', '') == 'WAN':
                            wan_interfaces.append(intf)

                    if len(wan_interfaces) > 0:
                        # if not silent:
                        #     print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Found {len(wan_interfaces)} WAN interface(s) configured.")
                        for intf in wan_interfaces:
                            intf_name = intf.get('ipv4', {}).get('name', '')
                            intf_mode = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', None)
                            pppoe = False
                            pptp = False
                            l2tp = False
                            dhcp = False
                            static = False
                            if intf_mode:
                                pppoe = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('pppoe',
                                                                                                          False)
                                pptp = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('pptp', False)
                                l2tp = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('l2tp', False)
                                dhcp = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('dhcp', False)
                                static = intf.get('ipv4', {}).get('ip_assignment', {}).get('mode', {}).get('static',
                                                                                                           False)
                            intf_type = 'PPPoE' if pppoe else 'PPTP' if pptp else 'L2TP' if l2tp else 'DHCP' if dhcp else 'Static' if static else intf_mode

                            if intf_type != 'Static' and intf_type != 'DHCP':
                                wan_list.append(intf_name)
                                # if not silent:
                                #     print(f"  - {intf_name} ({intf_type})")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No WAN interfaces found.")

                    if len(wan_list) > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {len(wan_interfaces)} PPPoE/PPTP/L2TP WAN interface(s) configured.")
                            print(f"WAN Interfaces using PPPoE/PPTP/L2TP: {', '.join(wan_list)}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No PPPoE/PPTP/L2TP WAN interfaces found.")

                    wan_interfaces = {"interesting_wan_list": wan_list, "wan_interfaces": wan_interfaces}
                    update_routine_results(self.routine_results, self.firewall, 'wan_interfaces', wan_interfaces)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No interfaces found")
                        print(type(interfaces), "->", interfaces)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving interfaces: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping WAN interface check (severity: {get_check_severity('wan_interfaces')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['wan_interfaces'])

    # Cellular WWAN
    def check_cellular_wwan(self):
        if should_run_check('cellular_wwan', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    cellular = self.alt_session.get_cellular_wwan_settings()
                else:
                    cellular = get_request(self.api_base, self.api_session, '/api/sonicos/reporting/wwan', silent=self.silent)

                if isinstance(cellular, list) and len(cellular) > 0:
                    wwan_attached = False
                    try:
                        for wwan in cellular:
                            wwan_attached = wwan.get('modem_attached', 0)
                            wwan_name = wwan.get('vendor_name', None)

                            if wwan_attached != 0 or wwan_name is not None:
                                wwan_attached = True
                                if not self.silent:
                                    print(
                                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: WWAN modem attached: {wwan_attached}/'{wwan_name}'. Please update the account's password, then update it in SonicOS.")

                        cellular = {'cellular_wwan': cellular, 'cellular_attached': wwan_attached}
                        update_routine_results(self.routine_results, self.firewall, 'cellular_wwan', cellular)
                    except (KeyError, TypeError) as e:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving WWAN modem configuration.")
                            print(type(cellular), "->", cellular)
                            print()
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No WWAN modem information found")
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving WWAN modem information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Cellular WWAN check (severity: {get_check_severity('cellular_wwan')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['cellular_wwan'])

    # List dynamic DNS services
    def list_dynamic_dns(self):
        if should_run_check('ddns_services', self.a.severity):
            try:
                ddns_services_v4 = get_request(self.api_base, self.api_session, '/api/sonicos/dynamic-dns/profiles/ipv4',
                                               silent=self.silent)
                # print(ddns_services_v4)
                ddns_count = 0
                if ddns_services_v4:
                    try:
                        ddns_key = ddns_services_v4.get('dynamic_dnss', None) or ddns_services_v4.get('dynamic_dns',
                                                                                                      None)
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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining IPv4 dynamic DNS service count.")
                            print(type(ddns_services_v4), "->", ddns_services_v4)
                            print()

                    if ddns_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {ddns_count} IPv4 dynamic DNS services configured.")
                            print("IPv4 Dynamic DNS Services:")
                        for service in ddns_services_v4:
                            service_name = service.get('profile', {}).get('ipv4', {}).get('profile_name', '')
                            service_provider = service.get('profile', {}).get('ipv4', {}).get('provider', '')
                            service_status = service.get('profile', {}).get('ipv4', {}).get('enable', False)
                            service_domain = service.get('profile', {}).get('ipv4', {}).get('domain', '')
                            if not self.silent:
                                print(
                                    f"  - Profile Name: {service_name}, Domain: {service_domain}, Provider: {service_provider}: {'enabled' if service_status else 'disabled'}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No IPv4 dynamic DNS services found.")

                    update_routine_results(self.routine_results, self.firewall, 'ddns_services_v4', ddns_services_v4)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No IPv4 dynamic DNS services found")
                        # print(type(ddns_services_v4), "->", ddns_services_v4)
                        # print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving IPv4 dynamic DNS services: {e}")

            try:
                ddns_services_v6 = get_request(self.api_base, self.api_session, '/api/sonicos/dynamic-dns/profiles/ipv6',
                                               silent=self.silent)
                # print(ddns_services_v6)
                ddns_count = 0
                if ddns_services_v6:
                    try:
                        ddns_key = ddns_services_v6.get('dynamic_dnss', None) or ddns_services_v6.get('dynamic_dns',
                                                                                                      None)
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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining IPv6 dynamic DNS service count.")
                            print(type(ddns_services_v6), "->", ddns_services_v6)
                            print()

                    if ddns_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {ddns_count} IPv6 dynamic DNS services configured.")
                            print("IPv6 Dynamic DNS Services:")
                        for service in ddns_services_v6:
                            service_name = service.get('profile', {}).get('ipv6', {}).get('profile_name', '')
                            service_provider = service.get('profile', {}).get('ipv6', {}).get('provider', '')
                            service_status = service.get('profile', {}).get('ipv6', {}).get('enable', False)
                            service_domain = service.get('profile', {}).get('ipv6', {}).get('domain', '')
                            if not self.silent:
                                print(
                                    f"  - Profile Name: {service_name}, Domain: {service_domain}, Provider: {service_provider}: {'enabled' if service_status else 'disabled'}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No IPv6 dynamic DNS services found.")

                    update_routine_results(self.routine_results, self.firewall, 'ddns_services_v6', ddns_services_v6)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No IPv6 dynamic DNS services found")
                        # print(type(ddns_services_v6), "->", ddns_services_v6)
                        # print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving IPv6 dynamic DNS services: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping dynamic DNS service check (severity: {get_check_severity('ddns_services')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['ddns_services'])

    # Check Clearpass/NAC
    def check_clearpass_nac(self):
        if should_run_check('clearpass_nac', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    clearpass_base = None
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is not available on Gen6 firewalls.")
                else:
                    clearpass_base = get_request(self.api_base, self.api_session,
                                                 '/api/sonicos/network-access-control/clearpass/base', silent=self.silent)

                if clearpass_base:
                    clearpass_enabled = clearpass_base.get('network_access_control', {}).get('clearpass', {}).get(
                        'enable', False)
                    if clearpass_enabled:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is enabled. Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is not enabled.")
                    clearpass_base['clearpass_enabled'] = clearpass_enabled
                    update_routine_results(self.routine_results, self.firewall, 'clearpass_base', clearpass_base)

                if self.firewall_info['firewall_generation'] == 6:
                    # print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is not available on GEN6 firewalls.")
                    clearpass_servers = None
                else:
                    clearpass_servers = get_request(self.api_base, self.api_session,
                                                    '/api/sonicos/network-access-control/clearpass/servers',
                                                    silent=self.silent)

                cp_servers = []
                if clearpass_servers:
                    if not self.silent:
                        print("Clearpass/NAC Servers:")
                    for server in clearpass_servers.get('network_access_control', {}).get('clearpass', {}).get('server',
                                                                                                               []):
                        server_host = server.get('name', '')
                        server_port = server.get('port', '')
                        cp_servers.append(server_host)
                        if not self.silent:
                            print(f"  - {server_host}, port {server_port}")
                    clearpass_servers['clearpass_servers'] = cp_servers
                    update_routine_results(self.routine_results, self.firewall, 'clearpass_servers', clearpass_servers)
                elif not clearpass_servers:
                    if self.firewall_info['firewall_generation'] == 6:
                        pass
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Clearpass/NAC is enabled but no servers found.")
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Clearpass/NAC information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Clearpass/NAC check (severity: {get_check_severity('clearpass_nac')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['clearpass_nac'])

    # Dynamic External Address Objects
    def check_deao(self):
        if should_run_check('dynamic_address_objects', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    dynamic_address_objects = self.alt_session.get_dynamic_external_address_objects()
                else:
                    dynamic_address_objects = get_request(self.api_base, self.api_session,
                                                          '/api/sonicos/dynamic-external-objects', silent=self.silent)

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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining dynamic address object count.")
                            print(type(dynamic_address_objects), "->", dynamic_address_objects)
                            print()

                    if dynamic_object_count > 0:
                        dynamic_address_objects['dynamic_ao_count'] = dynamic_object_count
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {dynamic_object_count} dynamic address objects configured.")
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
                                if not self.silent:
                                    print(f"  - {obj_name}: Protocol: {obj_protocol}, URL: {obj_url}")
                            elif obj_protocol == 'ftp':
                                if not self.silent:
                                    print(
                                        f"  - {obj_name}: Protocol: {obj_protocol}, Server: {obj_server}, Username: {obj_username}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No dynamic address objects found.")

                    dynamic_address_objects['dynamic_ao_data'] = deao_data
                    update_routine_results(self.routine_results, self.firewall, 'dynamic_address_objects',
                                           dynamic_address_objects)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No dynamic address objects found")
                        print(type(dynamic_address_objects), "->", dynamic_address_objects)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving dynamic address objects: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Dynamic Address Objects check (severity: {get_check_severity('dynamic_address_objects')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['dynamic_address_objects'])

    # Dynamic Botnet List Server
    def check_dyn_botnet_list_server(self):
        if should_run_check('dynamic_botnet_list_server', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    dynamic_botnet_list = get_request(self.api_base, self.api_session, '/api/sonicos/botnet/global',
                                                      silent=self.silent)
                else:
                    dynamic_botnet_list = get_request(self.api_base, self.api_session, '/api/sonicos/botnet/base', silent=self.silent)

                # print(dynamic_botnet_list)
                dynamic_botnet_data = {}
                if dynamic_botnet_list:
                    botnet_dynlist_enabled = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('enable',
                                                                                                               False)
                    botnet_dynlist_protocol = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get(
                        'protocol', None)
                    botnet_dynlist_ftp_server = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get('ftp',
                                                                                                                  {}).get(
                        'server_ip_address', None)
                    botnet_dynlist_ftp_username = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get(
                        'ftp', {}).get('login', None)
                    botnet_dynlist_ftp_password = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get(
                        'ftp', {}).get('password', None)
                    botnet_dynlist_https_username = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get(
                        'https', {}).get('login', None)
                    botnet_dynlist_https_password = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get(
                        'https', {}).get('password', None)
                    botnet_dynlist_https_url = dynamic_botnet_list.get('botnet', {}).get('dynamic_list', {}).get(
                        'https', {}).get('url_name', None)
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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: A Dynamic Botnet List Server is configured. Protocol: {botnet_dynlist_protocol}, {botnet_dynlist_ftp_username}@{botnet_dynlist_ftp_server}. Please update the password on the server, then update it in SonicOS.")
                    elif botnet_dynlist_protocol == 'https':
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: A Dynamic Botnet List Server is configured. Protocol: {botnet_dynlist_protocol}, URL: {botnet_dynlist_https_url}, Login: {botnet_dynlist_https_username}. Please update the password on the server, then update it in SonicOS.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Dynamic Botnet List Server is not configured.")

                    dynamic_botnet_list = {'botnet': dynamic_botnet_list, 'botnet_data': dynamic_botnet_data}
                    update_routine_results(self.routine_results, self.firewall, 'dynamic_botnet_list_server', dynamic_botnet_list)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No dynamic botnet list information found")
                        print(type(dynamic_botnet_list), "->", dynamic_botnet_list)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving dynamic botnet list information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Dynamic Botnet List Server check (severity: {get_check_severity('dynamic_botnet_list_server')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['dynamic_botnet_list_server'])

    # Custom NTP Servers
    def list_custom_ntp_servers(self):
        if should_run_check('ntp_servers', self.a.severity):
            try:
                ntp_servers = None
                if self.firewall_info['firewall_generation'] == 6:
                    ntp_servers = get_request(self.api_base, self.api_session, '/api/sonicos/time', silent=self.silent)
                else:
                    ntp_servers = get_request(self.api_base, self.api_session, '/api/sonicos/time/ntp-servers', silent=self.silent)

                if ntp_servers:
                    ntp_server_count = 0
                    try:
                        ntp_server_key = ntp_servers.get('time', {}).get('ntp_server', {})
                        if isinstance(ntp_server_key, list):
                            ntp_server_count = len([x for x in ntp_server_key if x.get('no_auth', False) is False])
                        elif isinstance(ntp_server_key, dict) and ntp_server_key == {}:
                            ntp_server_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining NTP server count.")
                            print(type(ntp_servers), "->", ntp_servers)
                            print()

                    ntps = []
                    if ntp_server_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {ntp_server_count} NTP Server(s) with authentication configured.")
                            print("NTP Servers with authentication:")
                        for server in ntp_servers.get('time', {}).get('ntp_server', {}):
                            server_host = server.get('name', '')
                            server_auth = server.get('no_auth', False)
                            if server_host and server_auth is False:
                                ntps.append({'host': server_host, 'no_auth': server_auth})
                                if not self.silent:
                                    print(
                                        f"  - {server_host} ({'auth disabled' if server_auth else 'auth enabled'}): Please update the password at the server, then update it in SonicOS.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No NTP servers found.")

                    ntp_servers = {'custom_ntp_servers': ntp_servers, 'ntp_data': ntps}
                    update_routine_results(self.routine_results, self.firewall, 'ntp_servers', ntp_servers)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No NTP servers found")
                        print(type(ntp_servers), "->", ntp_servers)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving NTP servers: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping NTP Servers check (severity: {get_check_severity('ntp_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['ntp_servers'])

    # Security Services Signature Proxy
    def check_sec_services_proxy(self):
        if should_run_check('security_services_proxy', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    security_services = get_request(self.api_base, self.api_session, '/api/sonicos/security-services',
                                                    silent=self.silent)
                else:
                    security_services = get_request(self.api_base, self.api_session, '/api/sonicos/security-services/base',
                                                    silent=self.silent)

                if security_services:
                    sig_proxy_enabled = security_services.get('security_services', {}).get('proxy_server', {}).get(
                        'enable', False)
                    sig_proxy_auth = security_services.get('security_services', {}).get('proxy_server', {}).get(
                        'authentication', {}).get('enable', False)
                    sig_proxy_host = security_services.get('security_services', {}).get('proxy_server', {}).get('host',
                                                                                                                '')
                    sig_proxy_username = security_services.get('security_services', {}).get('proxy_server', {}).get(
                        'authentication', {}).get('user_name', '')
                    sig_proxy_password = security_services.get('security_services', {}).get('proxy_server', {}).get(
                        'authentication', {}).get('password', None)

                    if sig_proxy_auth or sig_proxy_username:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Security Services Signature Proxy authentication is configured with user '{sig_proxy_username}', host '{sig_proxy_host}'. Please update the account's password, then update it in SonicOS.")

                    update_routine_results(self.routine_results, self.firewall, 'security_services_signature_proxy',
                                           security_services)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Security Services Signature Proxy information found")
                        print(type(security_services), "->", security_services)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Security Services Signature Proxy information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Security Services Signature Proxy check (severity: {get_check_severity('security_services_proxy')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['security_services_proxy'])
