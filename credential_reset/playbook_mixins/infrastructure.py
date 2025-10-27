from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request
from sonicos.api import (
    get_request,
    post_request_direct_cli,
)

class InfrastructureMixin:
    # GMS IPSec Management Tunnel
    def check_gms_ipsec_tunnel(self):
        if should_run_check('gms_ipsec_tunnel', self.a.severity):
            try:
                gms_config = get_request(self.api_base, self.api_session, '/api/sonicos/administration/global', silent=self.silent)
                gms_config = gms_config.get('administration', {}).get('gms_management', {})
                if gms_config:
                    ipsec_management = gms_config.get('ipsec_tunnel', False)
                    if ipsec_management:
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: GMS Management:")
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: - GMS IPSec Management Tunnel is configured. Please ensure the encryption/authentication keys are updated.")

                    gms_config = {'gms': gms_config}
                    update_routine_results(self.routine_results, self.firewall, 'gms_ipsec_management_tunnel', gms_config)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No GMS IPsec Management Tunnel configuration found.")
                        # print(type(gms_config), "->", gms_config)
                        # print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving GMS IPsec Management Tunnel information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping GMS IPsec Management Tunnel check (severity: {get_check_severity('gms_ipsec_tunnel')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['gms_ipsec_tunnel'])

    # Advanced Routing Protocols (RIP, OSPFv2, BGP)
    def list_advanced_routing_protocols(self):
        if should_run_check('advanced_routing', self.a.severity):
            if self.firewall_info['firewall_generation'] == 6:
                # The direct/cli endpoint won't work because SonicOS responds with a blank routing dictionary.
                bgp_adv_data = post_request_direct_cli(self.api_base, self.api_session, 'show routing bgp', silent=self.silent)
                bgp_adv_data = bgp_adv_data.get('routing', {}).get('bgp', False)

                # Uses the alternate session instead.
                routing_adv_data = self.alt_session.get_advanced_routing_settings()
            else:
                routing_adv_data = get_request(self.api_base, self.api_session,
                                               '/api/sonicos/dynamic-file/getAdvancedRoutingData.json', silent=self.silent)
                bgp_adv_data = False

            if routing_adv_data:
                try:
                    adv_routing_enabled = routing_adv_data.get('data', {}).get('ipv4', {}).get('advancedRoutingEnabled',
                                                                                               False)
                    bgp_enabled = routing_adv_data.get('data', {}).get('ipv4', {}).get('isBGPEnabled',
                                                                                       False) or bgp_adv_data
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
                            routing_data_entry['rip_enabled'] = False
                        elif isinstance(intf_rip, bool) and intf_rip:
                            intf_rip = True
                            routing_data_entry['rip_enabled'] = True
                        elif isinstance(intf_rip, bool) and not intf_rip:
                            intf_rip = False
                            routing_data_entry['rip_enabled'] = False
                        else:
                            intf_rip = True
                            routing_data_entry['rip_enabled'] = True

                        if intf_ospfv2 == 'disabled':
                            intf_ospfv2 = False
                            routing_data_entry['ospfv2_enabled'] = False
                        elif isinstance(intf_ospfv2, bool) and intf_ospfv2:
                            intf_ospfv2 = True
                            routing_data_entry['ospfv2_enabled'] = True
                        elif isinstance(intf_ospfv2, bool) and not intf_ospfv2:
                            intf_ospfv2 = False
                            routing_data_entry['ospfv2_enabled'] = False
                        else:
                            intf_ospfv2 = True
                            routing_data_entry['ospfv2_enabled'] = True

                        if intf_ospfv2_authentication == 'disabled':
                            intf_ospfv2_authentication = False
                            routing_data_entry['ospfv2_authentication'] = False
                        elif isinstance(intf_ospfv2_authentication, bool) and intf_ospfv2_authentication:
                            intf_ospfv2_authentication = True
                            routing_data_entry['ospfv2_authentication'] = True
                        elif isinstance(intf_ospfv2_authentication, bool) and not intf_ospfv2_authentication:
                            intf_ospfv2_authentication = False
                            routing_data_entry['ospfv2_authentication'] = False
                        else:
                            intf_ospfv2_authentication = True
                            routing_data_entry['ospfv2_authentication'] = True

                        if intf_rip or intf_rip_password != '':
                            routing_data_entry['flag_rip'] = True
                            if not self.silent:
                                print(
                                    f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Routing - RIP is enabled or password is set on interface {intf_name}. Please ensure any RIP passwords are updated.")
                        if intf_ospfv2 or intf_ospfv2_authentication or intf_ospfv2_password != '':
                            routing_data_entry['flag_ospfv2'] = True
                            if not self.silent:
                                print(
                                    f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Routing - OSPFv2 is enabled or password is set on interface {intf_name}. Please ensure any OSPFv2 passwords are updated.")
                        if bgp_enabled:
                            routing_data_entry['flag_bgp'] = True
                            if not self.silent:
                                print(
                                    f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Routing - BGP is enabled on interface {intf_name}. Please ensure any BGP passwords are updated.")
                        routing_data.append(routing_data_entry)

                    routing_adv_data = {'advanced_routing_protocols': routing_adv_data, 'routing_data': routing_data}
                    update_routine_results(self.routine_results, self.firewall, 'advanced_routing_protocols', routing_adv_data)
                except (KeyError, TypeError) as e:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Advanced Routing Protocols configuration.")
                        print(type(routing_adv_data), "->", routing_adv_data)
                        print()
            else:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Advanced Routing Protocols information found")
                    print(type(routing_adv_data), "->", routing_adv_data)
                    print()
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Advanced Routing Protocols check (severity: {get_check_severity('advanced_routing')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['advanced_routing'])

    # Extended Switches
    def check_extended_switches(self):
        if should_run_check('extended_switches', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    ext_switches = get_request(self.api_base, self.api_session, '/api/sonicos/switch-controller/switch',
                                               silent=self.silent)
                else:
                    ext_switches = get_request(self.api_base, self.api_session, '/api/sonicos/switch-controller/switch-info',
                                               silent=self.silent)

                if ext_switches:
                    ext_switch_count = 0
                    try:
                        if self.firewall_info['firewall_generation'] == 6:
                            ext_switch_key = ext_switches.get('switch_controller', {}).get('switch', {})
                        else:
                            ext_switch_key = ext_switches.get('switch_controller', {}).get('switch_info', {})
                        if isinstance(ext_switch_key, list):
                            ext_switch_count = len(ext_switch_key)
                        elif isinstance(ext_switch_key, dict) and ext_switch_count == {}:
                            ext_switch_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining extended switch count.")
                            print(type(ext_switches), "->", ext_switches)
                            print()

                    if ext_switch_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {ext_switch_count} extended switches configured.")
                            print("Extended Switches:")
                        if self.firewall_info['firewall_generation'] == 6:
                            for switch in ext_switches.get('switch_controller', {}).get('switch', []):
                                switch_id = switch.get('id', None)
                                switch_name = switch.get('switch_name', '')
                                switch_serial = switch.get('serial_number', '')
                                if switch_id:
                                    if not self.silent:
                                        print(f"  - {switch_name} ({switch_serial})")
                        else:
                            for switch in ext_switches.get('switch_controller', {}).get('switch_info', []):
                                switch_id = switch.get('id', None)
                                switch_name = switch.get('name', '')
                                switch_serial = switch.get('serial', '')
                                if switch_id:
                                    if not self.silent:
                                        print(f"  - {switch_name} ({switch_serial})")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No extended switches found.")

                    update_routine_results(self.routine_results, self.firewall, 'extended_switches', ext_switches)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No extended switches found")
                        print(type(ext_switches), "->", ext_switches)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switches: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Extended Switches check (severity: {get_check_severity('extended_switches')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['extended_switches'])

    # Extended Switch Users
    def check_extended_switch_users(self):
        if should_run_check('extended_switch_users', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    switch_users = get_request(self.api_base, self.api_session, '/api/sonicos/switch-controller/user',
                                               silent=self.silent)
                else:
                    switch_users = get_request(self.api_base, self.api_session, '/api/sonicos/switch-controller/user',
                                               silent=self.silent)

                if switch_users:
                    switch_user_count = 0
                    try:
                        switch_user_key = switch_users.get('switch_controller', {}).get('user', {})
                        if isinstance(switch_user_key, list):
                            switch_user_count = len(switch_user_key)
                        elif isinstance(switch_user_key, dict) and switch_user_key == {}:
                            switch_user_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining extended switch user count.")
                            print(type(switch_users), "->", switch_users)
                            print()

                    if switch_user_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {switch_user_count} extended switch users configured.")
                            print("Extended Switch Users:")
                        for user in switch_users.get('switch_controller', {}).get('user', []):
                            user_name = user.get('user_name', '')
                            user_switch = user.get('switch', '')
                            user_priv = user.get('privilege_type', '')
                            if not self.silent:
                                print(f"  - {user_name} on switch {user_switch}, Privilege: {user_priv}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No extended switch users found.")

                    update_routine_results(self.routine_results, self.firewall, 'extended_switch_users', switch_users)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No extended switch users found")
                        print(type(switch_users), "->", switch_users)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switch users: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Extended Switch Users check (severity: {get_check_severity('extended_switch_users')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['extended_switch_users'])

    # Extended Switch RADIUS servers
    def check_extended_switch_radius(self):
        if should_run_check('extended_switch_radius', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    switch_radius = get_request(self.api_base, self.api_session, '/api/sonicos/switch-controller/radius',
                                                silent=self.silent)
                else:
                    switch_radius = get_request(self.api_base, self.api_session, '/api/sonicos/switch-controller/radius',
                                                silent=self.silent)

                if switch_radius:
                    switch_radius_count = 0
                    try:
                        switch_radius_key = switch_radius.get('switch_controller', {}).get('radius', {})
                        if isinstance(switch_radius_key, list):
                            switch_radius_count = len(switch_radius_key)
                        elif isinstance(switch_radius_key, dict) and switch_radius_key == {}:
                            switch_radius_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining extended switch RADIUS server count.")
                            print(type(switch_radius), "->", switch_radius)
                            print()

                    if switch_radius_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {switch_radius_count} extended switch RADIUS servers configured.")
                            print("Extended Switch RADIUS Servers:")
                        for server in switch_radius.get('switch_controller', {}).get('radius', []):
                            server_ip = server.get('server_ip', '')
                            server_switch = server.get('switch', '')
                            if not self.silent:
                                print(f"  - {server_ip} a {server_switch}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No extended switch RADIUS servers found.")

                    update_routine_results(self.routine_results, self.firewall, 'extended_switch_radius_servers', switch_radius)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No extended switch RADIUS servers found")
                        print(type(switch_radius), "->", switch_radius)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving extended switch RADIUS servers: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Extended Switch RADIUS Servers check (severity: {get_check_severity('extended_switch_radius')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['extended_switch_radius'])

