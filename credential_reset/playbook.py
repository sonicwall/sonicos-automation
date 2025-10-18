from common.utils import generate_timestamp
from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
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


# Playbook Class
class Playbook:
    def __init__(self,
                 target,
                 target_numbers=None,
                 silent=False,
                 api_base=None,
                 alt_session=None,
                 api_session=None,
                 args=None,
                 routine_results=None,
                 firewall_info=None
                 ):
        self.target = target
        self.target_numbers = target_numbers
        self.silent = silent
        self.api_base = api_base
        self.alt_session = alt_session
        self.api_session = api_session
        self.a = args
        self.firewall = target.firewall
        self.routine_results = routine_results
        self.firewall_info = firewall_info

    # Setter/Getter for api_session.
    def set_api_session(self, api_session):
        self.api_session = api_session
    def get_api_session(self):
        return self.api_session

    # Setter/Getter for alt_session.
    def set_alt_session(self, alt_session):
        self.alt_session = alt_session
    def get_alt_session(self):
        return self.alt_session

    # Return latest routine results
    def get_routine_results(self):
        return self.routine_results

    # Replace routine results
    def set_routine_results(self, routine_results):
        self.routine_results = routine_results

    # List LDAP servers
    def list_ldap_servers(self):
        if should_run_check('ldap_servers', self.a.severity):
            try:
                ldap_servers = get_request(self.api_base, self.api_session, '/api/sonicos/user/ldap/servers', silent=self.silent)
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
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining LDAP server count.")
                        print(type(ldap_servers), "->", ldap_servers)
                        print("-----------------------")

                    if ldap_count > 0:
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {ldap_count} LDAP servers configured.")
                        ldap_servers = ldap_servers['user']['ldap']['server']
                        if not self.silent:
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
                            if not self.silent:
                                print(f"  - {server_host}, {server_role}: Status: {'enabled' if server_status else 'disabled'}")
                    else:
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No LDAP servers found.")

                    update_routine_results(self.routine_results, self.firewall, 'ldap_servers', ldap_servers)

                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No LDAP servers found")
                        print(type(ldap_servers), "->", ldap_servers)
                        print("-----------------------")
            except Exception as e:
                if not self.silent:
                    print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving LDAP servers: {e}")
        else:
            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping LDAP server check  (severity: {get_check_severity('ldap_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['ldap_servers'])

    # List RADIUS servers
    def list_radius_servers(self):
        if should_run_check('radius_servers', self.a.severity):
            try:
                radius_servers = get_request(self.api_base, self.api_session, '/api/sonicos/user/radius/servers', silent=self.silent)
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
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining RADIUS server count.")
                        if not self.silent:
                            print(type(radius_servers), "->", radius_servers)
                            print("-----------------------")

                    if radius_count > 0:
                        radius_servers = radius_servers['user']['radius']['server']
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {radius_count} RADIUS servers configured.")
                            print("RADIUS Servers:")
                        for server in radius_servers:
                            server_host = server.get('host', '')
                            server_port = server.get('port', {}).get('port_num', '')
                            server_status = server.get('enable', '')
                            if not self.silent:
                                print(f"  - {server_host}, port {server_port}: Status: {'enabled' if server_status else 'disabled'}")
                    else:
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No RADIUS servers found.")

                    update_routine_results(self.routine_results, self.firewall, 'radius_servers', radius_servers)
                else:
                    print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No RADIUS servers found")
                    print(type(radius_servers), "->", radius_servers)
                    print("-----------------------")
            except Exception as e:
                print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving RADIUS servers: {e}")
        else:
            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping RADIUS server check (severity: {get_check_severity('radius_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['radius_servers'])

    # List TACACS+ servers
    def list_tacacs_servers(self):
        # List TACACS servers
        if should_run_check('tacacs_servers', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    tacacs_servers = self.alt_session.get_tacacs_servers()
                else:
                    tacacs_servers = get_request(self.api_base, self.api_session,
                                                 '/api/sonicos/user/tacacs/servers',
                                                 silent=self.silent)

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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining TACACS server count.")
                            print(type(tacacs_servers), "->", tacacs_servers)
                            print()

                    if tacacs_count > 0:
                        tacacs_servers = tacacs_servers['user']['tacacs']['server']
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {tacacs_count} TACACS servers configured.")
                            print("TACACS Servers:")
                        for server in tacacs_servers:
                            server_host = server.get('host', '')
                            server_port = server.get('port', '')
                            server_status = server.get('enable', '')
                            if not self.silent:
                                print(
                                    f"  - {server_host}, port {server_port}: Status: {'enabled' if server_status else 'disabled'}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No TACACS servers found.")

                    update_routine_results(self.routine_results, self.firewall, 'tacacs_servers', tacacs_servers)
                else:
                    print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No TACACS servers found")
                    print(type(tacacs_servers), "->", tacacs_servers)
                    print("-----------------------")
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving TACACS servers: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping TACACS server check (severity: {get_check_severity('tacacs_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['tacacs_servers'])

    # List VPN policies
    def list_vpn_policies(self):
        if should_run_check('vpn_policies', self.a.severity):
            try:
                vpn_policies = None
                if self.firewall_info['firewall_generation'] == 6:
                    # In GEN6, we have to get VPN policies per type
                    vpn_policies = {'vpn': {'policy': []}}

                    # Site to Site
                    site_to_site = get_request(self.api_base, self.api_session, '/api/sonicos/vpn/policies/ipv4/site-to-site',
                                               silent=self.silent)
                    if site_to_site and site_to_site.get('vpn', {}).get('policy', []):
                        vpn_policies['vpn']['policy'].extend(site_to_site['vpn']['policy'])

                    site_to_site_v6 = get_request(self.api_base, self.api_session, '/api/sonicos/vpn/policies/ipv6/site-to-site',
                                                  silent=self.silent)
                    if site_to_site_v6 and site_to_site_v6.get('vpn', {}).get('policy', []):
                        vpn_policies['vpn']['policy'].extend(site_to_site_v6['vpn']['policy'])

                    # GroupVPN
                    group_vpn = get_request(self.api_base, self.api_session, '/api/sonicos/vpn/policies/ipv4/group-vpn',
                                            silent=self.silent)
                    if group_vpn and group_vpn.get('vpn', {}).get('policy', []):
                        vpn_policies['vpn']['policy'].extend(group_vpn['vpn']['policy'])

                    # Tunnel Interface
                    tunnel_interface = get_request(self.api_base, self.api_session,
                                                   '/api/sonicos/vpn/policies/ipv4/tunnel-interface', silent=self.silent)
                    if tunnel_interface and tunnel_interface.get('vpn', {}).get('policy', []):
                        vpn_policies['vpn']['policy'].extend(tunnel_interface['vpn']['policy'])

                    if vpn_policies['vpn']['policy'] == []:
                        vpn_policies = None

                    if vpn_policies is None:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No VPN policies found.")
                else:
                    vpn_policies = get_request(self.api_base, self.api_session, '/api/sonicos/vpn/policies/all', silent=self.silent)

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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining VPN policy count.")
                            print(type(vpn_policies), "->", vpn_policies)
                            print()

                    if vpn_policy_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {vpn_policy_count} VPN policies configured.")
                            print("VPN Policies:")
                        for policy in vpn_policies['vpn'].get('policy', []):
                            policy_name = policy.get('ipv4', {}).get('group_vpn', {}).get('name') or policy.get('ipv4',
                                                                                                                {}).get(
                                'site_to_site', {}).get('name') or policy.get('ipv4', {}).get('tunnel_interface',
                                                                                              {}).get('name')
                            policy_status = policy.get('ipv4', {}).get('group_vpn', {}).get('enable',
                                                                                            False) or policy.get('ipv4',
                                                                                                                 {}).get(
                                'site_to_site', {}).get('enable', False) or policy.get('ipv4', {}).get(
                                'tunnel_interface', {}).get('enable', False)
                            if not self.silent:
                                print(f"  - {policy_name}: {'enabled' if policy_status else 'disabled'}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No VPN policies found.")

                    update_routine_results(self.routine_results, self.firewall, 'vpn', vpn_policies)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No VPN policies found")
                        print(type(vpn_policies), "->", vpn_policies)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving VPN policies: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping VPN policy check (severity: {get_check_severity('vpn_policies')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['vpn_policies'])

    # Check AWS API status (log/aws)
    def check_aws_api(self):
        if should_run_check('aws_api', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    aws_api = self.alt_session.get_aws_api()
                else:
                    aws_api = get_request(self.api_base, self.api_session, '/api/sonicos/log/aws', silent=self.silent)

                if aws_api:
                    aws_enabled = aws_api.get('log', {}).get('aws', {}).get('enable', False)
                    if aws_enabled:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: AWS API is enabled. Please update the secret key.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: AWS API is not enabled.")

                    update_routine_results(self.routine_results, self.firewall, 'aws_api', aws_api)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No AWS API information found")
                        print(type(aws_api), "->", aws_api)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving AWS API information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping AWS API check (severity: {get_check_severity('aws_api')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['aws_api'])

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

    # List SNMPv3 users
    def list_snmpv3_users(self):
        if should_run_check('snmp_users', self.a.severity):
            try:
                snmpv3_users = None
                if self.firewall_info['firewall_generation'] == 6:
                    snmpv3_users = get_request(self.api_base, self.api_session, '/api/sonicos/snmp/settings', silent=self.silent)
                else:
                    snmpv3_users = get_request(self.api_base, self.api_session, '/api/sonicos/snmp/users', silent=self.silent)

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
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SNMP user count.")
                            print(type(snmpv3_users), "->", snmpv3_users)
                            print()

                    if snmpv3_user_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {snmpv3_user_count} SNMP users configured.")
                            print("SNMPv3 Users:")
                        for user in snmpv3_users['snmp'].get('user', []):
                            user_name = user.get('name', '')
                            user_level = user.get('security_level', {}).get('authentication_only', None) or user.get(
                                'security_level', {}).get('authentication_and_privacy', None) or None
                            user_level_key = list(user.get('security_level', {}).keys())
                            user_level_key = user_level_key[0] if user_level_key else None
                            if not self.silent:
                                print(f"  - {user_name}, Security Level: {user_level_key if user_level else None}")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SNMP users found.")

                    update_routine_results(self.routine_results, self.firewall, 'snmp_users', snmpv3_users)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SNMP users found")
                        print(type(snmpv3_users), "->", snmpv3_users)
                        print()
            except Exception as err:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SNMP users: {err}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SNMP user check (severity: {get_check_severity('snmp_users')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['snmp_users'])

    # Cloud Secure Edge (CSE)
    def check_cloud_secure_edge(self):
        if should_run_check('cloud_secure_edge', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is not available on GEN6 firewalls.")
                    cse_info = None
                else:
                    cse_info = get_request(self.api_base, self.api_session, '/api/sonicos/cloud-secure-edge/base', silent=self.silent)

                if cse_info:
                    cse_enabled = cse_info.get('cloud_secure_edge', {}).get('created', False)
                    if cse_enabled:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is enabled. Reset the Cloud Secure Edge connector authentication key.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Cloud Secure Edge (CSE) is not enabled.")

                    update_routine_results(self.routine_results, self.firewall, 'cse_info', cse_info)
                else:
                    if self.firewall_info['firewall_generation'] == 6:
                        pass
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No CSE information found")
                            print(type(cse_info), "->", cse_info)
                            print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving CSE information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Cloud Secure Edge (CSE) check (severity: {get_check_severity('cloud_secure_edge')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['cloud_secure_edge'])

    # Email Logging
    def check_email_logging(self):
        if should_run_check('email_logging', self.a.severity):
            try:
                email_logging = get_request(self.api_base, self.api_session, '/api/sonicos/log/automation', silent=self.silent)
                if email_logging:
                    mail_server = email_logging.get('log', {}).get('automation', {}).get('mail_server', None)
                    authentication_method = email_logging.get('log', {}).get('automation', {}).get(
                        'authentication_method', None)
                    pop3_server = email_logging.get('log', {}).get('automation', {}).get('pop3_server', None)
                    pop3_username = email_logging.get('log', {}).get('automation', {}).get('pop3_user_name', None)
                    pop3_password = email_logging.get('log', {}).get('automation', {}).get('pop3_user_name', None)
                    smtp_user = email_logging.get('log', {}).get('automation', {}).get('mail_server_advanced', {}).get(
                        'user_name', None)
                    smtp_password = email_logging.get('log', {}).get('automation', {}).get('mail_server_advanced',
                                                                                           {}).get('password', None)
                    ftp_logging = email_logging.get('log', {}).get('automation', {}).get('ftp_log', {})
                    ftp_server = ftp_logging.get('server', None)
                    ftp_username = ftp_logging.get('user_name', None)
                    ftp_password = ftp_logging.get('password', None)
                    email_logging_data = {
                        'mail_server': mail_server,
                        'authentication_method': authentication_method,
                        'pop3_server': pop3_server,
                        'pop3_username': pop3_username,
                        'pop3_password_set': bool(pop3_password),
                        'smtp_user': smtp_user,
                        'smtp_password_set': bool(smtp_password),
                        'ftp_server': ftp_server,
                        'ftp_username': ftp_username,
                        'ftp_password_set': bool(ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None)
                    }

                    if pop3_password or smtp_password or (
                            ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None):
                        if not self.silent:
                            print("Log Automation:")
                    if pop3_password:
                        email_logging_data['pop3_flag'] = True
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: POP3 password is set for {pop3_username}@{pop3_server}. Please update the account's password, then update it in SonicOS.")

                    if smtp_password:
                        email_logging_data['smtp_flag'] = True
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: SMTP password is set for {smtp_user}@{mail_server}. Please update the account's password, then update it in SonicOS.")

                    if ftp_password and ftp_server != "0.0.0.0" and ftp_server is not None:
                        email_logging_data['ftp_flag'] = True
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")

                    email_logging = {'log_automation_data': email_logging_data, 'log_automation_json': email_logging}
                    update_routine_results(self.routine_results, self.firewall, 'email_logging', email_logging)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No log automation information found")
                        print(type(email_logging), "->", email_logging)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving log automation information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping email logging check (severity: {get_check_severity('email_logging')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['email_logging'])

    # Packet Monitor FTP Logging
    def check_packet_monitor_ftp_logging(self):
        if should_run_check('packet_monitor_ftp', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    pktmon_settings = get_request(self.api_base, self.api_session, '/api/sonicos/packet-monitor/settings',
                                                  silent=self.silent)
                else:
                    pktmon_settings = get_request(self.api_base, self.api_session, '/api/sonicos/packet-monitor/base',
                                                  silent=self.silent)

                pkmon_flag = False
                if pktmon_settings:
                    pktmon_ftp = pktmon_settings.get('packet_monitor', {}).get('ftp', None)
                    if pktmon_ftp:
                        ftp_server = pktmon_ftp.get('server', None)
                        ftp_username = pktmon_ftp.get('login', None)
                        ftp_password = pktmon_ftp.get('password', None)

                        if ftp_password and ftp_server != "0.0.0.0" and ftp_server != "" and ftp_server is not None:
                            pkmon_flag = True
                            if not self.silent:
                                print(
                                    f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Packet Monitor FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Could not retrieve the Packet Monitor FTP settings.")
                    pktmon_ftp['packet_monitor_ftp_set'] = pkmon_flag
                    update_routine_results(self.routine_results, self.firewall, 'packetmonitor_ftp', pktmon_ftp)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Packet Monitor information found")
                        print(type(pktmon_settings), "->", pktmon_settings)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Packet Monitor information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Packet Monitor FTP check (severity: {get_check_severity('packet_monitor_ftp')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['packet_monitor_ftp'])

    # Settings/TSR scheduled exports
    def check_tsr_exp_scheduled_exports(self):
        if should_run_check('scheduled_exports', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    # scheduled_exports = get_request(self.api_base, self.api_session, '/api/sonicos/ftp/', silent=self.silent)
                    scheduled_exports = self.alt_session.get_scheduled_reports()
                else:
                    scheduled_exports = get_request(self.api_base, self.api_session, '/api/sonicos/ftp/base', silent=self.silent)

                scheduled_exports_flag = False
                if scheduled_exports:
                    ftp_server = scheduled_exports.get('server', None)
                    ftp_username = scheduled_exports.get('user', None)
                    ftp_password = scheduled_exports.get('password', None)

                    if ftp_password and ftp_server != "0.0.0.0" and ftp_server != "" and ftp_server is not None:
                        scheduled_exports_flag = True
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Settings/TSR scheduled export FTP password is set for {ftp_username}@{ftp_server}. Please update the account's password, then update it in SonicOS.")
                    scheduled_exports['scheduled_exports_ftp_set'] = scheduled_exports_flag
                    update_routine_results(self.routine_results, self.firewall, 'scheduled_exports', scheduled_exports)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No settings/TSR scheduled exports information found")
                        print(type(scheduled_exports), "->", scheduled_exports)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving settings/TSR scheduled exports information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping settings/TSR scheduled exports check (severity: {get_check_severity('scheduled_exports')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['scheduled_exports'])

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

    # Zone Objects: WLAN RADIUS servers
    def check_wlan_radius_servers(self):
        if should_run_check('wlan_radius_servers', self.a.severity):
            try:
                all_zone_objects = get_request(self.api_base, self.api_session, '/api/sonicos/zones', silent=self.silent)
                zone_objects = [z for z in all_zone_objects.get('zones', []) if
                                z.get('security_type', '').lower() == 'wireless']
                if zone_objects:
                    zone_data = []
                    if len(zone_objects) > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: WLAN Local RADIUS Server:")
                    try:
                        for zone in zone_objects:
                            if zone.get('security_type', '').lower() == 'wireless':
                                radius_server_enabled = zone.get('local_radius_server', {}).get('enable', False)
                                ldap_server_enabled = zone.get('local_radius_server', {}).get('ldap_server', {}).get(
                                    'enable', False)
                                ldap_server_host = zone.get('local_radius_server', {}).get('ldap_server', {}).get(
                                    'server', None)
                                zone_data_entry = {'zone': zone.get('name', ''),
                                                   'radius_server_enabled': radius_server_enabled,
                                                   'ldap_server_enabled': ldap_server_enabled,
                                                   'ldap_server_host': ldap_server_host
                                                   }
                                if radius_server_enabled:
                                    if not self.silent:
                                        print(
                                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}:  - Local RADIUS server is enabled on Zone {zone.get('name', '')}. Please update the RADIUS server client password.")
                                if ldap_server_enabled or ldap_server_host:
                                    if not self.silent:
                                        print(
                                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}:  - LDAP server is enabled on Zone {zone.get('name', '')}, Host: {ldap_server_host}. Please update the LDAP server password, then update it in SonicOS.")
                                zone_data.append(zone_data_entry)
                    except (KeyError, TypeError):
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving WLAN RADIUS Server configuration from zone objects.")
                        print(type(zone_objects), "->", zone_objects)
                        print()

                    zone_objects = {'wlan_radius_servers': zone_objects, 'wlan_zone_data': zone_data}
                    update_routine_results(self.routine_results, self.firewall, 'wlan_radius_servers', zone_objects)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No zone objects found")
                        print(type(zone_objects), "->", zone_objects)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving zone objects: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping WLAN RADIUS Servers check (severity: {get_check_severity('wlan_radius_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['wlan_radius_servers'])

    # Guest Services External Guest Authentication (Message Authentication)
    def check_ext_guest_auth(self):
        if should_run_check('guest_services_auth', self.a.severity):
            try:
                all_zone_objects = get_request(self.api_base, self.api_session, '/api/sonicos/zones',
                                               silent=self.silent)
                guest_zones = [z for z in all_zone_objects.get('zones', []) if
                               z.get('guest_services', {}).get('external_auth', {}).get('message_auth', {}).get(
                                   'enable', False)]
                if guest_zones:
                    guest_zone_data = []
                    if len(guest_zones) > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Guest Services External Guest Authentication (Message Authentication):")
                    try:
                        for zone in guest_zones:
                            guest_auth_ext_enabled = zone.get('guest_services', {}).get('external_auth', {}).get(
                                'message_auth', {}).get('enable', False)
                            guest_zone_data_entry = {'zone': zone.get('name', ''),
                                                     'guest_auth_ext_enabled': guest_auth_ext_enabled}
                            guest_zone_data.append(guest_zone_data_entry)
                            if guest_auth_ext_enabled:
                                if not self.silent:
                                    print(
                                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}:  - External Guest Authentication is enabled on Zone {zone.get('name', '')}. Please update the message authentication shared secret.")
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Guest Services External Guest Authentication configuration from zone objects.")
                            print(type(guest_zones), "->", guest_zones)
                            print()

                    guest_zones = {'guest_services_external_auth': guest_zones, 'guest_zone_data': guest_zone_data}
                    update_routine_results(self.routine_results, self.firewall, 'guest_services_external_auth', guest_zones)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No zone objects with Guest Services External Guest Authentication found")
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving zone objects for Guest Services: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Guest Services External Guest Authentication check (severity: {get_check_severity('guest_services_auth')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['guest_services_auth'])

    # SSO Agents
    def list_sso_agents(self):
        if should_run_check('sso_agents', self.a.severity):
            try:
                sso_agents = get_request(self.api_base, self.api_session, '/api/sonicos/user/sso/agents', silent=self.silent)
                if sso_agents:
                    sso_agent_count = 0
                    try:
                        sso_agent_key = sso_agents.get('user', {}).get('sso', {}).get('agent', {})
                        if isinstance(sso_agent_key, list):
                            sso_agent_count = len(sso_agent_key)
                        elif isinstance(sso_agent_key, dict) and sso_agent_key == {}:
                            sso_agent_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SSO agent count.")
                            print(type(sso_agents), "->", sso_agents)
                            print()

                    if sso_agent_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {sso_agent_count} SSO Agent(s) configured.")
                            print("SSO Agents:")
                        for agent in sso_agents.get('user', {}).get('sso', {}).get('agent', []):
                            agent_status = agent.get('enable', '')
                            agent_host = agent.get('host', '')
                            agent_port = agent.get('port', '')
                            agent_shared_secret = agent.get('shared_key', None)
                            if agent_shared_secret:
                                if not self.silent:
                                    print(
                                        f"  - {agent_host}, port {agent_port} ({'enabled' if agent_status else 'disabled'}): Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SSO agents found.")

                    sso_agents = {'sso_agents': sso_agents}
                    update_routine_results(self.routine_results, self.firewall, 'sso_agents', sso_agents)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SSO Agents found")
                        print(type(sso_agents), "->", sso_agents)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO Agents: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SSO Agents check (severity: {get_check_severity('sso_agents')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sso_agents'])

    # Terminal Services Agents (TSA)
    def list_ts_agents(self):
        if should_run_check('ts_agents', self.a.severity):
            try:
                ts_agents = get_request(self.api_base, self.api_session, '/api/sonicos/user/sso/terminal-services-agents',
                                        silent=self.silent)
                if ts_agents:
                    ts_agent_count = 0
                    try:
                        ts_agent_key = ts_agents.get('user', {}).get('sso', {}).get('terminal_services_agent', {})
                        if isinstance(ts_agent_key, list):
                            ts_agent_count = len(ts_agent_key)
                        elif isinstance(ts_agent_key, dict) and ts_agent_key == {}:
                            ts_agent_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining TS Agent count.")
                            print(type(ts_agents), "->", ts_agents)
                            print()

                    if ts_agent_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {ts_agent_count} TS Agent(s) configured.")
                            print("Terminal Services Agents:")
                        for agent in ts_agents.get('user', {}).get('sso', {}).get('terminal_services_agent', []):
                            agent_status = agent.get('enable', '')
                            agent_host = agent.get('host', '')
                            agent_port = agent.get('port', '')
                            agent_shared_secret = agent.get('shared_key', None)
                            if agent_shared_secret:
                                if not self.silent:
                                    print(
                                        f"  - {agent_host}, port {agent_port} ({'enabled' if agent_status else 'disabled'}): Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No TS agents found.")

                    ts_agents = {'ts_agents': ts_agents}
                    update_routine_results(self.routine_results, self.firewall, 'tsa_agents', ts_agents)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No TS agents found")
                        print(type(ts_agents), "->", ts_agents)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving TSA agents: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Terminal Server Agents check (severity: {get_check_severity('ts_agents')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['ts_agents'])

    # SSO RADIUS Accounting Clients
    def list_sso_radius_clients(self):
        if should_run_check('sso_radius_clients', self.a.severity):
            try:
                sso_radius_clients = get_request(self.api_base, self.api_session,
                                                 '/api/sonicos/user/sso/radius-accounting-clients', silent=self.silent)
                if sso_radius_clients:
                    sso_radius_client_count = 0
                    try:
                        sso_radius_client_key = sso_radius_clients.get('user', {}).get('sso', {}).get(
                            'radius_accounting_client', {})
                        if isinstance(sso_radius_client_key, list):
                            sso_radius_client_count = len(sso_radius_client_key)
                        elif isinstance(sso_radius_client_key, dict) and sso_radius_client_key == {}:
                            sso_radius_client_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SSO RADIUS client count.")
                            print(type(sso_radius_clients), "->", sso_radius_clients)
                            print()

                    if sso_radius_client_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {sso_radius_client_count} SSO RADIUS Client(s) configured.")
                            print("SSO RADIUS Clients:")
                        for client in sso_radius_clients.get('user', {}).get('sso', {}).get('radius_accounting_client',
                                                                                            []):
                            client_host = client.get('host', '')
                            client_shared_secret = client.get('shared_secret', None)
                            if client_shared_secret:
                                if not self.silent:
                                    print(f"  - {client_host}: Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SSO RADIUS clients found.")

                    sso_radius_clients = {'sso_radius_clients': sso_radius_clients}
                    update_routine_results(self.routine_results, self.firewall, 'sso_radius_clients', sso_radius_clients)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SSO RADIUS clients found")
                        print(type(sso_radius_clients), "->", sso_radius_clients)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO RADIUS clients: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SSO RADIUS Clients check (severity: {get_check_severity('sso_radius_clients')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sso_radius_clients'])

    # 3rd Party SSO API Clients
    def list_sso_api_clients(self):
        if should_run_check('sso_api_clients', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    sso_api_clients = self.alt_session.get_sso_api_clients()
                else:
                    sso_api_clients = get_request(self.api_base, self.api_session,
                                                  '/api/sonicos/user/sso/third-party-api/clients', silent=self.silent)

                if sso_api_clients:
                    sso_api_client_count = 0
                    try:
                        sso_api_client_key = sso_api_clients.get('user', {}).get('sso', {}).get('third_party_api',
                                                                                                {}).get('client', {})
                        if isinstance(sso_api_client_key, list):
                            sso_api_client_count = len(sso_api_client_key)
                        elif isinstance(sso_api_client_key, dict) and sso_api_client_key == {}:
                            sso_api_client_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SSO API client count.")
                            print(type(sso_api_clients), "->", sso_api_clients)
                            print()

                    if sso_api_client_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {sso_api_client_count} SSO API Client(s) configured.")
                            print("SSO API Clients:")
                        for client in sso_api_clients.get('user', {}).get('sso', {}).get('third_party_api', {}).get(
                                'client', []):
                            client_host = client.get('host', '')
                            client_shared_secret = client.get('shared_secret', None)
                            if client_host and not client_shared_secret:
                                if not self.silent:
                                    print(f"  - {client_host}: Please consider setting a shared secret.")
                            elif client_shared_secret:
                                if not self.silent:
                                    print(f"  - {client_host}: Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SSO API clients found.")

                    sso_api_clients = {'sso_api_clients': sso_api_clients}
                    update_routine_results(self.routine_results, self.firewall, 'sso_api_clients', sso_api_clients)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SSO API clients found")
                        print(type(sso_api_clients), "->", sso_api_clients)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SSO API clients: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping 3rd Party SSO API Clients check (severity: {get_check_severity('sso_api_clients')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sso_api_clients'])

    # RADIUS Accounting Servers
    def list_radius_accounting_servers(self):
        if should_run_check('radius_accounting_servers', self.a.severity):
            try:
                acct_servers = get_request(self.api_base, self.api_session, '/api/sonicos/user/radius/accounting/servers',
                                           silent=self.silent)
                if acct_servers:
                    acct_server_count = 0
                    try:
                        acct_server_key = acct_servers.get('user', {}).get('radius', {}).get('accounting', {}).get(
                            'server', {})
                        if isinstance(acct_server_key, list):
                            acct_server_count = len(acct_server_key)
                        elif isinstance(acct_server_key, dict) and acct_server_key == {}:
                            acct_server_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining RADIUS accounting server count.")
                            print(type(acct_servers), "->", acct_servers)
                            print()

                    if acct_server_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {acct_server_count} RADIUS Accounting Server(s) configured.")
                            print("RADIUS Accounting Servers:")
                        for server in acct_servers.get('user', {}).get('radius', {}).get('accounting', {}).get('server',
                                                                                                               []):
                            server_host = server.get('host', '')
                            server_port = server.get('port', 0)
                            server_status = server.get('enable', False)
                            server_shared_secret = server.get('shared_secret', None)
                            if server_shared_secret:
                                if not self.silent:
                                    print(
                                        f"  - {server_host}, port {server_port} ({'enabled' if server_status else 'disabled'}): Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No RADIUS accounting servers found.")

                    acct_servers = {'acct_servers': acct_servers}
                    update_routine_results(self.routine_results, self.firewall, 'radius_accounting_servers', acct_servers)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No RADIUS accounting servers found")
                        print(type(acct_servers), "->", acct_servers)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving RADIUS accounting servers: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping RADIUS Accounting Servers check (severity: {get_check_severity('radius_accounting_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['radius_accounting_servers'])

    # TACACS+ Accounting Servers
    def list_tacacs_accounting_servers(self):
        if should_run_check('tacacs_accounting_servers', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    tacacs_servers = self.alt_session.get_tacacs_accounting_servers()
                else:
                    tacacs_servers = get_request(self.api_base, self.api_session, '/api/sonicos/user/tacacs/accounting/servers',
                                                 silent=self.silent)

                if tacacs_servers:
                    tacacs_server_count = 0
                    try:
                        tacacs_server_key = tacacs_servers.get('user', {}).get('tacacs', {}).get('accounting', {}).get(
                            'server', {})
                        if isinstance(tacacs_server_key, list):
                            tacacs_server_count = len(tacacs_server_key)
                        elif isinstance(tacacs_server_key, dict) and tacacs_server_key == {}:
                            tacacs_server_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining TACACS+ server count.")
                            print(type(tacacs_servers), "->", tacacs_servers)
                            print()

                    if tacacs_server_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {tacacs_server_count} TACACS+ Server(s) configured.")
                            print("TACACS+ Servers:")
                        for server in tacacs_servers.get('user', {}).get('tacacs', {}).get('accounting', {}).get(
                                'server', []):
                            server_host = server.get('host', '')
                            server_port = server.get('port', '')
                            server_status = server.get('enable', '')
                            server_shared_secret = server.get('shared_secret', None)
                            if server_shared_secret:
                                if not self.silent:
                                    print(
                                        f"  - {server_host}, port {server_port} ({'enabled' if server_status else 'disabled'}): Please update the shared secret.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No TACACS+ servers found.")

                    tacacs_servers = {'tacacs_accounting_servers': tacacs_servers}
                    update_routine_results(self.routine_results, self.firewall, 'tacacs_accounting_servers', tacacs_servers)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No TACACS+ servers found")
                        print(type(tacacs_servers), "->", tacacs_servers)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving TACACS+ servers: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping TACACS+ Servers check (severity: {get_check_severity('tacacs_accounting_servers')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['tacacs_accounting_servers'])

    # AppFlow SFR Reporting
    def check_appflow_sfr_reporting(self):
        if should_run_check('sfr_reporting', self.a.severity):
            try:
                if self.firewall_info['firewall_generation'] == 6:
                    sfr = self.alt_session.get_sfr_mailing_settings()
                else:
                    sfr = get_request(self.api_base, self.api_session, '/api/sonicos/appflow/sfr-mailing/base', silent=self.silent)

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
                    sfr_data = {'smtp_configured': False, 'pop_configured': False}

                    if sfr_server != "" and sfr_server is not None and sfr_password:
                        sfr_data['smtp_configured'] = True
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: AppFlow SFR Mailing SMTP server is configured to use {sfr_username}@{sfr_server}. Please update the account's password, then update it in SonicOS.")

                    if sfr_server_pop != "" and sfr_server_pop is not None and sfr_password_pop:
                        if not self.silent:
                            sfr_data['pop_configured'] = True
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: AppFlow SFR Mailing POP server is configured to use {sfr_username_pop}@{sfr_server_pop}. Please update the account's password, then update it in SonicOS.")

                    sfr = {'sfr_reporting': sfr, "sfr_data": sfr_data}
                    update_routine_results(self.routine_results, self.firewall, 'sfr_reporting', sfr)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No AppFlow SFR reporting information found")
                        print(type(sfr), "->", sfr)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving AppFlow SFR reporting information: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping AppFlow SFR Reporting check (severity: {get_check_severity('sfr_reporting')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sfr_reporting'])

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

    # Internal Wireless Radio preshared key and/or RADIUS
    def check_internal_wlan_radio(self):
        if should_run_check('internal_wlan_radio', self.a.severity):
            try:
                radios = get_request(self.api_base, self.api_session, '/api/sonicos/wireless/radio', silent=self.silent)
                if radios:
                    # The only confirmed radio role is access_point_mesh. Changing the setting does not trigger an API change when in read only.
                    radio_role = (
                            radios.get('wireless', {}).get('radio_role', {}).get('access_point_mesh', None) or  # GEN7
                            radios.get('wireless', {}).get('radio_role', {}).get('access_point_station',
                                                                                 None) or  # GEN6/7
                            radios.get('wireless', {}).get('radio_role', {}).get('station', None) or  # May be invalid
                            radios.get('wireless', {}).get('radio_role', {}).get('wds-station', None) or  # GEN7
                            radios.get('wireless', {}).get('radio_role', {}).get('client-bridge', None) or  # GEN6
                            radios.get('wireless', {}).get('radio_role', {}).get('access_point', None)  # GEN6/7
                    )
                    radio_auth_type = radios.get('wireless', {}).get('authentication_type', {})
                    radio_radius = radios.get('wireless', {}).get('radius', {}).get('server', {}).get('server1',
                                                                                                      {}).get('ip',
                                                                                                              None)
                    radio_psk = radios.get('wireless', {}).get('wpa', {}).get('passphrase', None)

                    if radio_psk:
                        if not self.silent:
                            print(
                                f"  - The internal wireless radio is configured with a pre-shared key. Please update the pre-shared key.")
                    if radio_radius:
                        if not self.silent:
                            print(
                                f"  - RADIUS is configured on the internal wireless radio. Please ensure the RADIUS server shared secret is updated.")

                    radios = {'internal_wlan': radios}
                    update_routine_results(self.routine_results, self.firewall, 'internal_wlan_radios', radios)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Radios found")
                        print(type(radios), "->", radios)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Internal Wireless Radios: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Internal Wireless Radio check (severity: {get_check_severity('internal_wlan_radio')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['internal_wlan_radio'])

    # Internal Wireless Virtual Access Points
    def check_internal_wlan_vaps(self):
        if should_run_check('internal_wlan_vaps', self.a.severity):
            try:
                vaps = get_request(self.api_base, self.api_session, '/api/sonicos/wireless/virtual-access-point/objects',
                                   silent=self.silent)
                if vaps:
                    vap_count = 0
                    try:
                        vap_key = vaps.get('wireless', {}).get('virtual_access_point', {}).get('object', {})
                        if isinstance(vap_key, list):
                            vap_count = len(vap_key)
                        elif isinstance(vap_key, dict) and vap_key == {}:
                            vap_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining Internal Wireless VAP count.")
                            print(type(vaps), "->", vaps)
                            print()

                    vap_data = []
                    if vap_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {vap_count} Internal Wireless Virtual Access Point(s) configured.")
                            print("Internal Wireless Virtual Access Points:")
                        all_vaps = vaps.get('wireless', {}).get('virtual_access_point', {}).get('object', [])
                        for vap in all_vaps:
                            vap_name = vap.get('name', '')
                            vap_ssid = vap.get('ssid', '')
                            vap_vlan = vap.get('vlan', '')
                            vap_status = vap.get('enable', '')
                            vap_security = vap.get('authentication_type', {})
                            vap_radius = vap.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                            vap_accounting = vap.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip',
                                                                                                                None) or vap.get(
                                'radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                            vap_data_entry = {'name': vap_name, 'ssid': vap_ssid, 'vlan': vap_vlan,
                                              'status': vap_status, 'radius': vap_radius, 'accounting': vap_accounting}
                            vap_data.append(vap_data_entry)
                            if vap_name:
                                if not self.silent:
                                    print(
                                        f"  - {vap_name}, SSID: {vap_ssid}, VLAN: {vap_vlan} ({'enabled' if vap_status else 'disabled'}): Please update the pre-shared key.")
                                if vap_radius:
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS is configured on the VAP. Please ensure the RADIUS server shared secret is updated.")
                                if vap_accounting:
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS Accounting is configured on the VAP. Please ensure the RADIUS Accounting server shared secret is updated.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Points found.")

                    vaps = {'internal_wlan_vaps': vaps, 'internal_wlan_vap_data': vap_data}
                    update_routine_results(self.routine_results, self.firewall, 'virtual_access_points', vaps)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Points found")
                        print(type(vaps), "->", vaps)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Internal Wireless Virtual Access Points: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Internal Wireless Virtual Access Points check (severity: {get_check_severity('internal_wlan_vaps')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['internal_wlan_vaps'])

    # Internal Wireless Virtual Access Point Profiles
    def check_internal_wlan_vap_profiles(self):
        if should_run_check('internal_wlan_vap_profiles', self.a.severity):
            try:
                vap_profiles = get_request(self.api_base, self.api_session, '/api/sonicos/wireless/virtual-access-point/profiles',
                                           silent=self.silent)

                if vap_profiles:
                    vap_profile_count = 0
                    try:
                        vap_profile_key = vap_profiles.get('wireless', {}).get('virtual_access_point', {}).get(
                            'profile', {})
                        if isinstance(vap_profile_key, list):
                            vap_profile_count = len(vap_profile_key)
                        elif isinstance(vap_profile_key, dict) and vap_profile_key == {}:
                            vap_profile_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining Internal Wireless VAP profile count.")
                            print(type(vap_profiles), "->", vap_profiles)
                            print()

                    vap_profile_data = []
                    if vap_profile_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {vap_profile_count} Internal Wireless Virtual Access Point Profile(s) configured.")
                            print("Internal Wireless Virtual Access Point Profiles:")
                        all_vap_profiles = vap_profiles.get('wireless', {}).get('virtual_access_point', {}).get(
                            'profile', [])
                        for profile in all_vap_profiles:
                            profile_name = profile.get('name', '')
                            profile_security = profile.get('authentication_type', {})
                            profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip',
                                                                                                                None)
                            profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get(
                                'ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get(
                                'ip', None)
                            vap_profile_data.append(
                                {'name': profile_name, 'radius': profile_radius, 'accounting': profile_accounting})
                            if profile_name:
                                if not self.silent:
                                    print(f"  - {profile_name}: Please update the pre-shared key.")
                                if profile_radius:
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS is configured on the VAP Profile. Please ensure the RADIUS server shared secret is updated.")
                                if profile_accounting:
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS Accounting is configured on the VAP Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Point Profiles found.")

                    vap_profiles = {'internal_wlan_vap_profiles': vap_profiles,
                                    'internal_wlan_vap_profile_data': vap_profile_data}
                    update_routine_results(self.routine_results, self.firewall, 'internal_wlan_virtual_access_point_profiles',
                                           vap_profiles)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Internal Wireless Virtual Access Point Profiles found")
                        print(type(vap_profiles), "->", vap_profiles)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Internal Wireless Virtual Access Point Profiles: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping Internal Wireless Virtual Access Point Profiles check (severity: {get_check_severity('internal_wlan_vap_profiles')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['internal_wlan_vap_profiles'])

    # Wireless SonicPoint/SonicWave/Virtual Access Points. Preshared keys, RADIUS shared secrets, etc.
    # SonicPoint/SonicWave Virtual Access Point Objects
    def check_sonicpoint_vaps(self):
        if should_run_check('sonicpoint_vaps', self.a.severity):
            try:
                vaps = get_request(self.api_base, self.api_session, '/api/sonicos/sonicpoint/virtual-access-point/objects',
                                   silent=self.silent)

                if vaps:
                    vap_count = 0
                    try:
                        vap_key = vaps.get('sonicpoint', {}).get('virtual_access_point', {}).get('object', {})
                        if isinstance(vap_key, list):
                            vap_count = len(vap_key)
                        elif isinstance(vap_key, dict) and vap_key == {}:
                            vap_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining VAP count.")
                            print(type(vaps), "->", vaps)
                            print()

                    vap_data = []
                    if vap_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found SonicPoint/SonicWave {vap_count} Virtual Access Point(s) configured.")
                            print("SonicPoint/SonicWave Virtual Access Points:")
                        all_vaps = vaps.get('sonicpoint', {}).get('virtual_access_point', {}).get('object', [])
                        for vap in all_vaps:
                            vap_name = vap.get('name', '')
                            vap_ssid = vap.get('ssid', '')
                            vap_vlan = vap.get('vlan', '')
                            vap_status = vap.get('enable', '')
                            vap_security = vap.get('authentication_type', {})
                            vap_radius = vap.get('radius', {}).get('server', {}).get('server1', {}).get('ip', None)
                            vap_accounting = vap.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip',
                                                                                                                None) or vap.get(
                                'radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                            vap_data_entry = {'name': vap_name, 'ssid': vap_ssid, 'vlan': vap_vlan,
                                              'status': vap_status, 'radius': vap_radius, 'accounting': vap_accounting}
                            vap_data.append(vap_data_entry)
                            if vap_name:
                                if not self.silent:
                                    print(
                                        f"  - {vap_name}, SSID: {vap_ssid}, VLAN: {vap_vlan} ({'enabled' if vap_status else 'disabled'}): Please update the pre-shared key.")
                                if vap_radius:
                                    if not self.silent:
                                        print(f"    - RADIUS is configured on the VAP. Please ensure the RADIUS server shared secret is updated.")
                                if vap_accounting:
                                    if not self.silent:
                                        print(f"    - RADIUS Accounting is configured on the VAP. Please ensure the RADIUS Accounting server shared secret is updated.")
                    else:
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Virtual Access Points found.")

                    vaps = {'sonicpoint_vaps': vaps, 'sonicpoint_vap_data': vap_data}
                    update_routine_results(self.routine_results, self.firewall, 'virtual_access_points', vaps)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No Virtual Access Points found")
                        print(type(vaps), "->", vaps)
                        print()
            except Exception as e:
                if not self.silent:
                    print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving Virtual Access Points: {e}")
        else:
            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SonicPoint/SonicWave Virtual Access Points check (severity: {get_check_severity('sonicpoint_vaps')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sonicpoint_vaps'])

    # SonicPoint/SonicWave Virtual Access Point Profiles
    def check_sonicpoint_vap_profiles(self):
        if should_run_check('sonicpoint_vap_profiles', self.a.severity):
            try:
                vap_profiles = get_request(self.api_base, self.api_session,
                                           '/api/sonicos/sonicpoint/virtual-access-point/profiles', silent=self.silent)

                if vap_profiles:
                    vap_profile_count = 0
                    try:
                        vap_profile_key = vap_profiles.get('sonicpoint', {}).get('virtual_access_point', {}).get(
                            'profile', {})
                        if isinstance(vap_profile_key, list):
                            vap_profile_count = len(vap_profile_key)
                        elif isinstance(vap_profile_key, dict) and vap_profile_key == {}:
                            vap_profile_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave VAP profile count.")
                            print(type(vap_profiles), "->", vap_profiles)
                            print()

                    vap_profile_data = []
                    if vap_profile_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {vap_profile_count} SonicPoint/SonicWave Virtual Access Point Profile(s) configured.")
                            print("SonicPoint/SonicWave Virtual Access Point Profiles:")
                        all_vap_profiles = vap_profiles.get('sonicpoint', {}).get('virtual_access_point', {}).get(
                            'profile', [])
                        for profile in all_vap_profiles:
                            profile_name = profile.get('name', '')
                            profile_security = profile.get('authentication_type', {})
                            profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip',
                                                                                                                None)
                            profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get(
                                'ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get(
                                'ip', None)
                            vap_profile_data.append(
                                {'name': profile_name, 'radius': profile_radius, 'accounting': profile_accounting})
                            if profile_name:
                                if not self.silent:
                                    print(f"  - {profile_name}: Please update the pre-shared key.")
                                if profile_radius:
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS is configured on the VAP Profile. Please ensure the RADIUS server shared secret is updated.")
                                if profile_accounting:
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS Accounting is configured on the VAP Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Virtual Access Point Profiles found.")

                    vap_profiles = {'sonicpoint_vap_profiles': vap_profiles,
                                    'sonicpoint_vap_profile_data': vap_profile_data}
                    update_routine_results(self.routine_results, self.firewall, 'virtual_access_point_profiles', vap_profiles)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Virtual Access Point Profiles found")
                        print(type(vap_profiles), "->", vap_profiles)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Virtual Access Point Profiles: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SonicPoint/SonicWave Virtual Access Point Profiles check (severity: {get_check_severity('sonicpoint_vap_profiles')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sonicpoint_vap_profiles'])

    # Wireless Access Points (SonicPoint/SonicWave Profiles and Objects)
    # SonicPoint/SonicWave Profiles
    def check_sonicpoint_profiles(self):
        if should_run_check('sonicpoint_profiles', self.a.severity):
            try:
                sp_profiles = get_request(self.api_base, self.api_session, '/api/sonicos/sonicpoint/profiles', silent=self.silent)
                if sp_profiles:
                    sp_profile_count = 0
                    try:
                        sp_profile_key = sp_profiles.get('sonicpoint', {}).get('profile', {})
                        if isinstance(sp_profile_key, list):
                            sp_profile_count = len(sp_profile_key)
                        elif isinstance(sp_profile_key, dict) and sp_profile_key == {}:
                            sp_profile_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave profile count.")
                            print(type(sp_profiles), "->", sp_profiles)
                            print()

                    sp_profile_data = []
                    if sp_profile_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {sp_profile_count} SonicPoint/SonicWave Profile(s) configured.")
                            print("SonicPoint/SonicWave Profiles:")
                        all_sp_profiles = sp_profiles.get('sonicpoint', {}).get('profile', [])
                        for profile in all_sp_profiles:
                            profile_name = (profile.get('waveax', {}).get('name_prefix', None) or
                                            profile.get('n', {}).get('name_prefix', None) or
                                            profile.get('ndr', {}).get('name_prefix', None) or
                                            profile.get('ac', {}).get('name_prefix', None) or
                                            profile.get('wave2', {}).get('name_prefix', None)
                                            )
                            profile_radius = profile.get('radius', {}).get('server', {}).get('server1', {}).get('ip',
                                                                                                                None)
                            profile_accounting = profile.get('radius', {}).get('accounting', {}).get('server1', {}).get(
                                'ip', None) or profile.get('radius', {}).get('accouting', {}).get('server1', {}).get(
                                'ip', None)
                            profile_administrator = profile.get('administrator', {}).get('name', None)
                            profile_sslvpn_server = profile.get('sslvpn', {}).get('server', False)
                            profile_sslvpn_user = profile.get('sslvpn', {}).get('user_name', False)
                            sp_profile_data.append(
                                {'name': profile_name, 'radius': profile_radius, 'accounting': profile_accounting,
                                 'administrator': profile_administrator, 'sslvpn_user': profile_sslvpn_user,
                                 'sslvpn_server': profile_sslvpn_server})
                            if profile_name:
                                if not self.silent:
                                    print(f"  - {profile_name}: Please update the pre-shared key.")
                                if profile_radius and (profile_radius != '' and profile_radius != '0.0.0.0'):
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS is configured on the SonicPoint/SonicWave Profile. Please ensure the RADIUS server shared secret is updated.")
                                if profile_accounting and (
                                        profile_accounting != '' and profile_accounting != '0.0.0.0'):
                                    if not self.silent:
                                        print(
                                            f"    - RADIUS Accounting is configured on the SonicPoint/SonicWave Profile. Please ensure the RADIUS Accounting server shared secret is updated.")
                                if profile_administrator:
                                    if not self.silent:
                                        print(
                                            f"    - Administrator account '{profile_administrator}' is set on the SonicPoint/SonicWave Profile. Please ensure the administrator account password is updated.")
                                if profile_sslvpn_server or profile_sslvpn_user:
                                    if not self.silent:
                                        print(
                                            f"    - L3 SSLVPN Management is configured on the SonicPoint/SonicWave Profile ({profile_sslvpn_user}@{profile_sslvpn_server}). Please ensure the SSLVPN server and user account password is updated.")
                    else:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Profiles found.")

                    sp_profiles = {"sonicpoint_profiles": sp_profiles, "sonicpoint_profile_data": sp_profile_data}
                    update_routine_results(self.routine_results, self.firewall, 'sonicpoint', sp_profiles)
                else:
                    if not self.silent:
                        print(
                            f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Profiles found")
                        print(type(sp_profiles), "->", sp_profiles)
                        print()
            except Exception as e:
                if not self.silent:
                    print(
                        f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Profiles: {e}")
        else:
            print(
                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SonicPoint/SonicWave Profiles check (severity: {get_check_severity('sonicpoint_profiles')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sonicpoint_profiles'])

    # SonicPoint/SonicWave Access Point Objects
    def check_sonicpoint_objects(self):
        if should_run_check('sonicpoint_objects', self.a.severity):
            try:
                sp_objects = get_request(self.api_base, self.api_session, '/api/sonicos/sonicpoint/sonicpoints', silent=self.silent)
                if sp_objects:
                    sp_object_count = 0
                    try:
                        sp_object_key = sp_objects.get('sonicpoint', {}).get('sonicpoint', {})
                        if isinstance(sp_object_key, list):
                            sp_object_count = len(sp_object_key)
                        elif isinstance(sp_object_key, dict) and sp_object_key == {}:
                            sp_object_count = 0
                    except (KeyError, TypeError):
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error determining SonicPoint/SonicWave object count.")
                            print(type(sp_objects), "->", sp_objects)
                            print()

                    sp_object_data = []
                    if sp_object_count > 0:
                        if not self.silent:
                            print(
                                f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Found {sp_object_count} SonicPoint/SonicWave Object(s) configured.")
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
                            obj_accounting = obj.get('radius', {}).get('accounting', {}).get('server1', {}).get('ip',
                                                                                                                None) or obj.get(
                                'radius', {}).get('accouting', {}).get('server1', {}).get('ip', None)
                            obj_administrator = obj.get('administrator', {}).get('name', None)
                            obj_sslvpn_server = obj.get('sslvpn', {}).get('server', False)
                            obj_sslvpn_user = obj.get('sslvpn', {}).get('user_name', False)
                            sp_object_data.append({'name': obj_name, 'radius': obj_radius, 'accounting': obj_accounting,
                                                   'administrator': obj_administrator, 'sslvpn_user': obj_sslvpn_user,
                                                   'sslvpn_server': obj_sslvpn_server})
                            if obj:
                                if not self.silent:
                                    print(f"  - {obj}: Please update the pre-shared key.")
                                if obj_radius and (obj_radius != '' and obj_radius != '0.0.0.0'):
                                    if not self.silent:
                                        print(f"    - RADIUS is configured on the SonicPoint/SonicWave Object. Please ensure the RADIUS server shared secret is updated.")
                                if obj_accounting and (obj_accounting != '' and obj_accounting != '0.0.0.0'):
                                    if not self.silent:
                                        print(f"    - RADIUS Accounting is configured on the SonicPoint/SonicWave Object. Please ensure the RADIUS Accounting server shared secret is updated.")
                                if obj_administrator:
                                    if not self.silent:
                                        print(f"    - Administrator account '{obj_administrator}' is set on the SonicPoint/SonicWave Object. Please ensure the administrator account password is updated.")
                                if obj_sslvpn_server or obj_sslvpn_user:
                                    if not self.silent:
                                        print(f"    - L3 SSLVPN Management is configured on the SonicPoint/SonicWave Object ({obj_sslvpn_user}@{obj_sslvpn_server}). Please ensure the SSLVPN server and user account password is updated.")
                    else:
                        if not self.silent:
                            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Objects found.")

                    sp_objects = {"sonicpoint_objects": sp_objects, "sonicpoint_object_data": sp_object_data}
                    update_routine_results(self.routine_results, self.firewall, 'sonicpoint_sonicwave_objects', sp_objects)
                else:
                    if not self.silent:
                        print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: No SonicPoint/SonicWave Objects found")
                        print(type(sp_objects), "->", sp_objects)
                        print()
            except Exception as e:
                if not self.silent:
                    print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Error retrieving SonicPoint/SonicWave Objects: {e}")
        else:
            print(f"({self.target_numbers[0]}/{self.target_numbers[1]}) {generate_timestamp()}: Skipping SonicPoint/SonicWave Objects check (severity: {get_check_severity('sonicpoint_objects')}, filter: {self.a.severity})")
            update_routine_results(self.routine_results, self.firewall, 'skipped_checks', data=['sonicpoint_objects'])

