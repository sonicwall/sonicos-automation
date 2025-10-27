from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request


class AuthenticationMixin:
    """
    Mixin class to provide authentication-related methods. LDAP, RADIUS, TACACS, SSO, Accounting, etc. are here.
    """
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

