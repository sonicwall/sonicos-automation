from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request


class VPNMixin:
    """Mixin class to add VPN-related methods to the main playbook class."""
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
