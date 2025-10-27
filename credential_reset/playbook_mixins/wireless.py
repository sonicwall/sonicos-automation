from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request


class WirelessMixin:
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
