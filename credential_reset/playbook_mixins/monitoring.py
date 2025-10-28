from credential_reset.utils import should_run_check, get_check_severity, update_routine_results
from common.utils import generate_timestamp
from sonicos.api import get_request


class MonitoringMixin():
    """Mixin class to add reporting, monitoring, and management-related methods to the main playbook class."""
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
