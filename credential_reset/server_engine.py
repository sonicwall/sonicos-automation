"""
Server-side SonicWall Operations Engine for Flask
Handles actual firewall operations without browser dependencies.
"""

import logging
import json
import importlib.util
import sys
import os
from typing import Dict, Any, Tuple, Optional

# Add parent directory to path to access common and sonicos modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from credential_reset.firewall import initialize_session, gather_firewall_info
from credential_reset.export_helper import export_tsr_if_enabled
from sonicos.api import logout, disable_sonicos_api_ssh
import common.constants as constants

# Import load_targets from remediation-app.py using importlib
spec = importlib.util.spec_from_file_location("remediation_app", os.path.join(os.path.dirname(os.path.dirname(__file__)), "remediation-app.py"))
remediation_app = importlib.util.module_from_spec(spec)
sys.modules["remediation_app"] = remediation_app
spec.loader.exec_module(remediation_app)
load_targets = remediation_app.load_targets

logger = logging.getLogger(__name__)


class ServerOperationEngine:
    """Server-side operation engine that handles actual firewall operations."""

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def execute_connection_test_sync(self, target_data: Dict[str, Any], operation_id: str = None) -> Dict[str, Any]:
        """
        Server-side connection test without browser dependencies.

        Args:
            target_data: Dictionary containing firewall connection parameters
            operation_id: Optional operation ID for progress tracking

        Returns:
            Dictionary with test results in format expected by web client
        """
        # Create result structure similar to remediation-app.py response
        test_result = {
            "success": False,
            "data": target_data,
            "firewall_info": None,
            "return_msg": "",
            "errors": [],
            "function": "execute_connection_test_sync"
        }

        # Initialize progress tracker if operation_id is provided
        progress_tracker = None
        if operation_id:
            from common.progress_tracker import progress_manager
            # Get the actual progress tracker for this operation
            operation_data = progress_manager.active_operations.get(operation_id)
            if operation_data:
                progress_tracker = operation_data["tracker"]

        try:
            if progress_tracker:
                progress_tracker.update("Initializing connection test...", 5)

            self.logger.info("Starting server-side connection test")

            # Load the target from form data
            target = load_targets(target_data)
            target_numbers = (1, 1) # Single target (1 of 1)

            # Validate required fields
            errors = []
            if not target.firewall or target.firewall.strip() == "":
                errors.append("Firewall IP/Hostname is required.")
            if not target.username or target.username.strip() == "":
                errors.append("Username is required.")
            if not target.password or target.password.strip() == "":
                errors.append("Password is required.")

            if errors:
                test_result["errors"] = errors
                test_result["return_msg"] = "<br>".join(errors)
                self.logger.error(f"Validation failed: {errors}")
                if progress_tracker:
                    progress_tracker.complete(success=False, message=f"Validation failed: {'; '.join(errors)}", result_data=test_result)
                return test_result

            if progress_tracker:
                progress_tracker.update(f"Connecting to {target.firewall}...", 10)

            self.logger.info(f"Connecting to {target.firewall}")

            if target.sshport == 0:
                progress_tracker.update(f"SSH Management failback connection is disabled", 10)
                self.logger.info("SSH logic is disabled.")

            # Initialize a session with the firewall
            if progress_tracker:
                progress_tracker.update("Establishing firewall session...", 15)

            api_session, return_msg, api_base, username, password = initialize_session(
                target,
                target_numbers,
                username=target.username,
                password=target.password,
                sshport=target.sshport
            )

            if api_session is None or api_session is False:
                error_msg = f"Unable to create an admin session. Return message: {return_msg}"
                self.logger.error(error_msg)
                test_result["return_msg"] = return_msg
                test_result["errors"] = [error_msg]
                if progress_tracker:
                    progress_tracker.complete(success=False, message=f"Session failed: {return_msg}", result_data=test_result)
                return test_result

            if constants.get_autoenabled_sonicos_api():
                progress_tracker.update(f"SonicOS API auto-enabled via SSH", 25)

            if progress_tracker:
                progress_tracker.update("Gathering firewall information...", 30)

            # Gather firewall information
            firewall_info, error_msg = gather_firewall_info(api_session, api_base, target_numbers, silent=True)
            if firewall_info is None:
                error_msg = f"Error gathering firewall information: {error_msg}"
                self.logger.error(error_msg)
                test_result["return_msg"] = error_msg
                test_result["errors"] = [error_msg]
                if progress_tracker:
                    progress_tracker.complete(success=False, message=f"Info gathering failed: {error_msg}", result_data=test_result)
                return test_result

            if progress_tracker:
                progress_tracker.update(f"{firewall_info['device_model']} (Gen{firewall_info['firewall_generation']}) - {firewall_info['firmware_version']}", 60)

            # Successfully connected and gathered info
            self.logger.info(f"Successfully connected to firewall: {firewall_info}")

            if progress_tracker:
                progress_tracker.update("Finalizing connection test...", 75)

            # If we enabled SonicOS API via SSH, flag it for display
            if constants.get_autoenabled_sonicos_api():
                firewall_info['api_autoenabled'] = True
                progress_tracker.update(f"Auto-disabling SonicOS API via SSH", 80)
                disable_sonicos_api_ssh(target.firewall, target.sshport, username, password)

            # Log out from the session
            try:
                logout(api_base, api_session, firewall_generation=firewall_info.get('firewall_generation', None))
            except Exception as e:
                self.logger.error(f"Error logging out: {e}")

            # Reset auto-enabled SonicOS API flag
            if constants.get_autoenabled_sonicos_api() is True:
                constants.set_autoenabled_sonicos_api(False)

            # Set success result
            test_result["success"] = True
            test_result["firewall_info"] = firewall_info
            test_result["return_msg"] = return_msg or "Connection test successful"

            # Complete operation with result data
            if progress_tracker:
                progress_tracker.complete(success=True, message="Connection test completed successfully", result_data=test_result)

            return test_result

        except Exception as e:
            error_msg = f"Connection test failed with exception: {str(e)}"
            self.logger.error(error_msg)
            test_result["return_msg"] = error_msg
            test_result["errors"] = [error_msg]
            if progress_tracker:
                progress_tracker.complete(success=False, message=f"Exception: {error_msg}", result_data=test_result)
            return test_result

    def execute_single_target_operation(self, config: Dict[str, Any], operation_type: str, operation_id: str = None) -> Dict[str, Any]:
        """
        Execute a single target operation (analysis, credential reset, etc.) with progress tracking.

        Args:
            config: Configuration dictionary from web form
            operation_type: Type of operation ("analysis", "reset", etc.)
            operation_id: Optional operation ID for progress tracking

        Returns:
            Dictionary with operation results
        """
        operation_result = {
            "success": False,
            "operation_type": operation_type,
            "config": config,
            "results": {},
            "errors": [],
            "function": "execute_single_target_operation"
        }

        # Initialize progress tracker if operation_id is provided
        progress_tracker = None
        if operation_id:
            from common.progress_tracker import progress_manager
            operation_data = progress_manager.active_operations.get(operation_id)
            if operation_data:
                progress_tracker = operation_data["tracker"]

        try:
            if progress_tracker:
                progress_tracker.update("Initializing operation...", 0)

            self.logger.info(f"Starting {operation_type} operation")

            # Convert config to target format
            # Convert security_checks to severity filter
            security_checks = config.get('security_checks', [])
            if not security_checks or len(security_checks) == 4:
                severity = "all"
            elif set(security_checks) == {'critical'}:
                severity = "critical"
            elif set(security_checks) == {'critical', 'high'}:
                severity = "high"
            elif set(security_checks) == {'critical', 'high', 'medium'}:
                severity = "medium"
            else:
                severity = "all"

            target_data = {
                'firewall': config.get('firewall'),
                'username': config.get('username'),
                'password': config.get('password'),
                'sshport': config.get('sshport', 22),
                'temp_password': config.get('temp_password', ''),
                'randomize_temp_password': config.get('randomize_temp_password', True),
                'unbind_totp': config.get('unbind_totp', False),
                'force_password_change': config.get('force_password_change', False),
                'export_settings': config.get('export_settings', False),
                'export_tsr': config.get('export_tsr', False),
                'verbose': config.get('verbose', False),
                'severity': severity
            }

            if progress_tracker:
                progress_tracker.update(f"Connecting to {config.get('firewall')}...", 5)

            # Load the target
            target = load_targets(target_data)
            target_numbers = (1, 1)

            if progress_tracker:
                progress_tracker.update("Establishing firewall session...", 5)

            # Initialize session
            api_session, return_msg, api_base, username, password = initialize_session(
                target,
                target_numbers,
                username=target.username,
                password=target.password,
                sshport=target.sshport
            )

            if api_session is None or api_session is False:
                error_msg = f"Unable to create session: {return_msg}"
                operation_result["errors"] = [error_msg]
                if progress_tracker:
                    progress_tracker.complete(success=False, message=f"Session failed: {error_msg}", result_data=operation_result)
                return operation_result

            if progress_tracker:
                progress_tracker.update("Gathering firewall information...", 20)

            # Gather firewall info
            firewall_info, error_msg = gather_firewall_info(api_session, api_base, target_numbers, silent=True)
            if firewall_info is None:
                operation_result["errors"] = [f"Error gathering firewall info: {error_msg}"]
                if progress_tracker:
                    progress_tracker.complete(success=False, message=f"Info gathering failed: {error_msg}", result_data=operation_result)
                return operation_result

            if progress_tracker:
                progress_tracker.update(f"Connected to {firewall_info['device_model']} (Gen{firewall_info['firewall_generation']}) - {firewall_info['firmware_version']}", 30)

            # Execute based on operation type
            # TODO: Review the operation types.
            if operation_type == "analysis":
                results = self._execute_security_analysis(api_session, api_base, target, firewall_info, config, progress_tracker, username, password)
                if progress_tracker:
                    progress_tracker.clear_substeps()
            elif operation_type == "reset":
                results = self._execute_credential_reset(api_session, api_base, target, firewall_info, config, progress_tracker)
            else:
                results = {"error": f"Unknown operation type: {operation_type}"}

            if progress_tracker:
                progress_tracker.update("Finalizing operation. Initializing cleanup...", 91)

            # Cleanup
            try:
                if progress_tracker:
                    progress_tracker.update("Closing API session...", 92)
                logout(api_base, api_session, firewall_generation=firewall_info.get('firewall_generation'))
            except Exception as e:
                self.logger.error(f"Error during logout: {e}")

            # Reset API flag if needed
            if constants.get_autoenabled_sonicos_api():
                if progress_tracker:
                    progress_tracker.update("Disabling SonicOS API...", 94)
                disable_sonicos_api_ssh(target.firewall, target.sshport, username, password)
                constants.set_autoenabled_sonicos_api(False)

            if progress_tracker:
                progress_tracker.update("Closing API session...", 95)

            operation_result["success"] = True
            operation_result["results"] = results
            operation_result["firewall_info"] = firewall_info

            if progress_tracker:
                progress_tracker.update("Preparing results...", 100)
                progress_tracker.complete(success=True, message="Operation completed successfully", result_data=operation_result)

            return operation_result

        except Exception as e:
            error_msg = f"Operation failed: {str(e)}"
            self.logger.error(error_msg)
            operation_result["errors"] = [error_msg]
            if progress_tracker:
                progress_tracker.complete(success=False, message=f"Exception: {error_msg}", result_data=operation_result)
            return operation_result

    def _execute_security_analysis(self, api_session, api_base: str, target, firewall_info: Dict, config: Dict, progress_tracker: Optional[Any] = None, username: str = None, password: str = None) -> Dict:
        """Execute security analysis on the firewall with progress tracking."""
        try:
            if progress_tracker:
                progress_tracker.update("Starting security analysis...", 30)

            # Export TSR if requested (before analysis)
            tsr_result = {}
            if config.get('export_tsr', False):
                if progress_tracker:
                    progress_tracker.update("TSR export requested...", 30)
                    progress_tracker.add_substep("Exporting Tech Support Report...", "running")
                target_numbers = (1, 1)
                tsr_result = export_tsr_if_enabled(api_session, api_base, target, target_numbers, firewall_info, silent=False, tag="pre-analysis")
                if progress_tracker:
                    progress_tracker.add_substep("TSR export completed", "completed", "success")
                    progress_tracker.clear_substeps()

            # Export Settings if requested (before analysis)
            if config.get('export_settings', False):
                if progress_tracker:
                    progress_tracker.update("Preferences export requested...", 30)
                    progress_tracker.add_substep("Exporting preferences file...", "running")
                from credential_reset.export_helper import export_settings_if_enabled
                target_numbers = (1, 1)
                settings_result = export_settings_if_enabled(api_session, api_base, target, target_numbers, firewall_info, username, password, silent=False, tag="pre-analysis")
                if progress_tracker:
                    progress_tracker.add_substep("Preferences export completed", "completed", "success")
                    progress_tracker.clear_substeps()

            if progress_tracker:
                progress_tracker.update("Initializing playbook...", 35)

            # If the firewall is a GEN6, establish an alternate API session.
            alt_session = None
            if firewall_info.get('firewall_generation') == 6:
                if progress_tracker:
                    progress_tracker.update("Establishing GEN6 alternate API session...", 35)

                from sonicos.api2 import Login

                alt_session = Login(
                    ipaddress=api_base,
                    userid=username,
                    passwd=password,
                    admin_mode="config",
                    http_type="https",
                    brwsr_cache=0,
                    verbose=0,
                    sessIdRef=0
                )

                logged_in, rmsg = alt_session.login2()
                if logged_in == 1:
                    if progress_tracker:
                        progress_tracker.add_substep("GEN6 alternate API session established", "completed", "success")
                        progress_tracker.clear_substeps()
                else:
                    if progress_tracker:
                        progress_tracker.add_substep(f"GEN6 alternate API session failed: {rmsg}", "error", "warning")
                        progress_tracker.clear_substeps()
                    alt_session = None
            else:
                alt_session = None

            if progress_tracker:
                progress_tracker.update("Executing playbook...", 40)

            from credential_reset.playbook import Playbook

            # Initialize routine_results dictionary (similar to reset_credentials.py)
            routine_results = {
                target.firewall: {
                    'api_base': api_base,
                    'api_session_successful': True,
                    'firewall_generation': firewall_info.get('firewall_generation'),
                    'firmware_version': firewall_info.get('firmware_version'),
                    'device_model': firewall_info.get('device_model'),
                    'serial_number': firewall_info.get('serial_number')
                }
            }

            target_numbers = (1, 1) # Single target (1 of 1)
            silent = True # Keep output minimal for web interface

            # Initialize the playbook class exactly like reset_credentials.py does
            # Now we can use target directly as args since it has all required attributes
            pb = Playbook(target=target,
                          target_numbers=target_numbers,
                          silent=silent,
                          api_base=api_base,
                          alt_session=alt_session,
                          api_session=api_session,
                          args=target, # Pass target as args since it now has severity, verbose, etc.
                          routine_results=routine_results,
                          firewall_info=firewall_info)

            if progress_tracker:
                progress_tracker.update("Running security analysis checks...", 45)

            # Execute playbook methods based on security levels selected
            security_levels = config.get('security_checks', ['critical', 'high', 'medium', 'low'])

            # Track progress through security checks
            total_checks = 0
            completed_checks = 0

            # Define security check categories and their severity levels
            security_check_methods = {
                'critical': [
                    ('list_ldap_servers', 'LDAP Servers'),
                    ('list_radius_servers', 'RADIUS Servers'),
                    ('list_tacacs_servers', 'TACACS+ Servers'),
                    ('list_snmpv3_users', 'SNMPv3 Users'),
                    ('check_clearpass_nac', 'ClearPass/NAC'),
                    ('list_sso_agents', 'SSO Agents'),
                    ('list_ts_agents', 'Terminal Server Agents')
                ],
                'high': [
                    ('list_vpn_policies', 'VPN Policies'),
                    ('check_wan_interfaces', 'WAN Interfaces'),
                    ('check_aws_api', 'AWS API'),
                    ('check_cloud_secure_edge', 'Cloud Secure Edge'),
                    ('check_email_logging', 'Email Logging'),
                    ('check_gms_ipsec_tunnel', 'GMS IPsec Tunnel')
                ],
                'medium': [
                    ('list_dynamic_dns', 'Dynamic DNS'),
                    ('check_packet_monitor_ftp_logging', 'Packet Monitor FTP'),
                    ('check_tsr_exp_scheduled_exports', 'TSR Scheduled Exports'),
                    ('check_deao', 'Dynamic External Address Objects'),
                    ('check_dyn_botnet_list_server', 'Dynamic Botnet List'),
                    ('list_custom_ntp_servers', 'Custom NTP Servers')
                ],
                'low': [
                    ('check_extended_switches', 'Extended Switches'),
                    ('check_extended_switch_users', 'Extended Switch Users'),
                    ('check_extended_switch_radius', 'Extended Switch RADIUS'),
                    ('check_wlan_radius_servers', 'WLAN RADIUS Servers'),
                    ('check_ext_guest_auth', 'External Guest Authentication'),
                    ('list_sso_radius_clients', 'SSO RADIUS Clients'),
                    ('list_sso_api_clients', '3rd Party SSO API'),
                    ('list_radius_accounting_servers', 'RADIUS Accounting'),
                    ('list_tacacs_accounting_servers', 'TACACS+ Accounting'),
                    ('check_appflow_sfr_reporting', 'AppFlow SFR Reporting'),
                    ('check_sec_services_proxy', 'Security Services Proxy'),
                    ('list_advanced_routing_protocols', 'Advanced Routing'),
                    ('check_cellular_wwan', 'Cellular WWAN'),
                    ('check_internal_wlan_radio', 'Internal WLAN Radio'),
                    ('check_internal_wlan_vaps', 'Internal WLAN VAPs'),
                    ('check_internal_wlan_vap_profiles', 'Internal WLAN VAP Profiles'),
                    ('check_sonicpoint_vaps', 'SonicPoint VAPs'),
                    ('check_sonicpoint_vap_profiles', 'SonicPoint VAP Profiles'),
                    ('check_sonicpoint_profiles', 'SonicPoint Profiles'),
                    ('check_sonicpoint_objects', 'SonicPoint Objects')
                ]
            }

            # Count total checks to perform
            for level in security_levels:
                if level in security_check_methods:
                    total_checks += len(security_check_methods[level])

            # Execute security checks
            check_results = {}

            for level in security_levels:
                if level in security_check_methods:
                    for method_name, check_description in security_check_methods[level]:
                        try:
                            if progress_tracker:
                                progress_percent = 45 + int((completed_checks / total_checks) * 35)
                                progress_tracker.update(f"Checking {check_description}...", progress_percent)

                            # Execute the playbook method
                            if hasattr(pb, method_name):
                                method = getattr(pb, method_name)
                                result = method()
                                check_results[method_name] = {
                                    'description': check_description,
                                    'severity': level,
                                    'result': result,
                                    'status': 'completed'
                                }

                            else:
                                if progress_tracker:
                                    progress_tracker.add_substep(f"{check_description} check not available", "completed", "warning")
                                    progress_tracker.clear_substeps()
                                check_results[method_name] = {
                                    'description': check_description,
                                    'severity': level,
                                    'result': None,
                                    'status': 'not_available'
                                }

                            completed_checks += 1

                        except Exception as e:
                            self.logger.error(f"Error running {method_name}: {e}")
                            if progress_tracker:
                                progress_tracker.add_substep(f"{check_description} check failed: {str(e)}", "error", "error")
                            check_results[method_name] = {
                                'description': check_description,
                                'severity': level,
                                'result': None,
                                'status': 'error',
                                'error': str(e)
                            }
                            completed_checks += 1

            if progress_tracker:
                progress_tracker.clear_substeps()
                progress_tracker.update("Security analysis completed", 80)

            # Build the security analysis result
            security_analysis = {
                "playbook_results": check_results,
                "routine_results": routine_results,
                "checks_performed": list(check_results.keys()),
                "security_levels_analyzed": security_levels,
                "total_checks": total_checks,
                "completed_checks": completed_checks,
                "configuration_analysis": {
                    "checks_performed": [result['description'] for result in check_results.values()],
                    "recommendations": []  # Could be populated based on check results
                }
            }

            # NEW: Generate markdown report
            markdown_report = None
            converted_results = {}  # Initialize early to avoid reference before assignment
            try:
                if progress_tracker:
                    progress_tracker.update("Generating markdown report...", 85)

                from credential_reset.report_markdown import generate_markdown_summary

                # Convert playbook results to format expected by report generator
                converted_results = self._convert_results_for_markdown(check_results, routine_results, firewall_info)

                markdown_report = generate_markdown_summary(
                    results=converted_results,
                    firewall=target.firewall,
                    firewall_info=firewall_info,
                    args=target
                )

                if progress_tracker:
                    progress_tracker.update("Markdown report generated", 88)

            except Exception as e:
                self.logger.error(f"Failed to generate markdown report: {e}")
                markdown_report = f"# Report Generation Error\n\nFailed to generate markdown report: {str(e)}"
                # Ensure converted_results is available for summary generation even if markdown fails
                if not converted_results:
                    converted_results = self._convert_results_for_markdown(check_results, routine_results, firewall_info)

            # Generate summary data for the frontend
            try:
                if progress_tracker:
                    progress_tracker.update("Generating summary data...", 90)

                summary_data = self._generate_summary_data(converted_results, check_results, routine_results)

                if progress_tracker:
                    progress_tracker.update("Summary data generated", 92)
            except Exception as e:
                self.logger.error(f"Failed to generate summary data: {e}")
                summary_data = {}

            return {
                "security_analysis": security_analysis,
                "markdown_report": markdown_report,  # NEW: Add markdown report
                "summary_data": summary_data,  # NEW: Add summary data for frontend
                "analysis_timestamp": constants.generate_timestamp(),
                "tsr_result": tsr_result
            }

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            if progress_tracker:
                progress_tracker.add_substep(f"Analysis failed: {str(e)}", "error", "error")
            return {"error": f"Security analysis failed: {str(e)}"}

    def _convert_results_for_markdown(self, check_results: Dict, routine_results: Dict, firewall_info: Dict) -> Dict:
        """
        Convert playbook check results to format expected by markdown generator.

        Args:
            check_results: Dictionary of security check results
            routine_results: Dictionary containing routine operation results
            firewall_info: Dictionary containing firewall information

        Returns:
            Dictionary in format expected by generate_markdown_summary
        """
        try:
            # Start with firewall-specific data from routine_results
            converted = {}
            for firewall_ip, info in routine_results.items():
                if isinstance(info, dict):
                    converted.update(info)
                    break

            # Map playbook method results to keys expected by markdown generator
            method_mapping = {
                'list_ldap_servers': 'ldap_servers',
                'list_radius_servers': 'radius_servers',
                'list_tacacs_servers': 'tacacs_servers',
                'list_snmpv3_users': 'snmpv3_users',
                'check_clearpass_nac': 'clearpass_nac',
                'list_sso_agents': 'sso_agents',
                'list_ts_agents': 'ts_agents',
                'list_vpn_policies': 'vpn',  # Special case - VPN data structure
                'check_wan_interfaces': 'interesting_wan_list',
                'check_aws_api': 'log',  # AWS is nested under log
                'check_cloud_secure_edge': 'cloud_secure_edge',
                'check_email_logging': 'log_automation_data',
                'check_gms_ipsec_tunnel': 'gms_ipsec_tunnel',
                'list_dynamic_dns': 'ddns_services_v4',  # DDNS has v4/v6 variants
                'check_packet_monitor_ftp_logging': 'packet_monitor_ftp_set',
                'check_tsr_exp_scheduled_exports': 'tsr_scheduled_exports',
                'check_deao': 'deao',
                'check_dyn_botnet_list_server': 'botnet_list_server',
                'list_custom_ntp_servers': 'custom_ntp_servers',
                'check_extended_switches': 'extended_switches',
                'check_extended_switch_users': 'extended_switch_users',
                'check_extended_switch_radius': 'extended_switch_radius',
                'check_wlan_radius_servers': 'wlan_radius_servers',
                'check_ext_guest_auth': 'ext_guest_auth',
                'list_sso_radius_clients': 'sso_radius_clients',
                'list_sso_api_clients': 'sso_api_clients',
                'list_radius_accounting_servers': 'radius_accounting_servers',
                'list_tacacs_accounting_servers': 'tacacs_accounting_servers',
                'check_appflow_sfr_reporting': 'appflow_sfr_reporting',
                'check_sec_services_proxy': 'sec_services_proxy',
                'list_advanced_routing_protocols': 'advanced_routing_protocols',
                'check_cellular_wwan': 'cellular_wwan',
                'check_internal_wlan_radio': 'internal_wlan_radio',
                'check_internal_wlan_vaps': 'internal_wlan_vaps',
                'check_internal_wlan_vap_profiles': 'internal_wlan_vap_profiles',
                'check_sonicpoint_vaps': 'sonicpoint_vaps',
                'check_sonicpoint_vap_profiles': 'sonicpoint_vap_profiles',
                'check_sonicpoint_profiles': 'sonicpoint_profiles',
                'check_sonicpoint_objects': 'sonicpoint_objects'
            }

            # Process completed check results
            for method_name, result_data in check_results.items():
                if result_data.get('status') == 'completed' and result_data.get('result') is not None:
                    result = result_data['result']

                    # Map to expected key name
                    if method_name in method_mapping:
                        expected_key = method_mapping[method_name]

                        # Handle special cases for complex data structures
                        if method_name == 'list_vpn_policies':
                            # VPN policies need to be nested under vpn.policy
                            converted['vpn'] = {'policy': result if isinstance(result, list) else []}
                        elif method_name == 'check_aws_api':
                            # AWS API is nested under log.aws
                            if 'log' not in converted:
                                converted['log'] = {}
                            converted['log']['aws'] = result
                        elif method_name == 'list_dynamic_dns':
                            # DDNS might need to be split into v4/v6
                            converted['ddns_services_v4'] = result if isinstance(result, list) else []
                            converted['ddns_services_v6'] = []  # Separate v6 check if available
                        elif method_name == 'check_wan_interfaces':
                            # WAN interfaces should be a list of interface names
                            if isinstance(result, list):
                                converted[expected_key] = result
                            elif isinstance(result, dict):
                                # Extract interface names from dict if needed
                                converted[expected_key] = list(result.keys()) if result else []
                            else:
                                converted[expected_key] = []
                        else:
                            converted[expected_key] = result
                    else:
                        # Fallback: remove prefixes for unmapped methods
                        clean_key = method_name.replace('list_', '').replace('check_', '')
                        converted[clean_key] = result

            # Add default values for fields the markdown generator expects
            default_fields = {
                'total_user_count': 0,
                'total_users_forced_to_update_password': 0,
                'skipped_user_count': 0,
                'totp_unbind_attempted': False,
                'totp_unbind_successful_count': 0,
                'totp_unbind_failed_count': 0,
                'tsr_downloaded': False,
                'trace_logs_downloaded': False,
                'settings_exported': False
            }

            for key, default_value in default_fields.items():
                if key not in converted:
                    converted[key] = default_value

            return converted

        except Exception as e:
            self.logger.error(f"Error converting results for markdown: {e}")
            return {}

    def _generate_summary_data(self, converted_results: Dict, check_results: Dict, routine_results: Dict) -> Dict:
        """
        Generate summary data for the frontend summary tab.

        Args:
            converted_results: Results converted for markdown generation
            check_results: Raw check results from playbook
            routine_results: Routine operation results

        Returns:
            Dictionary containing summary data for frontend display
        """
        try:
            summary = {
                "overview": {
                    "total_checks": len(check_results),
                    "completed_checks": sum(1 for r in check_results.values() if r.get('status') == 'completed'),
                    "failed_checks": sum(1 for r in check_results.values() if r.get('status') == 'error'),
                    "unavailable_checks": sum(1 for r in check_results.values() if r.get('status') == 'not_available')
                },
                "severity_breakdown": {
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                },
                "findings": [],
                "device_info": {},
                "recommendations": []
            }

            # Extract device information
            if routine_results:
                for firewall_ip, info in routine_results.items():
                    if isinstance(info, dict):
                        summary["device_info"] = {
                            "firewall": firewall_ip,
                            "device_model": info.get('device_model', 'Unknown'),
                            "firmware_version": info.get('firmware_version', 'Unknown'),
                            "serial_number": info.get('serial_number', 'Unknown'),
                            "generation": info.get('firewall_generation', 'Unknown')
                        }
                        break

            # Count findings by severity and generate findings list
            # Fixed logic: Process ALL completed checks, not just those with truthy results
            for method_name, result_data in check_results.items():
                if result_data.get('status') == 'completed':  # Removed the 'and result_data.get('result')' condition
                    severity = result_data.get('severity', 'low')
                    description = result_data.get('description', method_name)
                    result = result_data.get('result')

                    # Count items found - handle None, empty lists, empty dicts properly
                    item_count = 0
                    if result is None:
                        item_count = 0
                    elif isinstance(result, list):
                        item_count = len(result)
                    elif isinstance(result, dict):
                        # Handle various dict structures
                        for key, value in result.items():
                            if isinstance(value, list):
                                item_count += len(value)
                            elif isinstance(value, dict):
                                for subkey, subvalue in value.items():
                                    if isinstance(subvalue, list):
                                        item_count += len(subvalue)
                                    elif subvalue:
                                        item_count += 1
                            elif value:
                                item_count += 1
                    elif result:  # For boolean or other truthy results
                        item_count = 1

                    # Add to severity breakdown and findings list
                    # This now counts ONLY items that were actually found (item_count > 0)
                    if item_count > 0:
                        summary["severity_breakdown"][severity] += item_count
                        summary["findings"].append({
                            "check": description,
                            "severity": severity,
                            "count": item_count,
                            "method": method_name
                        })

            # Generate recommendations based on findings
            total_findings = sum(summary["severity_breakdown"].values())
            completed_checks = summary["overview"]["completed_checks"]

            # Enhanced recommendations logic
            if total_findings > 0:
                if summary["severity_breakdown"]["critical"] > 0:
                    summary["recommendations"].append("Address critical security findings immediately")
                if summary["severity_breakdown"]["high"] > 0:
                    summary["recommendations"].append("Review high-priority configurations")
                if summary["severity_breakdown"]["medium"] > 0:
                    summary["recommendations"].append("Review medium-priority configurations when possible")
                if total_findings > 10:
                    summary["recommendations"].append("Consider a comprehensive security review")
                summary["recommendations"].append("Download the detailed report for specific remediation steps")
            else:
                # No items found - this is actually good!
                if completed_checks > 0:
                    summary["recommendations"].append("No security configuration items found that require attention")
                    summary["recommendations"].append("Your firewall appears to have a clean security configuration")
                else:
                    summary["recommendations"].append("Run security checks to analyze your firewall configuration")

            # Always add this recommendation
            summary["recommendations"].append("Review the detailed report for complete analysis results")

            return summary

        except Exception as e:
            self.logger.error(f"Error generating summary data: {e}")
            return {
                "overview": {"total_checks": 0, "completed_checks": 0, "failed_checks": 0, "unavailable_checks": 0},
                "severity_breakdown": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                "findings": [],
                "device_info": {},
                "recommendations": ["Error generating summary data"]
            }

    def _execute_credential_reset(self, api_session, api_base: str, target, firewall_info: Dict, config: Dict, progress_tracker: Optional[Any] = None) -> Dict:
        """Execute credential reset operation."""
        try:
            # Export TSR if requested (before making changes)
            tsr_result = {}
            if config.get('export_tsr', False):
                target_numbers = (1, 1)
                tsr_result = export_tsr_if_enabled(api_session, api_base, target, target_numbers, firewall_info, silent=False, tag="pre-reset")

            # This would implement the full credential reset logic
            # For now, return a placeholder result
            return {
                "credential_reset": {
                    "users_processed": 0,
                    "passwords_reset": 0,
                    "totp_unbound": 0 if not config.get('unbind_totp') else 0,
                    "status": "Not yet implemented"
                },
                "operation_timestamp": constants.generate_timestamp(),
                "tsr_result": tsr_result  # Include TSR result
            }

        except Exception as e:
            self.logger.error(f"Credential reset failed: {e}")
            return {"error": f"Credential reset failed: {str(e)}"}


# Create a singleton instance for Flask to use
server_operation_engine = ServerOperationEngine()
