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
            target_numbers = (1, 1)  # Single target (1 of 1)

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
                progress_tracker.update("Finalizing operation...", 85)

            # Cleanup
            try:
                if progress_tracker:
                    progress_tracker.update("Closing API session...", 85)
                logout(api_base, api_session, firewall_generation=firewall_info.get('firewall_generation'))
            except Exception as e:
                self.logger.error(f"Error during logout: {e}")

            # Reset API flag if needed
            if constants.get_autoenabled_sonicos_api():
                if progress_tracker:
                    progress_tracker.update("Disabling SonicOS API...", 90)
                disable_sonicos_api_ssh(target.firewall, target.sshport, username, password)
                constants.set_autoenabled_sonicos_api(False)

            if progress_tracker:
                progress_tracker.update("Closing API session...", 95)

            operation_result["success"] = True
            operation_result["results"] = results
            operation_result["firewall_info"] = firewall_info

            if progress_tracker:
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

            target_numbers = (1, 1)  # Single target (1 of 1)
            silent = True  # Keep output minimal for web interface

            # Initialize the playbook class exactly like reset_credentials.py does
            # Now we can use target directly as args since it has all required attributes
            pb = Playbook(target=target,
                          target_numbers=target_numbers,
                          silent=silent,
                          api_base=api_base,
                          alt_session=alt_session,
                          api_session=api_session,
                          args=target,  # Pass target as args since it now has severity, verbose, etc.
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
                                progress_tracker.add_substep(f"Running {check_description} check", "running")

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

                                if progress_tracker:
                                    progress_tracker.add_substep(f"{check_description} check completed", "completed", "success")
                            else:
                                if progress_tracker:
                                    progress_tracker.add_substep(f"{check_description} check not available", "completed", "warning")
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

            return {
                "security_analysis": security_analysis,
                "analysis_timestamp": constants.generate_timestamp(),
                "tsr_result": tsr_result
            }

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            if progress_tracker:
                progress_tracker.add_substep(f"Analysis failed: {str(e)}", "error", "error")
            return {"error": f"Security analysis failed: {str(e)}"}

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
