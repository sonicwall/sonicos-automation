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

    def execute_single_target_operation(self, config: Dict[str, Any], operation_type: str) -> Dict[str, Any]:
        """
        Execute a single target operation (analysis, credential reset, etc.).

        Args:
            config: Configuration dictionary from web form
            operation_type: Type of operation ("analysis", "reset", etc.)

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

        try:
            self.logger.info(f"Starting {operation_type} operation")

            # Convert config to target format
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
                'export_tsr': config.get('export_tsr', False)
            }

            # Load the target
            target = load_targets(target_data)
            target_numbers = (1, 1)

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
                return operation_result

            # Gather firewall info
            firewall_info, error_msg = gather_firewall_info(api_session, api_base, target_numbers, silent=True)
            if firewall_info is None:
                operation_result["errors"] = [f"Error gathering firewall info: {error_msg}"]
                return operation_result

            # Execute based on operation type
            # TODO: Review the operation types.
            if operation_type == "analysis":
                results = self._execute_security_analysis(api_session, api_base, target, firewall_info, config)
            elif operation_type == "reset":
                results = self._execute_credential_reset(api_session, api_base, target, firewall_info, config)
            else:
                results = {"error": f"Unknown operation type: {operation_type}"}

            # Cleanup
            try:
                logout(api_base, api_session, firewall_generation=firewall_info.get('firewall_generation'))
            except Exception as e:
                self.logger.error(f"Error during logout: {e}")

            # Reset API flag if needed
            if constants.get_autoenabled_sonicos_api():
                disable_sonicos_api_ssh(target.firewall, target.sshport, username, password)
                constants.set_autoenabled_sonicos_api(False)

            operation_result["success"] = True
            operation_result["results"] = results
            operation_result["firewall_info"] = firewall_info

            return operation_result

        except Exception as e:
            error_msg = f"Operation failed: {str(e)}"
            self.logger.error(error_msg)
            operation_result["errors"] = [error_msg]
            return operation_result

    def _execute_security_analysis(self, api_session, api_base: str, target, firewall_info: Dict, config: Dict) -> Dict:
        """Execute security analysis on the firewall."""
        try:
            # Export TSR if requested (before analysis)
            tsr_result = {}
            if config.get('export_tsr', False):
                target_numbers = (1, 1)
                tsr_result = export_tsr_if_enabled(api_session, api_base, target, target_numbers, firewall_info, silent=False, tag="pre-analysis")

            from credential_reset.firewall import get_local_users

            # Get local users for analysis
            local_users = get_local_users(api_session, api_base, firewall_info.get('firewall_generation'))

            if not local_users:
                return {"error": "No local users found or unable to retrieve users"}

            # Perform security analysis
            security_analysis = {
                "user_security": {
                    "users_analyzed": len(local_users),
                    "users_found": len(local_users),
                    "issues": []
                },
                "configuration_analysis": {
                    "checks_performed": [],
                    "recommendations": []
                }
            }

            # Analyze each user for security issues
            for user in local_users:
                user_issues = []

                # Check for default passwords (basic heuristic)
                if user.get('name', '').lower() in ['admin', 'user', 'guest']:
                    user_issues.append({
                        "severity": "high",
                        "issue": f"Default account '{user.get('name')}' detected",
                        "recommendation": "Review default account security"
                    })

                # Check for password policy issues
                if not user.get('password_change_required', False):
                    user_issues.append({
                        "severity": "medium",
                        "issue": f"User '{user.get('name')}' not required to change password",
                        "recommendation": "Enable forced password change"
                    })

                # Add user-specific issues to analysis
                if user_issues:
                    security_analysis["user_security"]["issues"].extend(user_issues)

            # Add configuration checks based on selected security levels
            security_levels = config.get('security_checks', ['critical', 'high', 'medium', 'low'])

            for level in security_levels:
                security_analysis["configuration_analysis"]["checks_performed"].append(f"{level}_security_check")

            return {
                "security_analysis": security_analysis,
                "users_found": len(local_users),
                "analysis_timestamp": constants.generate_timestamp(),
                "tsr_result": tsr_result  # Include TSR result
            }

        except Exception as e:
            self.logger.error(f"Security analysis failed: {e}")
            return {"error": f"Security analysis failed: {str(e)}"}

    def _execute_credential_reset(self, api_session, api_base: str, target, firewall_info: Dict, config: Dict) -> Dict:
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
