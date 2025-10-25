"""
Client-side SonicWall Operations Engine for PyScript
Handles UI interactions and calls Flask server for actual operations.
"""

import asyncio
from js import document, console, fetch, JSON
from pyodide.ffi import create_proxy

class OperationEngine:
    """Client-side operation engine that handles UI and calls Flask server for operations."""

    def __init__(self):
        self.current_operation = None
        self.operation_cancelled = False
        self.results_history = []

    def show_progress_modal(self):
        """Show the progress modal."""
        document.getElementById('progress-modal').classList.remove('hide')

    def hide_progress_modal(self):
        """Hide the progress modal."""
        document.getElementById('progress-modal').classList.add('hide')

    def update_progress(self, percentage, current_step, target_info=""):
        """Update progress bar and information."""
        document.getElementById('progress-bar').style.width = f"{percentage}%"
        document.getElementById('progress-percentage').textContent = f"{percentage}%"
        document.getElementById('current-target').textContent = target_info or current_step

    def add_progress_step(self, step_text, status="info"):
        """Add a step to the progress log."""
        steps_container = document.getElementById('operation-steps')
        step_div = document.createElement('div')
        step_div.className = f"text-xs p-2 rounded status-{status}"
        step_div.textContent = f"{step_text}"
        steps_container.appendChild(step_div)
        steps_container.scrollTop = steps_container.scrollHeight

    def clear_progress_steps(self):
        """Clear the progress steps display."""
        document.getElementById('operation-steps').innerHTML = ''

    async def execute_connection_test(self, target_data):
        """Client-side connection test that calls Flask server."""
        self.operation_cancelled = False
        self.show_progress_modal()
        self.clear_progress_steps()

        try:
            self.update_progress(10, "Connecting to server...")
            self.add_progress_step("Starting connection test")

            # Make HTTP request to Flask server
            console.log("Calling Flask /test_connection endpoint")
            console.log("Target data:", target_data)
            response = await fetch('/test_connection', {
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": JSON.stringify(target_data)
            })

            self.update_progress(50, "Processing server response...")
            result = await response.json()

            if response.ok and result.get('success'):
                self.update_progress(100, "Connection test completed")
                self.add_progress_step("Connection successful", "success")
                console.log("Connection test successful:", result)
                return result
            else:
                error_msg = result.get('error', 'Unknown error')
                self.add_progress_step(f"Connection failed: {error_msg}", "error")
                console.error("Connection test failed:", error_msg)
                return result

        except Exception as e:
            error_msg = f"Client error: {str(e)}"
            self.add_progress_step(error_msg, "error")
            console.error("Connection test exception:", error_msg)
            return {
                'success': False,
                'error': error_msg,
                'function': 'execute_connection_test'
            }
        finally:
            # Keep modal open briefly to show final result
            await asyncio.sleep(2)
            self.hide_progress_modal()

    async def execute_single_target_operation(self, config, operation_type):
        """Execute single target operation by calling Flask server."""
        self.operation_cancelled = False
        self.show_progress_modal()
        self.clear_progress_steps()

        try:
            self.update_progress(10, f"Starting {operation_type} operation...")
            self.add_progress_step(f"Initiating {operation_type} operation")

            # Determine which Flask endpoint to call
            if operation_type == "analysis":
                endpoint = "/single_analysis"
            else:
                endpoint = "/single"

            console.log(f"Calling Flask {endpoint} endpoint")
            self.update_progress(20, "Connecting to server...")

            # Make HTTP request to Flask server
            response = await fetch(endpoint, {
                "method": "POST",
                "headers": {"Content-Type": "application/json"},
                "body": JSON.stringify(config)
            })

            self.update_progress(60, "Processing operation...")
            result = await response.json()

            if response.ok and result.get('success'):
                self.update_progress(100, f"{operation_type.capitalize()} completed")
                self.add_progress_step(f"{operation_type.capitalize()} operation successful", "success")

                # Store result in history
                self.results_history.append({
                    'timestamp': self._get_timestamp(),
                    'operation': operation_type,
                    'target': config.get('firewall', 'Unknown'),
                    'result': result
                })

                console.log(f"{operation_type} operation successful:", result)
                return result
            else:
                errors = result.get('errors', [result.get('error', 'Unknown error')])
                error_msg = '; '.join(errors) if isinstance(errors, list) else str(errors)
                self.add_progress_step(f"Operation failed: {error_msg}", "error")
                console.error(f"{operation_type} operation failed:", error_msg)
                return result

        except Exception as e:
            error_msg = f"Client error: {str(e)}"
            self.add_progress_step(error_msg, "error")
            console.error(f"{operation_type} operation exception:", error_msg)
            return {
                'success': False,
                'errors': [error_msg],
                'function': 'execute_single_target_operation'
            }
        finally:
            # Keep modal open briefly to show final result
            await asyncio.sleep(3)
            self.hide_progress_modal()

    def _get_timestamp(self):
        """Get current timestamp for results history."""
        from js import Date
        return Date().toLocaleString()

    def get_results_history(self):
        """Get the results history for display."""
        return self.results_history

    def cancel_operation(self):
        """Cancel the current operation."""
        self.operation_cancelled = True
        self.add_progress_step("Operation cancelled by user", "warning")
        console.log("Operation cancelled by user")


# Create a singleton instance for the web app to use
operation_engine = OperationEngine()
