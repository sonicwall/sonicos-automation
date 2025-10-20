#!/usr/bin/env python3
"""
CORS Proxy Server for SonicWall Web App
This proxy server allows the web application to bypass CORS restrictions
by forwarding requests to SonicWall firewalls.

Usage:
    python remediation-app.py [--port PORT] [--host HOST]

Example:
    python remediation-app.py --port 8080
"""

from flask import Flask, request, Response, send_from_directory, send_file
from flask_cors import CORS
from typing import Union
from dataclasses import dataclass
import requests
import argparse
import sys
import logging
import os
import uuid
import queue
import json
import time
import threading


# Imports from reset_credentials.py
from typing import Optional, List
from os import path, mkdir
from common.banner import print_banner
from common.utils import (
    generate_timestamp,
    write_to_file,
)
from common.arguments import get_parser
from sonicos.api import (
    get_request,
    post_request,
    commit_pending,
    logout,
    disable_sonicos_api_ssh,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh,
    post_request_direct_cli,
)
import common.constants as constants
from sonicos.api2 import Login
from credential_reset.utils import (
    update_routine_results,
    print_verbose_details,
    normalize_password,
    normalize_temp_password,
    normalize_boolean,
    create_random_password,
    should_run_check,
    get_check_severity,
)
from credential_reset.firewall import (
    FirewallTarget,
    gather_firewall_info,
    initialize_session,
    get_local_users,
)
from credential_reset.firewall_actions import unbind_totp_from_users, process_password_changes
from credential_reset.csv_helper import parse_csv_targets
from credential_reset.export_helper import (
    export_tsr_if_enabled,
    export_tracelogs_if_enabled,
    export_settings_if_enabled
)
from credential_reset.report_console import generate_summary_table
from credential_reset.report_markdown import generate_markdown_summary
from credential_reset.playbook import Playbook
from credential_reset.report_helper import (
    calculate_routine_statistics,
)
from rich import print





# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})  # Allow all origins

# Disable SSL warnings for development
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Get the directory where this script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.route('/')
def index():
    """Serve the main HTML file."""
    try:
        return send_file(os.path.join(BASE_DIR, 'credential_reset/web/index.html'))
    except Exception as e:
        logger.error(f"Error serving HTML file: {e}")
        return f"Error: Could not find sonicwall_credential_reset_webapp.html in {BASE_DIR}", 404

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files (Python modules, etc.)."""
    try:
        logger.debug(f"Serving static file: {filename}")

        # First, check if the file exists in the web directory (for PyScript files)
        web_file_path = os.path.join(BASE_DIR, 'credential_reset/web', filename)
        if os.path.exists(web_file_path):
            logger.info(f"Serving file from web directory: {web_file_path}")
            return send_file(web_file_path)

        # Then check in the base directory for other files
        base_file_path = os.path.join(BASE_DIR, filename)
        if os.path.exists(base_file_path):
            logger.info(f"Serving file from base directory: {base_file_path}")
            return send_file(base_file_path)

        # File not found in either location
        logger.warning(f"File not found in web or base directory: {filename}")
        return f"File not found: {filename}", 404

    except Exception as e:
        logger.error(f"Error serving file {filename}: {e}")
        return f"Error serving file: {str(e)}", 500

@app.route('/proxy', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
def proxy():
    """
    Proxy endpoint that forwards requests to the target URL.
    The target URL should be provided in the 'target' query parameter.
    The HTTP method can be specified via X-Proxy-Method header.
    """
    # Handle preflight OPTIONS requests
    if request.method == 'OPTIONS':
        response = Response()
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, Accept, X-Proxy-Method, X-Proxy-Target'
        response.headers['Access-Control-Max-Age'] = '3600'
        return response

    # Get target URL from query parameter
    target_url = request.args.get('target')

    # Check for X-Proxy-Method header to determine the actual HTTP method to use
    # This allows GET requests to the proxy to be forwarded as POST/PUT/etc to the target
    proxy_method = request.headers.get('X-Proxy-Method', request.method).upper()

    if not target_url:
        return {'error': 'Missing target URL parameter'}, 400

    logger.info(f"Proxying {request.method} request as {proxy_method} to: {target_url}")
    logger.info(f"X-Proxy-Method header: {request.headers.get('X-Proxy-Method', 'Not set')}")

    try:
        # Build headers for the actual request
        # Filter out browser-specific headers and our custom proxy headers
        excluded_request_headers = ['host', 'connection', 'origin', 'referer', 'user-agent', 'x-proxy-method', 'x-proxy-target']
        headers = {
            key: value for key, value in request.headers
            if key.lower() not in excluded_request_headers
        }

        # Ensure we have the right Content-Type and Accept headers for SonicWall
        if proxy_method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            headers['Content-Type'] = 'application/json'

        # SonicWall expects this specific Accept header for all methods
        headers['Accept'] = 'application/json'

        # Remove any charset from Content-Type if present
        if 'Content-Type' in headers and ';' in headers['Content-Type']:
            headers['Content-Type'] = headers['Content-Type'].split(';')[0].strip()

        logger.info(f"Forwarding with method: {proxy_method}")
        logger.info(f"Request headers: {headers}")

        # Get request body
        body_data = request.get_data()

        # Log request body for debugging (only for methods that typically have a body)
        if proxy_method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            if body_data:
                logger.info(f"Request body: {body_data.decode('utf-8') if body_data else 'None'}")
            else:
                logger.info(f"Request body: Empty")

        logger.info(f"Making {proxy_method} request to: {target_url}")

        response = requests.request(
            method=proxy_method,
            url=target_url,
            headers=headers,
            data=body_data if body_data else None,
            cookies=request.cookies,
            allow_redirects=False,
            verify=False,  # Disable SSL verification for SonicWall devices
            timeout=30
        )

        logger.info(f"Response status: {response.status_code} {response.reason}")
        logger.info(f"Response headers: {dict(response.headers)}")

        # Log response body for debugging
        if response.content:
            try:
                logger.info(f"Response body preview: {response.content[:500].decode('utf-8', errors='ignore')}")
            except:
                logger.info(f"Response body size: {len(response.content)} bytes")

        # Create response with CORS headers
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        response_headers = [
            (name, value) for (name, value) in response.raw.headers.items()
            if name.lower() not in excluded_headers
        ]

        # Add CORS headers
        response_headers.append(('Access-Control-Allow-Origin', '*'))
        response_headers.append(('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS'))
        response_headers.append(('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With, Accept'))
        response_headers.append(('Access-Control-Expose-Headers', '*'))

        return Response(
            response.content,
            response.status_code,
            response_headers
        )

    except requests.exceptions.RequestException as e:
        logger.error(f"Proxy request failed: {e}")
        return {'error': str(e)}, 502


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint."""
    return {'status': 'ok', 'message': 'CORS Proxy Server is running'}


@app.route('/progress/<operation_id>')
def progress_stream(operation_id):
    """
    Server-Sent Events endpoint for streaming operation progress.

    Args:
        operation_id: Unique identifier for the operation to stream

    Returns:
        SSE stream with progress events
    """
    from common.progress_tracker import progress_manager

    def generate_progress_events():
        """Generator function for SSE events."""
        operation_queue = progress_manager.get_operation_queue(operation_id)

        if not operation_queue:
            # Operation doesn't exist, send error and close
            yield f"data: {json.dumps({'type': 'error', 'message': 'Operation not found'})}\n\n"
            return

        logger.info(f"Starting SSE stream for operation {operation_id}")

        try:
            while True:
                try:
                    # Get progress event from queue with timeout
                    event_data = operation_queue.get(timeout=30)

                    # Send the event as SSE
                    yield f"data: {json.dumps(event_data)}\n\n"

                    # Check if operation is complete
                    if event_data.get('type') == 'complete':
                        logger.info(f"Operation {operation_id} completed, ending SSE stream")
                        break

                except queue.Empty:
                    # Send keepalive ping
                    yield f"data: {json.dumps({'type': 'ping', 'timestamp': generate_timestamp()})}\n\n"
                    continue

        except Exception as e:
            logger.error(f"Error in SSE stream for operation {operation_id}: {e}")
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            # Clean up operation
            progress_manager.complete_operation(operation_id)
            logger.info(f"SSE stream ended for operation {operation_id}")

    return Response(
        generate_progress_events(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Cache-Control'
        }
    )


@app.route('/test_connection', methods=['POST'])
def test_connection():
    """Test connectivity using the operation engine with progress tracking."""
    logger.info(f"Received {request.method} -> {request.url}")
    if request.method == 'POST':
        try:
            # Extract JSON data from the request body
            data = request.get_json()
            if not data:
                logger.error("test_connection(): No JSON data received")
                return {'success': False, 'error': 'No data received', 'function': 'test_connection() 0'}, 400

            logger.info(f"test_connection(): Received data: {data}")

            # Import and use the SERVER operation engine (not PyScript engine)
            from credential_reset.server_engine import server_operation_engine

            # Execute connection test with the server engine
            result = server_operation_engine.execute_connection_test_sync(data)

            # Return the result in the expected format
            if result['success']:
                return {
                    'success': True,
                    'data': result['data'],
                    'firewall_info': result['firewall_info'],
                    'return_msg': result['return_msg']
                }, 200
            else:
                return {
                    'success': False,
                    'error': result['return_msg'],
                    'function': result['function']
                }, 400

        except Exception as e:
            logger.error(f"test_connection(): Error processing request: {e}")
            return {'success': False, 'error': str(e), 'function': 'test_connection() exception'}, 400

    return {'error': 'Method not supported'}, 405


@app.route('/single_analysis', methods=['POST'])
def single_analysis():
    """Execute security analysis using the server operation engine."""
    logger.info(f"Received {request.method} -> {request.url}")
    if request.method == 'POST':
        try:
            # Extract JSON data from the request body
            data = request.get_json()
            if not data:
                logger.error("single_analysis(): No JSON data received")
                return {'success': False, 'error': 'No data received', 'function': 'single_analysis() 0'}, 400

            logger.info(f"single_analysis(): Received data: {data}")

            # Import and use the SERVER operation engine
            from credential_reset.server_engine import server_operation_engine

            # Execute security analysis operation
            result = server_operation_engine.execute_single_target_operation(data, "analysis")

            # Return the result in the expected format
            if result['success']:
                return {
                    'success': True,
                    'results': result['results'],
                    'firewall_info': result.get('firewall_info'),
                    'operation_type': result['operation_type']
                }, 200
            else:
                return {
                    'success': False,
                    'errors': result['errors'],
                    'function': result['function']
                }, 400

        except Exception as e:
            logger.error(f"single_analysis(): Error processing request: {e}")
            return {'success': False, 'error': str(e), 'function': 'single_analysis() exception'}, 400

    return {'error': 'Method not supported'}, 405


@app.route('/single', methods=['POST', 'GET'])
def single_target():
    """Proxy endpoint that accepts the single target form data from the web app and triggers the routine for a single device."""
    logger.info(f"Received {request.method} -> {request.url}")
    if request.method == 'POST':
        try:
            # Extract JSON data from the request body (not form data)
            data = request.get_json()
            if not data:
                logger.error("single_target(): No JSON data received")
                return {'success': False, 'error': 'No data received', 'function': 'single_target() 0'}, 400
            logger.info(f"single_target(): Received data: {data}")

            # Load the target from form data
            target = load_targets(data)
            target_numbers = (1, 1)  # Single target (1 of 1)
            logger.info(target)

            errors = []
            if target.firewall is None or target.firewall.strip() == "":
                errors.append(f"Firewall IP/Hostname is required.")
            if target.username is None or target.username.strip() == "":
                errors.append(f"Username is required.")
            if target.password is None or target.password.strip() == "":
                errors.append(f"Password is required.")
            if errors:
                return {'success': False, 'error': "<br>".join(errors), 'function': 'single_target() 0.1'}, 400

            if target.sshport == 0:
                logger.info(f"SSH logic is disabled.")

            # Initialize a session with the firewall.
            api_session, return_msg, api_base, username, password = initialize_session(target,
                                                                                       target_numbers,
                                                                                       username=target.username,
                                                                                       password=target.password,
                                                                                       sshport=target.sshport)

            if api_session is None or api_session is False:
                logger.error(f"Unable to create an admin session. Return message: {return_msg}")

                # Write error results and return
                # routine_results[firewall] = dict(sorted(routine_results[firewall].items()))
                # results_str = json.dumps(routine_results[firewall], indent=4)
                # write_to_file(f"\n{results_str}\n", filename=f"{constants.START_TIMESTAMP_FOLDER}/{target_numbers[0]}results.txt")
                # return False, return_msg
                return {'success': False, 'error': return_msg, 'function': 'single_target(), 1'}, 400

            # Gather firewall information
            # TODO: Silent mode?
            firewall_info, error_msg = gather_firewall_info(api_session, api_base, target_numbers, silent=False)
            if firewall_info is None:
                logger.error(f"Error gathering firewall information: {error_msg}")
                return {'success': False, 'error': error_msg, 'function': 'single_target() 2'}, 400

            # Successfully connected and gathered info
            logger.info(f"Successfully connected to firewall: {firewall_info}")

            # TODO: Tagging the line... Logged in, got fw info... now what?


            # TODO: Tagging the line... Should be done with the single target routine here and may disable API if needed.

            # If we enabled SonicOS API via SSH, disable it now
            if constants.get_autoenabled_sonicos_api():
                firewall_info['api_autoenabled'] = True  # Flag for the web app to display conditional message
                disable_sonicos_api_ssh(target.firewall, target.sshport, username, password)

            # Log out from the session
            try:
                logout(api_base, api_session, firewall_generation=firewall_info.get('firewall_generation', None))
            except Exception as e:
                logger.error(f"Error logging out: {e}")

            # Reset auto-enabled SonicOS API flag for each new firewall
            if constants.get_autoenabled_sonicos_api() is True:
                constants.set_autoenabled_sonicos_api(False)

            return {'success': True, 'data': data, 'firewall_info': firewall_info, 'return_msg': return_msg}, 200
        except Exception as e:
            logger.error(f"test_connection(): Error processing request data: {e}")
            return {'success': False, 'error': str(e), 'function': 'test_connection() 3'}, 400
    return {'error': 'Method not supported'}, 405


@app.route('/test_connection_with_progress', methods=['POST'])
def test_connection_with_progress():
    """Test connectivity with real-time progress streaming via SSE."""
    logger.info(f"Received {request.method} -> {request.url}")

    try:
        # Extract JSON data from the request body
        data = request.get_json()
        if not data:
            logger.error("test_connection_with_progress(): No JSON data received")
            return {'success': False, 'error': 'No data received'}, 400

        logger.info(f"test_connection_with_progress(): Received data for {data.get('firewall', 'unknown')}")

        # Generate unique operation ID
        operation_id = str(uuid.uuid4())

        # Import progress manager and create operation
        from common.progress_tracker import progress_manager
        from credential_reset.server_engine import server_operation_engine

        # Create progress tracker for this operation (5 main steps for connection test)
        progress_tracker = progress_manager.create_operation(operation_id, total_steps=5)

        def run_connection_test():
            """Run the connection test in a separate thread with progress tracking."""
            try:
                # Execute connection test with progress tracking
                # The server engine will handle all progress updates and completion
                result = server_operation_engine.execute_connection_test_sync(data, operation_id)

                # No need to call progress_tracker.complete() here - server engine handles it
                # The result_data is automatically included in the SSE completion event

            except Exception as e:
                logger.error(f"Connection test thread error: {e}")
                # Only handle exceptions not caught by server engine
                from common.progress_tracker import progress_manager
                operation_data = progress_manager.active_operations.get(operation_id)
                if operation_data:
                    tracker = operation_data["tracker"]
                    error_result = {
                        "success": False,
                        "error": str(e),
                        "function": "run_connection_test"
                    }
                    tracker.complete(success=False, message=f"Connection test failed: {str(e)}", result_data=error_result)

        # Start the connection test in a background thread
        test_thread = threading.Thread(target=run_connection_test, daemon=True)
        test_thread.start()

        # Return operation ID immediately so client can start SSE stream
        return {
            'success': True,
            'operation_id': operation_id,
            'message': 'Connection test started, use operation_id to stream progress'
        }, 200

    except Exception as e:
        logger.error(f"test_connection_with_progress(): Error processing request: {e}")
        return {'success': False, 'error': str(e)}, 400


def main():
    parser = argparse.ArgumentParser(description='CORS Proxy Server for SonicWall Web App')
    parser.add_argument('--port', type=int, default=8080, help='Port to run the proxy server on (default: 8080)')
    parser.add_argument('--host', type=str, default='127.0.0.1', help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')

    args = parser.parse_args()

    logger.info("="*60)
    logger.info("CORS Proxy Server for SonicWall Web App")
    logger.info("="*60)
    logger.info(f"Starting proxy server on http://{args.host}:{args.port}")
    logger.info(f"Web App: http://{args.host}:{args.port}/")
    logger.info(f"Proxy endpoint: http://{args.host}:{args.port}/proxy?target=YOUR_URL")
    logger.info(f"Health check: http://{args.host}:{args.port}/health")
    logger.info("="*60)
    logger.info(f"Serving files from: {BASE_DIR}")
    logger.info("="*60)
    logger.info("Press Ctrl+C to stop the server")
    logger.info("")

    try:
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("\nShutting down proxy server...")
        sys.exit(0)

def load_targets(target_input) -> Union[List[FirewallTarget], FirewallTarget]:
    """Load targets from either CSV file or single target data."""
    if not isinstance(target_input, dict) and path.isfile(target_input):
        logger.info(f"Loading targets from {target_input}")
        return parse_csv_targets(target_input)
    elif isinstance(target_input, dict):
        # Target came from web form data
        logger.debug(f"Target came from web form: {target_input}")
        return FirewallTarget(
            firewall=target_input.get('firewall'),
            username=target_input.get('username'),
            password=normalize_password(password=target_input.get('password')),
            sshport=target_input.get('sshport'),
            temp_password=normalize_temp_password(password=target_input.get('temp_password'),
                                                  randomize=normalize_boolean(target_input.get('randomize_temp_password'))),
            randomize_temp_password=normalize_boolean(target_input.get('randomize_temp_password')),
            unbind_totp=normalize_boolean(target_input.get('unbind_totp')),
            force_password_change=normalize_boolean(target_input.get('force_password_change'))
        )
    else:
        # Single target from command line - this case may need proper args handling
        logger.info(f"Target came from CLI: {target_input}")
        # For now, return a basic FirewallTarget - this needs proper CLI args integration
        return FirewallTarget(
            firewall=target_input,
            sshport=22,  # Default SSH port
            temp_password="",
            randomize_temp_password=False,
            unbind_totp=False,
            force_password_change=False
        )

# TODO: Integrate argument parsing with web form data handling
def print_and_save_summary(results: dict, firewall: str, firewall_info: dict, output_folder: str):
    """Print summary table to console and save markdown report to file."""
    try:
        if not a.no_summary:
            generate_summary_table(results, a)
    except Exception as e:
        print(f"Error printing summary table: {e}")

    try:
        # Generate and save markdown report
        md_content = generate_markdown_summary(results, firewall, firewall_info, a)

        dm = firewall_info['device_model'].replace(" ", "")
        sn = firewall_info['serial_number']
        md_filename = f"{output_folder}/{dm}-{sn}-summary.md"

        try:
            write_to_file(md_content, filename=md_filename)
            print(f"\n{generate_timestamp()}: Summary report saved to {md_filename}\n")
        except Exception as e:
            print(f"Error writing markdown summary to file: {e}")

    except Exception as err:
        print(f"Error generating markdown summary: {err}")


def finalize_routine(api_session, api_base: str, firewall: str, firewall_generation: int,
                    sshport: str, username: str, password: str, target_numbers: tuple, firewall_info: dict):
    """Finalize routine by cleaning up, writing results, and logging out."""
    # Sort results for consistency
    routine_results[firewall] = dict(sorted(routine_results[firewall].items()))

    # Generate and print summary
    print_and_save_summary(routine_results[firewall], firewall, firewall_info, constants.START_TIMESTAMP_FOLDER)

    # Write results to file
    results_str = json.dumps(routine_results[firewall], indent=4)
    results_str = "\n" + results_str + "\n"

    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    write_to_file(results_str, filename=f"{constants.START_TIMESTAMP_FOLDER}/{dm}-{sn}-results.txt")

    # Disable auto-enabled SonicOS API if needed
    if constants.get_autoenabled_sonicos_api():
        disable_sonicos_api_ssh(firewall, sshport, username, password)

    # Logout from session
    try:
        logout(api_base, api_session, firewall_generation=firewall_generation)
    except KeyboardInterrupt:
        print(f"\nStopped!")
        exit()
    except Exception as e:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Error logging out: {e}")


if __name__ == '__main__':
    main()
