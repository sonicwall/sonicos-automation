from collections import OrderedDict
from datetime import datetime
from codecs import decode as dc
from hashlib import md5
import json
import requests
import urllib3
import base64
from common.utils import generate_timestamp
from common.arguments import a
from common.ssh import connect_ssh, send_cmd
from common.config import config
from common.constants import (
	get_fw_generation,
	set_autoenabled_sonicos_api,
	SKIP_TO_NTH_COMMIT,
	PROMPT_LEVEL,
	AUTOENABLED_SONICOS_API
)


# Hide the certificate warnings.
def hide_certificate_warnings():
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Good headers to use with SonicOS API.
sonicos_api_headers = OrderedDict([
	('Accept', 'application/json'),
	('Content-Type', 'application/json'),
	('Accept-Encoding', 'application/json'),
	('charset', 'UTF-8')])


# Calculate input timestamp delta
# Ex: 2020-12-22 23:51:59.664
def calculate_timedelta(first_time, last_time):
	first_time = datetime.strptime(first_time, '%Y-%m-%d %H:%M:%S.%f')
	last_time = datetime.strptime(last_time, '%Y-%m-%d %H:%M:%S.%f')

	# Calculate the time delta
	td = last_time - first_time

	# Return the time delta string.
	return td


# HTTP response printing
# Print response information
def print_response_info(resp, override_verbose=False, **kwargs):
	"""
	Prints the response information.
	:param resp: Requests response object.
	:param override_verbose: Override the verbose setting (make it verbose even if not set).
	:param kwargs: Optional arguments.
	:return: JSON response and string response (or None).
	"""
	if override_verbose is True:
		a.verbose = True
	print()
	if 'obj_name' in kwargs:
		print(f"Object: {kwargs['obj_name']}")
	request_method = str(resp.request).split()[-1].strip("[]>")
	print(f"Request: {request_method} -> {resp.url}")
	print(f"Status Code: {resp.status_code} {resp.reason}")
	if a.verbose:
		if 'start_time' in kwargs:
			print(f"Request took {calculate_timedelta(kwargs['start_time'], generate_timestamp(split=False))}")
	# try:
	if a.verbose:
		print("SonicOS Response:")

	# Try to decode the response as JSON.
	try:
		r = resp.json()
		r_string = None

	# If the response isn't JSON, try to decode it as a string.
	except Exception as e:
		r = resp.content
		r = r.decode()
		r_string = None

		# Extract JSON from the end of the string if possible.
		if '{"' in r.split("\n")[-1]:
			# Remove the JSON from the end of the string.
			r_string = r.split("\n")[:-1]
			r_string = "" + "\n".join(r_string)

			# Extract the JSON from the end of the string.
			r = r.split("\n")[-1]
			r = json.loads(r)

	if r_string:
		if a.verbose:
			print(f"{r_string}")
	try:
		if r.get("status", None):
			for k, v in r['status'].items():
				if k == "info":
					if a.verbose:
						print("- Info:")
					for i in v[0]:
						if a.verbose:
							print(f"-- {i.title()}: {v[0][i]}")
				# print()
				if k == "cli":
					if a.verbose:
						print("- CLI:")
					for i in v:
						if a.verbose:
							print(f"-- {i.title()}: {v[i]}")
		else:
			if a.verbose:
				print(r)
	except KeyError as e:
		print(f"{generate_timestamp()}: KeyError (1): {e}")
	except AttributeError as e:
		# print(f"{generate_timestamp()}: AttributeError: {e}")
		print(f"{generate_timestamp()}: Response: {resp.content}")
	print()
	if override_verbose is True:
		a.verbose = False
	return r, r_string


# SonicOS API
# Encode credentials
def encoded_credentials(user_name, password):
	user_name = bytes(user_name, 'utf-8')
	password = bytes(password, 'utf-8')
	encoded_credentials = base64.b64encode(user_name + b":" + password)
	encoded_credentials = encoded_credentials.decode('utf-8')
	return encoded_credentials


# Create the admin session and return a session object for later use.
def create_admin_session(firewall, admin_user, admin_password, sshport='22'):
	# Get Timestamp
	start_time = generate_timestamp(split=False)

	# Headers
	auth_headers = OrderedDict([
		('Accept', 'application/json'),
		('Content-Type', 'application/json'),
		('Accept-Encoding', 'application/json'),
		('charset', 'UTF-8'),
		('Authorization', f'Basic {encoded_credentials(admin_user, admin_password)}')])

	# Override existing SonicOS API login. This should avoid logging in as non-config.
	override = {'override': True}

	# Create a session and POST a login.
	session = requests.Session()
	auth_resp = session.post(firewall + '/api/sonicos/auth',
							 headers=auth_headers,
							 verify=False,
							 json=override)

	# print_response_info(auth_resp, start_time=start_time)

	# Return a session object
	if not auth_resp.status_code == requests.codes.ok:
		sonicos_api_disabled = False
		sonicos_digest_enabled = False
		try:
			resp_json = auth_resp.json()
			message = resp_json['status']['info'][0]['message']
			print(f"{generate_timestamp()}: Failed to establish an administration session using Basic auth. (HTTP {auth_resp.status_code}): {resp_json['status']['info'][0]['code']} -- {message}")

			# When the SonicOS API is disabled, response is HTTP 403 with code E_DISABLED and message "Service disabled.".
			if "service disabled" in message.lower():
				print(f"{generate_timestamp()}: SonicOS API is disabled. Trying to enable it *temporarily* via SSH Management.")
				sonicos_api_disabled = True
		except Exception as e:
			resp_json = auth_resp.content
			print(f"{generate_timestamp()}: Failed to establish an administration session using Basic auth. (HTTP {auth_resp.status_code}):\n{resp_json}\n")

			# When the target is a GEN5, there's a 404 at /api/sonicos/auth.
			if "not found" in str(resp_json).lower():
				print(f"{generate_timestamp()}: Please make sure the target firewall is a SonicWall GEN6 or GEN7 firewall.")
				return "E_GEN5", str(resp_json)

			# When the SonicOS API is disabled, response is HTTP 403 with code E_DISABLED and message "Service disabled.".
			if resp_json == b'' and auth_resp.status_code == 401:
				# When digest is enabled there may be a 401 response.
				# This is a mechanism to flag that digest is enabled and try to disable it via SSH.
				# May not be needed anymore since simply handling the bytes response is enough to allow the CHAP auth failover.
				sonicos_digest_enabled = True
			elif "service disabled" in resp_json.lower():
				print(f"{generate_timestamp()}: SonicOS API is disabled. Trying to enable it *temporarily* via SSH Management.")
				sonicos_api_disabled = True

		# If the SonicOS API is disabled, we'll try to use SSH Management to enable it.
		if sonicos_api_disabled:
			if sonicos_digest_enabled:
				# Try to enable the SonicOS API via SSH Management.
				enabled = enable_sonicos_api_ssh(firewall, sshport, admin_user, admin_password, disable_digest=True)
			else:
				# Try to enable the SonicOS API via SSH Management.
				enabled = enable_sonicos_api_ssh(firewall, sshport, admin_user, admin_password)
			if enabled is True:
				return "E_DISABLED", resp_json
			if enabled is False:
				return "E_GIVE_UP", resp_json
			else:
				return None, resp_json

		return None, resp_json
		# exit()
	else:
		resp_json = auth_resp.json()
		print(f"{generate_timestamp()}: Logged in via SonicAPI using Basic auth! (HTTP {auth_resp.status_code}): {resp_json['status']['info'][0]['code']} -- {resp_json['status']['info'][0]['message']}")
	return session, resp_json


# Create an admin session (CHAP MD5 Digest) and return a session object for later use.
def create_admin_session_chap(firewall, admin_user, admin_password, sshport='22'):
	# Get Timestamp
	start_time = generate_timestamp(split=False)

	# Headers for the API
	headers = OrderedDict([
		('Accept', 'application/json'),
		('Content-Type', 'application/json'),
		('Accept-Encoding', 'application/json'),
		('charset', 'UTF-8')
	])

	# Create a CHAP digest.
	chap_digest = md5()

	# Send the GET request to get the ID and Challenge
	req = requests.get(firewall + '/api/sonicos/auth',
					   headers=headers,
					   verify=False)

	# print_response_info(req, start_time=start_time)

	# Grab the JSON response
	try:
		response_json = req.json()
	except json.JSONDecodeError:
		# This exception is hit when an admin is logged into SonicOS and the API is accessed.
		print(f"{generate_timestamp()}: Failed to decode JSON response. (HTTP {req.status_code}): {req.content}")
		print(f"{generate_timestamp()}: Log out of SonicOS, wait a few seconds, and re-try. (HTTP {req.status_code}): {req.content}")
		exit()

	# Extract the ID and Challenge
	id_val = response_json['id']
	challenge_val = response_json['challenge']

	# Convert them to Hex
	id_hex = dc(id_val, "hex")
	challenge_hex = dc(challenge_val, "hex")

	# Update the CHAP digest with the following:
	# ID string returned in the GET request (in Hex)
	# SonicOS management password encoded to UTF-8 (documentation says "credentials"--just need the password)
	# Challenge returned in the GET request (in Hex)
	chap_digest.update(id_hex)
	chap_digest.update(admin_password.encode("utf-8"))
	chap_digest.update(challenge_hex)
	chap_digest.digest()

	# Create the final digest
	digest = chap_digest.hexdigest()

	# Get Timestamp
	start_time = generate_timestamp(split=False)

	# Data to send to the API
	req_data = {
		"override": True,
		"id": id_val,
		"user": admin_user,
		"digest": digest
	}

	# Send the auth POST
	session = requests.Session()
	auth_resp = session.post(firewall + '/api/sonicos/auth',
					   data=json.dumps(req_data),
					   headers=headers,
					   verify=False)
	# print(json.dumps(auth_resp.json(), indent=4))

	# print_response_info(auth_resp, start_time=start_time)

	# Return a session object
	if not auth_resp.status_code == requests.codes.ok:
		sonicos_api_disabled = False
		try:
			resp_json = auth_resp.json()
			message = resp_json['status']['info'][0]['message'].strip()
			print(f"{generate_timestamp()}: Failed to establish an administration session. (HTTP {auth_resp.status_code}): {resp_json['status']['info'][0]['code']} -- {message}")

			# When the SonicOS API is disabled, response is HTTP 403 with code E_DISABLED and message "Service disabled.".
			if "service disabled" in message.lower():
				print(f"{generate_timestamp()}: SonicOS API is disabled. Trying to enable it *temporarily* via SSH Management.")
				sonicos_api_disabled = True
		except:
			resp_json = auth_resp.content
			print(f"{generate_timestamp()}: Failed to establish an administration session. (HTTP {auth_resp.status_code}): {resp_json}")

			# When the SonicOS API is disabled, response is HTTP 403 with code E_DISABLED and message "Service disabled.".
			if "service disabled" in resp_json.lower():
				print(f"{generate_timestamp()}: SonicOS API is disabled. Trying to enable it *temporarily* via SSH Management.")
				sonicos_api_disabled = True

		# If the SonicOS API is disabled, we'll try to use SSH Management to enable it.
		if sonicos_api_disabled:
			# Try to enable the SonicOS API via SSH Management.
			enable_sonicos_api_ssh(firewall, sshport, admin_user, admin_password)
		return None, resp_json
		# exit()
	else:
		resp_json = auth_resp.json()
		print(f"{generate_timestamp()}: Logged in via SonicOS API using CHAP MD5 Digest auth! (HTTP {auth_resp.status_code}): {resp_json['status']['info'][0]['code']} -- {resp_json['status']['info'][0]['message']}")

		# Checks for the auth_code received when logging in for the first time.
		if resp_json.get("status", {}).get("info", [{"auth_code": ""}])[0]["auth_code"] == "API_AUTH_PASSWORD_UPDATE":
#			print(f"Password change required. Please change your password.\n")
			return Exception("Password change required. Please change the firewall's password and update the configuration file.")
	return session, resp_json


# Generic GET request
def get_request(fw, session, api_path):
	start_time = generate_timestamp(split=False)
	resp = session.get(fw + api_path, headers=sonicos_api_headers, verify=False)
	print_response_info(resp, start_time=start_time)
	try:
		return resp.json()
	except json.JSONDecodeError:
		return resp.content


# Generic POST request
def post_request(fw, session, api_path, data):
	start_time = generate_timestamp(split=False)
	resp = session.post(fw + api_path, headers=sonicos_api_headers, verify=False, json=data)
	print_response_info(resp, start_time=start_time)
	return resp.json()


# Generic PUT request
def put_request(fw, session, api_path, data):
	start_time = generate_timestamp(split=False)
	resp = session.put(fw + api_path, headers=sonicos_api_headers, verify=False, json=data)
	print_response_info(resp, start_time=start_time)
	return resp.json()


# Generic PATCH request
def patch_request(fw, session, api_path, data):
	start_time = generate_timestamp(split=False)
	resp = session.patch(fw + api_path, headers=sonicos_api_headers, verify=False, json=data)
	print_response_info(resp, start_time=start_time)
	return resp.json()


# Commit pending changes to the firewall via SonicOS API.
def commit_pending(fw, session):
	start_time = generate_timestamp(split=False)
	resp = session.post(fw + '/api/sonicos/config/pending',
						headers=sonicos_api_headers,
						verify=False)
	# print_response_info(resp, start_time=start_time)

	# If the commit succeeds, return the response JSON.
	if resp.status_code == requests.codes.ok:
		print(f"{generate_timestamp()}: Commit action successful! (HTTP {resp.status_code}): {resp.json()['status']['info'][0]['code']} -- {resp.json()['status']['info'][0]['message']}\n")
		return resp.json()


# Log out of the API session.
def logout(fw, session):
	start_time = generate_timestamp(split=False)
	resp = session.delete(fw + '/api/sonicos/auth',
						headers=sonicos_api_headers,
						verify=False)
	# print_response_info(resp, start_time=start_time)

	# If the logout succeeds, return the response JSON.
	if resp.status_code == requests.codes.ok:
		print(f"{generate_timestamp()}: Logged out successfully! (HTTP {resp.status_code}): {resp.json()['status']['info'][0]['code']} -- {resp.json()['status']['info'][0]['message']}")
		return resp.json()


# Downloads the tech support report (TSR) from the firewall.
# For GEN7, there is an endpoint to download it. For GEN6 we need to use the /direct/cli endpoint.
def download_tsr(fw, session, filepath, firewall_generation=None):
	start_time = generate_timestamp(split=False)
	endpoint = '/api/sonicos/direct/cli'
	if firewall_generation == 6:
		endpoint = '/api/sonicos/direct/cli'
	elif firewall_generation == 7:
		endpoint = '/api/sonicos/export/tech-support-report'

	resp = None
	try:
		if firewall_generation == 6:
			# Update the Content-Type request header to plain/text.
			sonicos_api_headers['Content-Type'] = 'text/plain'

			resp = session.post(fw + endpoint,
								headers=sonicos_api_headers,
								data="show tech-support-report",
								verify=False)

			# Set the Content-Type header back to application/json.
			sonicos_api_headers['Content-Type'] = 'application/json'

		elif firewall_generation == 7:
			resp = session.get(fw + endpoint, headers=sonicos_api_headers, verify=False)
		# print_response_info(resp, start_time=start_time)
	except Exception as e:
		print(f"{generate_timestamp()}: Error downloading TSR: {e}")
		return False

	if resp:
		if resp.status_code == requests.codes.ok:
			try:
				with open(filepath, 'wb') as file:
					file.write(resp.content)
			except Exception as e:
				print(f"{generate_timestamp()}: Error writing TSR to file: {e}")
				return False

			print(f"{generate_timestamp()}: TSR download successful!")
			return True
		else:
			print(f"{generate_timestamp()}: Error downloading TSR: {resp.json()['status']['info'][0]['code']} -- {resp.json()['status']['info'][0]['message']}")
			return False


# Downloads the trace logs from the firewall.
# For GEN7, there is an endpoint to download it. For GEN6 we need to use the /direct/cli endpoint.
def download_tracelog(fw, session, filepath, log_selection="current", firewall_generation=None):
	start_time = generate_timestamp(split=False)
	endpoint = '/api/sonicos/direct/cli'

	if log_selection == "all":
		log_selection = "current"

	if firewall_generation == 6:
		endpoint = '/api/sonicos/direct/cli'
	elif firewall_generation == 7:
		endpoint = f'/api/sonicos/export/trace-log/{log_selection}'

	resp = None
	try:
		if firewall_generation == 6:
			# Update the Content-Type request header to plain/text.
			sonicos_api_headers['Content-Type'] = 'text/plain'

			resp = session.post(fw + endpoint,
								headers=sonicos_api_headers,
								data=f"diag show tracelog {log_selection}",
								verify=False)
			# print_response_info(resp, start_time=start_time)

			# Set the Content-Type header back to application/json.
			sonicos_api_headers['Content-Type'] = 'application/json'

		elif firewall_generation == 7:
			resp = session.get(fw + endpoint, headers=sonicos_api_headers, verify=False)
			# print_response_info(resp, start_time=start_time)
	except Exception as e:
		print(f"{generate_timestamp()}: Error downloading trace log: {e}")
		return False

	if resp:
		if resp.status_code == requests.codes.ok:
			try:
				with open(filepath, 'wb') as file:
					file.write(resp.content)
			except Exception as e:
				print(f"{generate_timestamp()}: Error writing trace log to file: {e}")
				return False

			print(f"{generate_timestamp()}: Trace log download successful!")
			return True
		else:
			print(f"{generate_timestamp()}: Error downloading trace log: HTTP {resp.status_code} -  {resp.json()['status']['info'][0]['code']} -- {resp.json()['status']['info'][0]['message']}")
			return False


# Upload a firmware image to the firewall via SonicOS API.
def upload_firmware(fw, session, filepath, firewall_generation=None):
	start_time = generate_timestamp(split=False)

	filename = filepath.split("/")[-1]

	# Opens the file, reads it into memory, and uploads it to the firewall.
	with open(filename, 'rb') as file:
		endpoint = '/api/sonicos/import/firmware'
		if firewall_generation == 6:
			endpoint = '/upload.cgi?safeMode=1'
		try:
			response = session.post(fw + endpoint,
									files=dict(firmware=(filename, file, 'application/octet-stream')),
									verify=False)
			print_response_info(response, start_time=start_time, override_verbose=True)
		except Exception as e:
			print(f"{generate_timestamp()}: Error uploading firmware: {e}")
			return False


# Boot uploaded firmware
def boot_firmware(fw, session, firewall_generation=None):
	start_time = generate_timestamp(split=False)
	endpoint = '/api/sonicos/boot/uploaded'
	if firewall_generation == 6:
		# Placeholder for GEN6 boot.
		endpoint = ''

	try:
		resp = session.post(fw + endpoint,
							headers=sonicos_api_headers,
							verify=False)
		print_response_info(resp, start_time=start_time, override_verbose=True)
	except Exception as e:
		print(f"{generate_timestamp()}: Error booting firmware: {e}")
		return False

	# If the boot succeeds, return the response JSON.
	if resp.status_code == requests.codes.ok:
		print(f"{generate_timestamp()}: Boot action successful! (HTTP {resp.status_code}): {resp.json()['status']['info'][0]['code']} -- {resp.json()['status']['info'][0]['message']}")
		return resp.json()
	else:
		print(f"{generate_timestamp()}: Error booting firmware: {resp.json()['status']['info'][0]['code']} -- {resp.json()['status']['info'][0]['message']}")
		return False


# Get the current state of Botnet Filtering.
def check_botnet_status(fw, session, firewall_generation=None):
	start_time = generate_timestamp(split=False)
	endpoint = '/api/sonicos/botnet/base'
	if firewall_generation == 6:
		endpoint = '/api/sonicos/botnet/global'
	elif firewall_generation == 7:
		endpoint = '/api/sonicos/botnet/base'

	try:
		resp = session.get(fw + endpoint, headers=sonicos_api_headers, verify=False)
		r = resp.json()

		for kv in r.get("status", {}).get("info", []):
			for key, value in kv.items():
				if "Licensing must be activated" in value:
					botnet_message = value
					print(f"{generate_timestamp()}: Botnet Filtering is not licensed. {botnet_message}")
					return {"status": "error", "license_status": "not_licensed", "message": botnet_message, "response": r}

		if firewall_generation == 6:
			# This logic: If botnet is disabled (either mode). Hits if either mode is enabled.
			if r.get("botnet", {}).get("block", {}).get("connections", {}).get("all", False) or	r.get("botnet", {}).get("block", {}).get("connections", {}).get("firewall_rule_based", False):
				# print(f"{generate_timestamp()}: Botnet Filtering is enabled.")
				return {"status": "enabled", "license_status": "licensed", "message": "", "response": r}

			# This logic: If botnet is enabled (no modes)
			elif r.get("botnet", {}).get("block", {}).get("connections", {}) == {}:
				# print(f"{generate_timestamp()}: Botnet Filtering is disabled.")
				return {"status": "disabled", "license_status": "licensed", "message": "", "response": r}

		elif firewall_generation == 7:
			if r.get("botnet", {}).get("block", {}).get("connections", {}).get("enable", False) is True:
				# print(f"{generate_timestamp()}: Botnet Filtering is enabled.")
				return {"status": "enabled", "license_status": "licensed", "message": "", "response": r}
			elif r.get("botnet", {}).get("block", {}).get("connections", {}).get("enable", False) is False:
				return {"status": "disabled", "license_status": "licensed", "message": "", "response": r}
		else:
			# print(f"{generate_timestamp()}: Botnet Filtering is disabled.")
			return {"status": "disabled", "license_status": "licensed", "message": "", "response": r}

	except Exception as e:
		print(f"{generate_timestamp()}: Error checking Botnet status (1): {e}")
		return {"status": "error", "license_status": "unknown", "message": e}


# Checks if TOTP is enabled on the input group name.
def check_totp_status(fw, session, group_name, enable_totp=False, firewall_generation=None):
	start_time = generate_timestamp(split=False)
	endpoint = '/api/sonicos/user/local/groups/name/'
	if firewall_generation == 6:
		endpoint = f'/api/sonicos/user/local/group/name/{group_name.replace(" ", "%20")}'
	elif firewall_generation == 7:
		endpoint = f'/api/sonicos/user/local/groups/name/{group_name.replace(" ", "%20")}'

	try:
		resp = session.get(fw + endpoint, headers=sonicos_api_headers, verify=False)
		r = resp.json()
		groups = r.get("user", {}).get("local", {}).get("group", [{}])

		for c, g in enumerate(groups):
			if g.get("name", "").lower() == group_name.lower():
				otp = g.get("one_time_password")
				email_based = otp.get("otp", False)
				app_based = otp.get("totp", False)

				selected_otp = ""
				if app_based:
					selected_otp = "App-based TOTP"
				elif email_based:
					selected_otp = "Email-based OTP"

				if otp == {}:
					# print(f"{generate_timestamp()}: TOTP/OTP is disabled for {g['name']}")
					if not enable_totp:
						return {"status": "disabled", "mode": selected_otp, "autoenabled": False, "group_name": g['name']}

				elif app_based or email_based:
					# print(f"{generate_timestamp()}: {selected_otp} is enabled for {g['name']}")
					enable_totp = False
					return {"status": "enabled", "mode": selected_otp, "autoenabled": False, "group_name": g['name']}

				if enable_totp:
					print(f"{generate_timestamp()}: Enabling TOTP for {g['name']}")

					r['user']['local']['group'][c]["one_time_password"] = {"totp": True}

					enable_totp_response = {}
					if firewall_generation == 6:
						endpoint = f'/api/sonicos/user/local/group/name/{group_name.replace(" ", "%20")}'
						enable_totp_response = put_request(fw, session, endpoint, r)
						# print("\n\n--------")
						# print(enable_totp_response)
						# print("-------\n\n")

					elif firewall_generation == 7:
						endpoint = f'/api/sonicos/user/local/groups/name/{group_name.replace(" ", "%20")}'
						enable_totp_response = patch_request(fw, session, endpoint, r)


					if enable_totp_response.get('status', {}).get('success', False) is False:
						err = enable_totp_response.get("status", {}).get("info", [{}])[0].get('message', "")
						print(f"{generate_timestamp()}: Error enabling TOTP on {group_name}")
						return {"status": "disabled",
								"mode": "",
								"autoenabled": False,
								"group_name": g['name'],
								"message": err,
								"response": enable_totp_response,
								"try_ssh": True}

					# Commit the changes.
					commit_pending(fw, session)

					return {"status": "enabled", "mode": "App-based TOTP", "autoenabled": True, "group_name": g['name']}

	except Exception as e:
		print(f"{generate_timestamp()}: Error checking TOTP status (1): {e}")
		return {"status": "error", "autoenabled": False, "message": "Error checking MFA status.", "response": e}


# Enable the SonicOS API via SSH Management.
def enable_sonicos_api_ssh(fw, sshport, admin_user, admin_password, disable_digest=False):
	print(f"{generate_timestamp()}: Enabling SonicOS API *temporarily* via SSH Management.")
	print(f"{generate_timestamp()}: The script will automatically log out after applying changes.")

	# This prepares the SSH target.
	fw = fw.strip("https://").split(":")[0]
	# fw = fw + ":" + str(sshport)

	# Connect to the firewall.
	try:
		ssh, ssh_conn = connect_ssh(fw,
									sshport,
									soniccore_user=admin_user,
									soniccore_pass=admin_password,
									sonicos_user=admin_user,
									sonicos_pass=admin_password,
									soniccore_prelogin=False)
	except KeyboardInterrupt:
		print(f"{generate_timestamp()}: Stopped!")
		exit()
	except KeyError as e:
		print(f"{generate_timestamp()}: KeyError: Either ({e}) is missing or the configuration is invalid/not found.")
		# exit()
		return False
	except Exception as e:
		print(f"{generate_timestamp()}: Error (2):", str(e))
		# exit()
		return False

	# Command list for enabling the SonicOS API.
	command_list = [
		"administration",
		"sonicos-api",
		"enable",
		"basic",
		"chap",
		"commit",
		"end",
		"exit",
		"exit",
	]

	# Commands vary slightly from one generation to another.
	# This replaces the command list with the appropriate one for the firewall generation.
	if get_fw_generation() is not None:
		if get_fw_generation() == 7:
			# This is the list of commands to enable the SonicOS API in GEN7.
			command_list = [
				"administration",
				"sonicos-api",
				"enable",
				"basic",
				"chap",
				"commit",
				"end",
				"exit",
				"exit",
			]
		elif get_fw_generation() == 6:
			# This is the list of commands to enable the SonicOS API in GEN6.
			command_list = [
				"administration",
				"sonicos-api",
				"basic",
				"chap",
				"commit",
				"end",
				"exit",
				"exit",
			]

	# if disable_digest is True, insert the commands to disable CHAP at index 3.
	if disable_digest:
		command_list.insert(3, "no digest")

	print(f"{generate_timestamp()}: Attempting to enable SonicOS API...")

	cnt = 0
	for cmd in command_list:
		# Send commands to the firewall and write the output to separate files.
		try:
			send_cmd(ssh, cmd + "\r", get_cmd_response=True, silent=True)
			cnt += 1
		except KeyboardInterrupt:
			ssh.close()
			ssh_conn.close()
			print(f"{generate_timestamp()}: Stopped!")
			exit()

	print(f"{generate_timestamp()}: SonicOS API should now be enabled.")
	set_autoenabled_sonicos_api(True)

	# Close the SSH session.
	ssh.close()
	ssh_conn.close()

	return True


# Disable the SonicOS API via SSH Management.
def disable_sonicos_api_ssh(fw, sshport, admin_user, admin_password):
	print(f"{generate_timestamp()}: Disabling SonicOS API via SSH Management.")
	print(f"{generate_timestamp()}: The script will automatically log out after applying changes.")

	# This prepares the SSH target.
	fw = fw.strip("https://").split(":")[0]
	# fw = fw + ":" + str(sshport)

	# Connect to the firewall.
	try:
		ssh, ssh_conn = connect_ssh(fw,
									sshport,
									soniccore_user=admin_user,
									soniccore_pass=admin_password,
									sonicos_user=admin_user,
									sonicos_pass=admin_password,
									soniccore_prelogin=False)
	except KeyboardInterrupt:
		print(f"{generate_timestamp()}: Stopped!")
		exit()
	except KeyError as e:
		print(f"{generate_timestamp()}: KeyError: Either ({e}) is missing or the configuration is invalid/not found.")
		# exit()
		return False
	except Exception as e:
		print(f"{generate_timestamp()}: Error with SSH connection (3):", str(e))
		# exit()
		return False

	# Command list for enabling the SonicOS API.
	command_list = [
		"administration",
		"sonicos-api",
		"no enable",
		"no basic",
		"no chap",
		"commit",
		"end",
		"exit",
		"exit",
	]

	# Commands vary slightly from one generation to another.
	# This replaces the command list with the appropriate one for the firewall generation.
	if get_fw_generation() is not None:
		if get_fw_generation() == 7:
			# This is the list of commands to disable the SonicOS API in GEN7.
			command_list = [
				"administration",
				"sonicos-api",
				"no enable",
				"no basic",
				"no chap",
				"commit",
				"end",
				"exit",
				"exit",
			]
		elif get_fw_generation() == 6:
			# This is the list of commands to disable the SonicOS API in GEN6.
			command_list = [
				"administration",
				"sonicos-api",
				"no basic",
				"no chap",
				"commit",
				"exit",
				"no sonicos-api",
				"commit",
				"end",
				"exit",
				"exit",
			]

	print(f"{generate_timestamp()}: Attempting to disable SonicOS API...")

	cnt = 0
	for cmd in command_list:
		# Send commands to the firewall and write the output to separate files.
		try:
			send_cmd(ssh, cmd + "\r", get_cmd_response=True, silent=True)
			cnt += 1
		except KeyboardInterrupt:
			ssh.close()
			ssh_conn.close()
			print(f"{generate_timestamp()}: Stopped!")
			exit()

	print(f"{generate_timestamp()}: SonicOS API disabled!")

	# Close the SSH session.
	ssh.close()
	ssh_conn.close()

	return True


# Get firmware version using 'show version' command via SSH.
def get_firmware_version_ssh(fw, sshport, admin_user, admin_password):
	print(f"{generate_timestamp()}: Getting firmware version via SSH Management.")

	# This prepares the SSH target.
	fw = fw.strip("https://").split(":")[0]
	# fw = fw + ":" + str(sshport)

	# Connect to the firewall.
	try:
		ssh, ssh_conn = connect_ssh(fw,
									sshport,
									soniccore_user=admin_user,
									soniccore_pass=admin_password,
									sonicos_user=admin_user,
									sonicos_pass=admin_password,
									soniccore_prelogin=False)
	except KeyboardInterrupt:
		print(f"{generate_timestamp()}: Stopped!")
		exit()
	except KeyError as e:
		print(f"{generate_timestamp()}: KeyError: Either ({e}) is missing or the configuration is invalid/not found.")
		# exit()
		return False, None
	except Exception as e:
		print(f"{generate_timestamp()}: Error with SSH connection (4):", str(e))
		# exit()
		return False, None

	# Command list for enabling the SonicOS API.
	command_list = [
		"show version",
		"exit",
		"exit",
	]

	cnt = 0
	command_output = []
	for cmd in command_list:
		# Send commands to the firewall and write the output to separate files.
		try:
			cmd_response = send_cmd(ssh, cmd + "\r", get_cmd_response=True, silent=True)
			command_output.append(cmd_response)
			cnt += 1
		except KeyboardInterrupt:
			ssh.close()
			ssh_conn.close()
			print(f"{generate_timestamp()}: Stopped!")
			exit()

	firmware_version = ""
	serial_number = ""
	for line in command_output:
		if "firmware-version" in line:
			firmware_version = line.split(" ")[-1].strip('"').strip()
			continue
		elif "serial-number" in line:
			serial_number = line.split(" ")[-1].strip('"').strip().replace("-", "")
			continue

	# Close the SSH session.
	ssh.close()
	ssh_conn.close()

	return firmware_version, serial_number


# Enable TOTP on a given group.
def enable_totp_ssh(fw, sshport, admin_user, admin_password, group_name):
	print(f"{generate_timestamp()}: Enabling TOTP on {group_name} via SSH Management.")

	# This prepares the SSH target.
	fw = fw.strip("https://").split(":")[0]
	# fw = fw + ":" + str(sshport)

	# Connect to the firewall.
	try:
		ssh, ssh_conn = connect_ssh(fw,
									sshport,
									soniccore_user=admin_user,
									soniccore_pass=admin_password,
									sonicos_user=admin_user,
									sonicos_pass=admin_password,
									soniccore_prelogin=False)
	except KeyboardInterrupt:
		print(f"{generate_timestamp()}: Stopped!")
		exit()
	except KeyError as e:
		print(f"{generate_timestamp()}: KeyError: Either ({e}) is missing or the configuration is invalid/not found.")
		# exit()
		return False
	except Exception as e:
		print(f"{generate_timestamp()}: Error with SSH connection (5):", str(e))
		# exit()
		return False

	# Command list for enabling the SonicOS API.
	command_list = [
		"user local",
		f'group "{group_name}"',
		"one-time-password totp",
		"commit",
		"exit",
		"exit",
		"exit",
		"exit"
	]

	cnt = 0
	command_output = []
	for cmd in command_list:
		# Send commands to the firewall and write the output to separate files.
		try:
			cmd_response = send_cmd(ssh, cmd + "\r", get_cmd_response=True, silent=True)
			command_output.append(cmd_response)
			cnt += 1
		except KeyboardInterrupt:
			ssh.close()
			ssh_conn.close()
			print(f"{generate_timestamp()}: Stopped!")
			exit()

	successful = False
	for line in command_output:
		if "% Changes made." in line:
			print(f"{generate_timestamp()}: TOTP sucessfully enabled.")
			successful = True
			break

	# Close the SSH session.
	ssh.close()
	ssh_conn.close()

	return successful

