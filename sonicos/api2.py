import time
import re
from xml.etree.ElementTree import indent

import requests
import hashlib
import os
from datetime import datetime


class Login:
    def __init__(self, ipaddress, userid, passwd, admin_mode, http_type, brwsr_cache, verbose, sessIdRef):
        self.ipaddress = ipaddress.strip("https://").strip("http://").strip("/")
        self.userid = userid
        self.passwd = passwd
        self.admin_mode = self.get_admin_mode(admin_mode)
        self.http_type = http_type.lower()
        self.brwsr_cache = brwsr_cache
        self.verbose = verbose
        self.session = requests.Session()
        self.sessIdRef = sessIdRef
        self.challenge = ""
        self.id_value = ""
        self.csrf_token = None
        self.param1 = ""  # param1 value from navigationView.html
        self.page_seed = ""  # Page seed is in local storage, created by random number + password.
        self.model = ""
        self.serial_number = ""
        self.firmware_version = ""
        self.ha_status = ""
        self.ha_primary_state = ""
        self.ha_secondary_state = ""
        self.ha_uptime = ""
        self.stored_params = {}

    def get_admin_mode(self, admin_mode_str):
        admin_mode_dict = {
            "none": 0,
            "read-only": 1,
            "non-config": 2,
            "config": 3
        }
        if admin_mode_str in admin_mode_dict:
            return admin_mode_dict[admin_mode_str]
        else:
            print(f"Invalid admin mode: {admin_mode_str}")
            return 0

    def get_firewall_info(self):
        details = {
            "model": self.model,
            "serial_number": self.serial_number,
            "firmware_version": self.firmware_version,
            "ha_status": self.ha_status,
            "ha_primary_state": self.ha_primary_state,
            "ha_secondary_state": self.ha_secondary_state,
            "ha_uptime": self.ha_uptime
        }
        return details

    def print_response(self, resp, print_content=False):
        print("Status code:", resp.status_code, resp.reason)
        print("Request Headers:")
        for key, value in resp.request.headers.items():
            print(f"  {key}: {value}")
        print()
        print("Response Headers:")
        for key, value in resp.headers.items():
            print(f"  {key}: {value}")
        print()
        if len(resp.cookies) > 0:
            print("Cookies:")
            for key, value in resp.cookies.items():
                print(f"  {key}: {value}")
            print()

        print("Content:")
        rc = resp.content.decode("utf-8").split("\r\n")
        if print_content:
            for l in rc:
                print(l)

    def store_params(self, content):
        if isinstance(content, requests.models.Response):
            content = content.text

        # Handle a few params we want to store.
        # Botnet Filter
        botnet_filter = [
            "botnetBlkMode=",  # 0 = all connections, 1 = firewall rule-based
            "botnetDisplayBlockDetails=",  # off or on
            "botnetBlock=",  # 0 or 1
            "botnetLoggingEnabled="  # off or on
        ]
        for p in botnet_filter:
            if p in content:
                rx = f"{p}(.*)&"
                rx = re.escape(rx)
                val = re.search(rx, content).group(1)
                # print("value", val)
                self.stored_params[p] = val

    def parse_xml_response(self, content):
        if isinstance(content, requests.models.Response):
            content = content.text

        result_code = re.search(r"<result>([0-1])</result>", content)
        restart_needed = re.search(r"<restart_needed>([0-1])</restart_needed>", content)
        error_msg = re.search(r"<error>\s*<desc>(.*?)</desc>\s*</error>", content)

        result_code = result_code.group(1)
        restart_needed = restart_needed.group(1)
        if error_msg:
            error_msg = error_msg.group(1)

        if self.verbose:
            print("Parsed XML response:")

        if not result_code:
            if self.verbose:
                print("  No result code found.")
            result_code = 0
        else:
            if self.verbose:
                print("  Result code:", result_code)
            result_code = int(result_code)

        if not restart_needed:
            if self.verbose:
                print("  No restart_needed code found.")
            restart_needed = 0
        else:
            if self.verbose:
                print("  Restart needed?:", restart_needed)
            restart_needed = int(restart_needed)

        if not error_msg:
            if self.verbose:
                print("  No error message.")
        else:
            if self.verbose:
                print("  Error message:", error_msg)

        return result_code, restart_needed, error_msg

    def login2(self, sess_id_ref=None):
        # print(f"ipaddress    = {self.ipaddress}\n"
              # f"userid       = {self.userid}\n"
              # f"passwd       = {self.passwd}\n"
              # f"adminMode    = {self.admin_mode}\n"
              # f"httpType     = {self.http_type}\n"
              # f"brwsrCache   = {self.brwsr_cache}\n"
              # f"verbose      = {self.verbose}\n")

        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        if self.http_type == 'https':
            ssl = True
        else:
            ssl = False

        # Start the login process
        ret, ret_msg = self.start_login_process2(sess_id_ref)
        return ret, ret_msg

    def start_login_process2(self, sess_id_ref):
        post_data = {
            "uName": self.userid,
            "pass": self.passwd,
            "adminMode": "3"
        }

        if self.admin_mode != 3:
            post_data["adminMode"] = self.admin_mode

        self.session.headers.update({"User-Agent": "SGMS/8.0"})
        try:
            response = self.get_request("sgmsAuth.xml", print_content=False, timeout=15)
        except requests.exceptions.Timeout as e:
            print("Timeout error:", e, "\n")
            return 0, f"Timeout error: {e}"
        except requests.exceptions.ConnectionError as e:
            print("Connection error:", e, "\n")
            return 0, f"Connection error: {e}"
        except KeyboardInterrupt:
            print("Stopped!")
            exit()

        if response.status_code != 200:
            print("Failed to connect to the firewall. -->", response.status_code, response.reason)
            return 0, f"Failed to connect to the firewall. --> {response.status_code} {response.reason}"

        authSessId = None
        authSessId = re.search(f"<authSessId>(.*)</authSessId>", response.text)
        if authSessId:
            authSessId = authSessId.group(1)
            self.sessIdRef = authSessId
        else:
            print("No authSessId found. The rest of this process will fail.\n")

            return 0, f"No authSessId found."


        response = self.post_request("auth4.cgi", post_data=post_data, print_content=False, timeout=15)
        result_code, restart_needed, err_msg = self.parse_xml_response(response)
        if result_code == 1:
            print("Logged in successfully!")
        elif result_code == 0:
            print("Error message:", err_msg)
            return 0, f"Error message: {err_msg}"

        try:
            op_failed = re.search(r"Operation failed - Error message is unspecified.", response.text)
            if op_failed:
                print(response.content.decode("utf-8"))
                print("Operation failed - Error message is unspecified.")
                print("2FA may be enabled on the firewall management user.")
                return 0, f"Operation failed - Error message is unspecified."
        except Exception as e:
            pass

        # Adds the "Cookie" header to "SessId=<sessIdRef>" and updates the session cookies with the SessId.
        # Subsequent requests will need this.
        self.session.headers.update({"Cookie": f"SessId={self.sessIdRef}"})
        self.session.cookies.update({"SessId": self.sessIdRef})

        # Gets firewall state info.
        response = self.get_request("firewallState.xml", print_content=False, timeout=15)
        if response.status_code != 200:
            print(f"{response.status_code}: Failed to get firewall state. A password update may be required.")
            print(response.content.decode("utf-8"))
            return 0, f"{response.status_code}: Failed to get firewall state. Admin password change may be required."

        # Get firmware version, model, and serial number.
        serial_number = re.search(r"<sn>(.*)</sn>", response.text).group(1)
        model = re.search(r"<model>(.*)</model>", response.text).group(1)
        firmware_version = re.search(r"<fv>(.*)</fv>", response.text).group(1)
        if firmware_version.startswith("27."):
            firmware_version = firmware_version.replace("27.", "7.")
        elif firmware_version.startswith("26."):
            firmware_version = firmware_version.replace("26.", "6.")
        elif firmware_version.startswith("25."):
            firmware_version = firmware_version.replace("25.", "5.")

        self.serial_number = serial_number
        self.model = model
        self.firmware_version = firmware_version

        # response = self.get_request("prefMeta.xml", print_content=False)
        # self.store_params(response.text)

        # Handle the CSRF token/navigation view
        self.handle_navigation_view2()

        if self.csrf_token:
            self.get_ha_status()

        if self.csrf_token:
            if self.verbose:
                print(f"Logged in successfully!\n"
                      f"Serial Number: {serial_number}\n"
                      f"Model: {model}\n"
                      f"Firmware Version: {firmware_version}\n"
                      f"High Availability Status: {self.ha_status}\n"
                      f"--Primary State: {self.ha_primary_state}\n"
                      f"--Secondary State: {self.ha_secondary_state}\n"
                      f"--HA Uptime: {self.ha_uptime}\n")
            return 1, f"Logged in successfully!"
        else:
            return 0, f"Failed to log in."

    def handle_navigation_view2(self):
        nav = self.get_request("navigationView.html", print_content=False, timeout=15)

        # GEN6
        csrf_token_match = re.search(r'csrfToken = "(.*)"', nav.text)
        if csrf_token_match:
            csrf_token = csrf_token_match.group(1)
            self.csrf_token = csrf_token
            # print(f"CSRF token found (1): {csrf_token}")
            print()
        else:
            # print("No CSRF token found (1).")
            print()

            # GEN5
            nav = self.get_request("outlookView.html", print_content=False, timeout=15)

            csrf_token_match = re.search(r'csrfToken = "(.*)"', nav.text)
            if csrf_token_match:
                csrf_token = csrf_token_match.group(1)
                self.csrf_token = csrf_token
                # print(f"CSRF token found (2): {csrf_token}")
                print()
            else:
                # print("No CSRF token found (2).")
                print()

    def get_ha_status(self):
        response = self.get_request("getJsonData.json?dataSet=svrrpHaStatus", print_content=False, timeout=15)

        try:
            data = response.json()
            data = data.get("svrrpNodes", [{}])[0]
        except Exception as e:
            print("Error converting response to JSON:", e)
            data = {}

        ha_status = data.get("status", "")
        ha_primary_state = data.get("priState", "")
        ha_secondary_state = data.get("secState", "")
        ha_uptime = data.get("upTime", "")

        if ha_status:
            self.ha_status = ha_status.upper()
        if ha_primary_state:
            self.ha_primary_state = ha_primary_state.upper()
        if ha_secondary_state:
            self.ha_secondary_state = ha_secondary_state.upper()
        if ha_uptime:
            self.ha_uptime = ha_uptime.upper()

    def logout(self):
        print("\nTrying to log out...")

        try:
            response = self.get_request("logout.html", print_content=False, timeout=5)
        except requests.exceptions.Timeout as e:
            print("Timeout error:", e, "\n")
            return 0

        if response.status_code == 200:
            print("Logged out successfully!")
            return 1
        else:
            print("Failed to log out.")
            return 0

    # Enable SonicOS API
    def enable_sonicos_api(self):
        print("\nTrying to enable SonicOS API...")

        post_data = {
            "sonicOsApi_enable": "on",
            "cbox_sonicOsApi_enable": "",
            "sonicOsApi_dgstAuth": "on",
            "cbox_sonicOsApi_dgstAuth": "",
            "sonicOsApi_dgstSHA256": "on",
            "cbox_sonicOsApi_dgstSHA256": "",
            "sonicOsApi_dgstMD5": "off",
            "cbox_sonicOsApi_dgstMD5": 0,
            "apiDgstInteg": 0,
            "sonicOsApi_dgstIntegrity": 0,
            "sonicOsApi_holdSessPwds": 1,
            "apiDgstSess": 1,
            "sonicOsApi_CHAPAuth": "on",
            "cbox_sonicOsApi_CHAPAuth": "",
            "sonicOsApi_basicAuth": "on",
            "cbox_sonicOsApi_basicAuth": "",
            "sonicOsApi_pubKeyAuth": "on",
            "cbox_sonicOsApi_pubKeyAuth": "",
            "sonicOsApi_pubKeyBits": 1024,
            "apiPubKeyPad": 1,
            "sonicOsApi_pubKeyOAEP": 1,
            "sonicOsApi_pkOAEPDgst": "SHA1",
            "sonicOsApi_pkOAEPMgf1": "SHA1",
            "sonicOsApi_sessSecurity": "off",
            "cbox_sonicOsApi_sessSecurity": "",
            "sonicOsApi_dgstNonceMax": 10,
            "cbox_sonicOsApi_tokenAuth": "",
            "refresh_page": "systemAdministrationView.html"
        }

        # Add the "Cookie" header to "SessId=<sessIdRef>"
        # self.session.headers.update({"Cookie": f"SessId={self.sessIdRef}"})

        # Add the SessId to the cookies.
        # self.session.cookies.update({"SessId": self.sessIdRef})

        # Send the POST request to enable SonicOS API
        response = self.post_request("main.cgi", post_data=post_data, print_content=False, timeout=15)

        # Check if the API was successfully enabled
        if response.status_code == 200:
            status_msg_success = re.search(r">The configuration has been updated.</", response.text)
            status_msg_wrong_browser = re.search(r">Wrong browser</", response.text)
            status_msg_messagered = re.search(r"messageRed.*>(.*)</", response.text)
            if status_msg_success:
                print("SonicOS API enabled successfully!\n")
                return 1
            elif status_msg_wrong_browser:
                print("Failed to enable SonicOS API. Wrong browser error.\n")
                print("-----------")
                print(response.content)
                print("-----------")
                return 0
            elif status_msg_messagered:
                print("Failed to enable SonicOS API. MessageRed error:", status_msg_messagered.group(1), "\n")

            print("\n---Response---")
            print(response.text)
            print("---------------\n")
        else:
            print("Failed to enable SonicOS API.")
            print(response.text)
            return 0

    def get_request(self, uri, print_content=False, timeout=30):
        if self.verbose:
            print(f"Fetching {self.http_type}://{self.ipaddress}/{uri} ...")
        response = self.session.get(f"{self.http_type}://{self.ipaddress}/{uri}", verify=False, timeout=timeout)

        # Print the headers
        if print_content:
            print(f"------------------- {uri.upper()} -------------------")
            self.print_response(response, print_content=print_content)
            print("------------------- END -------------------\n\n")
        return response

    def post_request(self, uri, post_data, file_data=None, print_content=False, timeout=30):
        if self.verbose:
            print(f"Posting data to {self.http_type}://{self.ipaddress}/{uri} ...")
        if file_data:
            response = self.session.post(f"{self.http_type}://{self.ipaddress}/{uri}",
                                         data=post_data,
                                         files=file_data,
                                         verify=False,
                                         timeout=timeout)
        else:
            response = self.session.post(f"{self.http_type}://{self.ipaddress}/{uri}",
                                         data=post_data,
                                         verify=False,
                                         timeout=timeout)

        if print_content:
            print(f"------------------- {uri.upper()} -------------------")
            self.print_response(response, print_content=print_content)
            print("------------------- END -------------------\n\n")
        return response

    def reboot_firewall(self):
        if self.get_firewall_info().get("ha_status", None):
            print("\nNot rebooting an HA firewall.")
        else:
            print("\nTrying to reboot the firewall...")

        data = {
            "csrfToken": self.csrf_token,
            "cgiaction": "reboot"
        }

        response = self.post_request("main.cgi", post_data=data, print_content=False, timeout=15)
        if response.status_code == 200:
            print("Firewall reboot successful!")
            return True
        else:
            print("Failed to reboot the firewall.")
            return False

    def wait_for_reboot(self, timeout=480):
        start_time = datetime.now()
        print("\nWaiting for the firewall to reboot...")

        time.sleep(30)

        while True:
            try:
                response = self.get_request("auth.html", print_content=False, timeout=15)

                # If the request is successful, the firewall auth page is reachable and firewall is back up.
                if response.status_code == 200:
                    print("Firewall auth page is reachable!")

                    li = False
                    li_count = 0
                    while not li:
                        logged_in, rmsg = self.login2()
                        if logged_in:
                            li = True
                            print("Logged in successfully!")
                            return True
                        else:
                            li_count += 1
                            time.sleep(30)
                            if li_count == 10:
                                print("Still unable to log in after 10 attempts.")
                                break
                            time.sleep(30)

                # If the request fails, the reboot is still in progress.
                else:
                    print("Firewall auth page is still not reachable.")
                    time.sleep(30)

            except requests.exceptions.RequestException as e:
                print("Connection error:", e)
                time.sleep(30)

            # If the request fails after the timeout, the reboot is likely still not complete.
            if (datetime.now() - start_time).seconds >= timeout:
                print("Reboot still in progress after timeout period.")
                # break
                return False

    def upload_firmware(self, fw_path):
        fm_filename = os.path.split(fw_path)[-1]

        if self.get_firewall_info().get("ha_status", None):
            timeout = 1000  # was 600
        else:
            timeout = 4200  # was 360 then 3600

        form_data = {
            "csrfToken": self.csrf_token,
            "auditpath": "Firmware Management & Backup",
        }

        files = {
            "firmware": (fm_filename, open(fw_path, "rb"), "application/octet-stream")
        }

        response = self.post_request("upload.cgi?safeMode=1",
                                     post_data=form_data,
                                     file_data=files,
                                     print_content=False,
                                     timeout=(timeout, 4200))  # was 420
        r_code = 0
        rn_code = 0
        err_msg = ""
        try:
            r_code, rn_code, err_msg = self.parse_xml_response(response)
            #print("api2.upload_firmware(): r_code:", r_code, "rn_code:", rn_code, "err_msg:", err_msg)
            return response, r_code, rn_code, err_msg
        except Exception as e:
            pass

        return response, r_code, rn_code, err_msg

    def boot_uploaded_firmware(self):
        data = {
            "csrfToken": self.csrf_token,
            "cgiaction": "none",
            "file": "upload",
            "cbox_diag": "",
            "fwAutoUpdate": "on",
            "cbox_fwAutoUpdate": "",
            "fwAutoDownload": "on",
            "cbox_fwAutoDownload": "",
            "cbox_fipsMode": "",
            "cbox_ndppMode": ""
        }

        # TODO: Before booting, make sure we're still logged in. Check for an active session/create a new one.

        try:
            response = self.post_request("boot.cgi",
                                         post_data=data,
                                         print_content=True,
                                         timeout=240)
            successful = re.search(r"(The SonicWall is restarting)", response.text)
            non_config_mode = re.search(r"(Not allowed in current mode)", response.text)
        except requests.exceptions.Timeout as e:
            print("Timeout error:", e)
            print("The boot action likely started.\n")
            successful = True
            non_config_mode = False
        except requests.exceptions.ConnectionError as e:
            print("Connection error:", e)
            print("The boot action likely started.\n")
            successful = True
            non_config_mode = False

        if successful:
            if self.verbose:
                print("Firmware boot successful!\n")
            return True, "SUCCESS"
        if non_config_mode:
            print(non_config_mode)
            return False, "NON_CONFIG_MODE"
        return False, "FAILED"

    def download_tsr(self, filepath):
        print("\nTrying to download TSR...")
        response = self.get_request("techSupport.wri", print_content=False)
        if response.status_code == 200:
            with open(filepath, "wb") as f:
                f.write(response.content)
            print("TSR downloaded successfully!")
            return True
        else:
            print("Failed to download TSR.")
            return False

    def download_tracelog(self, filepath, tracelog_type=3):
        print("\nTrying to download tracelog...")
        # 0-invalid, 1-current, 2-last, 3-last+current, 4-all files
        # I noticed 4 was empty on my firewall, while current was populated, so opting for 3.
        response = self.get_request(f"traceLog.wri?&traceLogType={tracelog_type}", print_content=False)
        if response.status_code == 200:
            with open(filepath, "wb") as f:
                f.write(response.content)
            print("Tracelog downloaded successfully!")
            return True
        else:
            print("Failed to download tracelog.")
            return False

    def export_preferences(self, filepath):
        print("\nTrying to export preferences...")
        response = self.get_request("sonicwall.exp", print_content=False)
        if response.status_code == 200:
            with open(filepath, "wb") as f:
                f.write(response.content)
            print("Preferences exported successfully!")
            return True
        else:
            print("Failed to export preferences.")
            return False

    def download_audit_log(self, filepath):
        print("\nTrying to download audit log...")
        response = self.get_request("auditRecords.wri?auditPath=MONITOR%20/%20Log%20/%20Auditing%20Records", print_content=False)
        if response.status_code == 200:
            with open(filepath, "wb") as f:
                f.write(response.content)
            print("Audit log downloaded successfully!")
            return True
        else:
            print("Failed to download audit log.")
            return False

    def enable_ssh_management(self):
        print("\nTrying to enable SSH Management...")
        data = {
            "csrfToken": self.csrf_token,
        }

        response = self.post_request("main.cgi", post_data=data, print_content=False)

    def get_botnet_status(self):
        print("\nTrying to get Botnet status...")
        response = self.get_request("botnetFilter.html", print_content=False)

        botnet_licensed = re.search(r"(Botnet Filter Not Licensed)", response.text)
        botnet_licensed2 = re.search(r"(App Visualization Not Licensed)", response.text)
        botnet_licensed = botnet_licensed or botnet_licensed2
        botnet_enabled = re.search(r'name="botnetBlock" value="(.*)">', response.text)
        botnet_mode = re.search(r'name="botnetBlkMode" value="(.*)" CHECKED>', response.text)

        if botnet_licensed is None:
            botnet_licensed = True
        else:
            botnet_licensed = False

        if botnet_enabled:
            botnet_enabled = int(botnet_enabled.group(1).strip('"').strip())
            if botnet_enabled == 1:
                botnet_enabled = True
            else:
                botnet_enabled = False

        if botnet_mode:
            botnet_mode = int(botnet_mode.group(1).strip('"').strip())
            if botnet_mode == 0:
                botnet_mode = "all"
            elif botnet_mode == 1:
                botnet_mode = "firewall_rule_based"

        if not botnet_licensed:
            print("Botnet Filter is not licensed.")
            return {
                "status": {
                    "info": [
                        {
                            "message": "Licensing must be activated"
                        }
                    ]
                }
            }

        return {
            "botnet": {
                "block": {
                    "connections": {
                        "enable": botnet_enabled,
                        botnet_mode: True
                    }
                }
            }
        }

    def enable_botnet_filtering(self):
        data = {
            "csrfToken": self.csrf_token,
            "botnetLoggingEnabled": 1,
            "botnetBlock": 1,
            "botnetBlkMode": 0,
        }
        response = self.post_request("main.cgi", post_data=data, print_content=False)
        rc, rn, ec = self.parse_xml_response(response)

        if rc == 1:
            print("Botnet Filtering enabled successfully!")
            rd = {
                "status": {
                    "success": True
                }
            }
            return rd

    # Function to get the AWS API page
    def get_aws_api(self):
        # print("\nTrying to get AWS API page...")
        # response = self.get_request("awsConfig.html", print_content=False)
        response = self.get_request("awsLogs.html", print_content=False)
        if response.status_code == 200:
            # print("AWS API page retrieved successfully!")
            aws_logging_enabled = re.search(r'var awsLogEnable = "CHECKED"', response.text)
            aws_region = re.search(r'var awsRegion = "(.*)"', response.text)
            aws_access_key_id = re.search(r'var awsAccessKeyId = "(.*)"', response.text)
            aws_log_group_name = re.search(r'var awsLogGroupName = "(.*)"', response.text)
            aws_steam_name = re.search(r'var awsLogStreamName = "(.*)"', response.text)

            if aws_logging_enabled:
                aws_logging_enabled = True
            else:
                aws_logging_enabled = False

            if aws_region:
                aws_region = aws_region.group(1)
            else:
                aws_region = ""

            if aws_access_key_id:
                aws_access_key_id = aws_access_key_id.group(1)
            else:
                aws_access_key_id = ""

            if aws_log_group_name:
                aws_log_group_name = aws_log_group_name.group(1)
            else:
                aws_log_group_name = ""

            if aws_steam_name:
                aws_steam_name = aws_steam_name.group(1)
            else:
                aws_steam_name = ""

            data = {
                "log": {
                    "aws": {
                        "enable": aws_logging_enabled,
                        "region": aws_region,
                        "access_key_id": aws_access_key_id,
                        "log_group_name": aws_log_group_name,
                        "log_stream_name": aws_steam_name
                    }
                }
            }

            return data
        else:
            print("Failed to retrieve AWS API page.")
            return None

    # Function to get the TACACS Authentication servers.
    def get_tacacs_servers(self):
        response = self.get_request("tacacsProps.html", print_content=False)
        if response.status_code == 200:
            tacacs_servers = []
            tacacs_entries = re.findall(r'tacSrvrArray\[(\d+)\]\s*=\s*new\s*TacacsServer\((.*?)\);', response.text, re.DOTALL)
            for entry in tacacs_entries:
                index = entry[0]
                values = [v.strip().strip('"') for v in entry[1].split(",")]
                if len(values) >= 6:
                    server_info = {
                        "host": values[0] or "",
                        "port": values[1] or 0,
                        "enable": values[5] or False,
                    }
                    tacacs_servers.append(server_info)

            data = {
                'user': {
                    'tacacs': tacacs_servers
                }
            }

            return data
        else:
            print("Failed to retrieve TACACS servers.")
            return None

    # Function to get the TACACS Accounting servers
    def get_tacacs_accounting_servers(self):
        response = self.get_request("tacacsAcctProps.html", print_content=False)
        if response.status_code == 200:
            tacacs_accounting_servers = []
            tacacs_acc_entries = re.findall(r'tacAcctSrvrArray\[(\d+)\]\s*=\s*new\s*TacAcctSrvr\((.*?)\);', response.text, re.DOTALL)
            for entry in tacacs_acc_entries:
                values = [v.strip().strip('"') for v in entry[1].split(",")]
                server_info = {
                    "host": values[0] or "",
                    "port": values[1] or 0,
                    "enable": values[4] or False,
                    "shared_secret": "not_extracted"
                }
                tacacs_accounting_servers.append(server_info)

            data = {
                'user': {
                    'tacacs': {
                        'accounting': {
                            'server': tacacs_accounting_servers
                        }
                    }
                }
            }

            return data
        else:
            print("Failed to retrieve TACACS accounting servers.")
            return None

    # Function to get the Settings/TSR Scheduled Reports
    def get_scheduled_reports(self):
        response = self.get_request("cloudBackupSettings.html", print_content=False)
        if response.status_code == 200:
            ftp_server = re.search(r'var gFtpServerAddr = \'(.*)\';', response.text)
            ftp_user = re.search(r'var gFtpUser = \'(.*)\';', response.text)
            ftp_password = re.search(r'var gFtpPwd = \'(.*)\';', response.text)

            data = {
                'server': ftp_server.group(1),
                'user': ftp_user.group(1),
                'password': ftp_password.group(1)
            }

            return data
        else:
            print("Failed to retrieve scheduled reports.")
            return None

    # Function to get the Dynamic External Address Objects
    def get_dynamic_external_address_objects(self):
        response = self.get_request("getObjectList.json?type=2056", print_content=False)
        if response.status_code == 200:
            response = response.json()
            response = response.get('dynObjArray', [])
            dynamic_objects = []
            for entry in response:
                obj_info = {
                    "type": entry['dynGroupType'] or "",
                    "name": entry['name'] or "",
                    "protocol": "ftp" if entry['dynGroupProtocol'] == 1 else "https" if entry['dynGroupProtocol'] == 2 else "",
                    "server": {"value": entry['dynGroupFtpServerAddr'] or ""},
                    "login": entry['dynGroupFtpUser'] or "",
                    "url": entry['dynGroupUrlName'] or "",
                }
                dynamic_objects.append(obj_info)

            data = {
                'dynamic_external_objects': dynamic_objects
            }

            return data
        else:
            print("Failed to retrieve dynamic external address objects.")
            return None

    # Function to get the SSO 3rd Party API Clients
    def get_sso_api_clients(self):
        response = self.get_request("ssoAuthProps.html", print_content=False)
        if response.status_code == 200:
            api_client_array = re.findall(r'restApiClientArray\[(\d+)\]\s*=\s*new\s*RestApiClient\((.*?)\);', response.text, re.DOTALL)
            api_clients = []
            for entry in api_client_array:
                values = [v.strip().strip('"') for v in entry[1].split(",")]
                client_info = {
                    "host": values[0] or "",
                    "shared_secret": "not_extracted",
                }
                api_clients.append(client_info)

            data = {
                'user': {
                    'sso': {
                        'third_party_api': {
                            'client': api_clients
                        }
                    }
                }
            }

            return data
        else:
            print("Failed to retrieve SSO API clients.")
            return None

    # Function to get the SFR Mailing configuration
    def get_sfr_mailing_settings(self):
        response = self.get_request("logNetFlowView.html", print_content=False)
        if response.status_code == 200:
            sfr_reporting_enabled = re.search(r'id="appVizActionEmail" name="appVizActionEmail" CHECKED', response.text)
            sfr_smtp_auth = re.search(r'id="appVizSmtpAuthEnable" name="appVizSmtpAuthEnable" CHECKED', response.text)
            sfr_pop_auth = re.search(r'id="appVizEmailPopBeforeSmtp" name="appVizEmailPopBeforeSmtp" CHECKED', response.text)
            sfr_server = re.search(r'id="appVizEmailServerName"\s+name="appVizEmailServerName"\s+value="(.*)"\s+', response.text)
            sfr_server_pop = re.search(r'id="appVizEmailPopServerAddr"\s+name="appVizEmailPopServerAddr"\s+value="(.*)"\s+', response.text)
            sfr_username = re.search(r'id="appVizSmtpAuthName"\s+name="appVizSmtpAuthName"\s+value="(.*)"\s+', response.text)
            sfr_password = re.search(r'id="appVizSmtpAuthPassword"\s+name="appVizSmtpAuthPassword"\s+value="(.*)"\s+', response.text)
            sfr_username_pop = re.search(r'id="appVizEmailUser"\s+name="appVizEmailUser"\s+value="(.*)"\s+', response.text)
            sfr_password_pop = re.search(r'id="appVizEmailPwd"\s+name="appVizEmailPwd"\s+value="(.*)"\s+', response.text)

            data = {
                'appflow': {
                    'sfr_mailing': {
                        'send_email': True if sfr_reporting_enabled else False,
                        'smtp_auth': True if sfr_smtp_auth else False,
                        'pop_before_smtp': True if sfr_pop_auth else False,
                        'smtp_server_host': sfr_server.group(1) if sfr_server else "",
                        'pop_server_address': sfr_server_pop.group(1) if sfr_server_pop else "",
                        'smtp_user': sfr_username.group(1) if sfr_username else "",
                        'smtp_pass': sfr_password.group(1) if sfr_password else "",
                        'pop_username': sfr_username_pop.group(1) if sfr_username_pop else "",
                        'pop_pass': sfr_password_pop.group(1) if sfr_password_pop else "",
                    }
                }
            }

            return data
        else:
            print("Failed to retrieve SFR mailing settings.")
            return None

    def get_cellular_wwan_settings(self):
        response = self.get_request("netDialupProfilesView.html", print_content=False)
        if response.status_code == 200:
            profile_list = []
            wwan_conn_profiles = re.findall(r'dupObjArray\[(\d+)\]\s*=\s*new\s*dupObj\((.*?)\);', response.text, re.DOTALL)

            # We're assuming WWAN is enabled if there are connection profiles configured.
            for pro in wwan_conn_profiles:
                values = [v.strip().strip('"') for v in pro[1].split(",")]
                p = {
                    'modem_attached': 1,  # Simulating modem attached when profiles exist
                    'vendor_name': values[1] or None,  # Provider and Plan Type
                }
                profile_list.append(p)

            return profile_list
        else:
            print("Failed to retrieve cellular WWAN settings.")
            return None

    def get_advanced_routing_settings(self):
        # RIP
        routing_interfaces = []
        rip_response = self.get_request("getRouteList.json?reqType=4096", print_content=False)
        if rip_response.status_code == 200:
            rip_response = rip_response.json()
            routed_ifs = rip_response.get('routedIfs', '')

            if len(routed_ifs) > 0:
                # Lines are separated by '|', first line is the header with key names
                lines = routed_ifs.split('|')
                key_names = lines[0].strip().split(',')

                # Creates a list of dictionaries for each route interface entry
                for line in lines[1:]:
                    values = line.strip().split(',')
                    route_info = dict(zip(key_names, values))
                    int_name = route_info.pop('ifName', 'N/A').strip('"')
                    int_zone = route_info.pop('zoneName', '"N/A"').strip('"')
                    int_num = route_info.pop('iface', '')

                    if route_info['rip'].lower() == 'rip enabled':
                        # RIP individual interface settings
                        int_response = self.get_request(f"ZRipSettingsGenEnum_{int_num}.html", print_content=False)
                        if int_response.status_code == 200:
                            # We can detect the "Simple Password" or "Message Digest" selections to see if a password would be required.
                            rip_use_password = re.search(r'<input type="checkbox"\s+name="ZRipUsePassword"\s+CHECKED', int_response.text)
                            route_info['rip_auth'] = True if rip_use_password else False

                    int_dict = {
                        'name': int_name,
                        'zone': int_zone,
                        'RIP': {
                            'status': True if route_info['rip'].lower() == 'rip enabled' else False,
                            'password': 'not_extracted' if route_info.get('rip_auth', False) else ''
                        },
                    }
                    routing_interfaces.append(int_dict)
        else:
            print("Failed to retrieve RIP routing settings.")

        # OSPFv2
        ospf_response = self.get_request("/getRouteList.json?reqType=256", print_content=False)
        if ospf_response.status_code == 200:
            ospf_response = ospf_response.json()
            ospf_routed_ifs = ospf_response.get('routedIfs', '')

            if len(ospf_routed_ifs) > 0:
                # Lines are separated by '|', first line is the header with key names
                lines = ospf_routed_ifs.split('|')
                key_names = lines[0].strip().split(',')

                # Creates a list of dictionaries for each route entry
                for line in lines[1:]:
                    values = line.strip().split(',')
                    route_info = dict(zip(key_names, values))
                    int_name = route_info.pop('ifName', 'N/A').strip('"')
                    int_num = route_info.pop('iface', '')

                    if route_info['ospf'].lower() == 'ospf enabled':
                        # OSPFv2 individual interface settings
                        int_response = self.get_request(f"ospfSettingsGenEnum_{int_num}.html", print_content=False)
                        if int_response.status_code == 200:
                            # We can detect the "Simple Password" or "Message Digest" selections to see if a password would be required.
                            simple_password = re.search(r'<option value="\d+"\s+SELECTED>Simple Password\s+</option>', int_response.text)
                            msg_digest = re.search(r'<option value="\d+"\s+SELECTED>Message Digest\s+</option>', int_response.text)
                            route_info['ospf_auth'] = True if simple_password or msg_digest else False

                    # Find the corresponding interface in routing_interfaces
                    for intf in routing_interfaces:
                        if intf['name'] == int_name:
                            intf['OSPFv2'] = {'status': True if route_info['ospf'].lower() == 'ospf enabled' else False}
                            intf['OSPFv2']['authentication'] = route_info.get('ospf_auth', False)
                            intf['OSPFv2']['password'] = 'not_extracted' if route_info.get('ospf_auth', False) else ''
                            break
        else:
            print("Failed to retrieve OSPF routing settings.")

        if len(routing_interfaces) > 0:
            data = {
                'data': {
                    'ipv4': {
                        'interfaces': routing_interfaces
                    }
                }
            }
            return data
        else:
            print("Failed to retrieve advanced routing settings.")
            return None


# Test
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Test the SonicWall API")
    parser.add_argument("target", type=str, help="Target firewall IP address:port.")
    parser.add_argument("-u", "--username", type=str, default="admin", help="Username.")
    parser.add_argument("-p", "--password", type=str, help="Password.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output.")
    a = parser.parse_args()

    if a.verbose:
        a.verbose = 1
    else:
        a.verbose = 0

    if not a.password:
        a.password = input("Enter password: ")

    login_object = Login(
        # ipaddress="192.168.0.107",  # 6
        # ipaddress="192.168.0.106",  # 5
        ipaddress=a.target,
        userid=a.username,
        passwd=a.password,
        admin_mode="config",
        http_type="https",
        brwsr_cache=0,
        verbose=a.verbose,
        sessIdRef=0,
    )
    result, result_msg = login_object.login2()

    if result == 1:
        print("Login successful! Result:", result, result_msg)
        r = login_object.get_firewall_info()
        print(r)
        print()
    else:
        print("Login failed! Result:", result, result_msg)
        print()

    # TODO: Do some test functions...


    # Log out
    result = login_object.logout()

    exit()