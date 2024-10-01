import time
import re
import requests
import hashlib
import os


class Login:
    def __init__(self, ipaddress, userid, passwd, admin_mode, http_type, brwsr_cache, verbose, sessIdRef):
        self.ipaddress = ipaddress
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
            "firmware_version": self.firmware_version
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

        result_code = result_code.group(1)
        restart_needed = restart_needed.group(1)

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

        return result_code, restart_needed

    def login2(self, sess_id_ref=None):
        print(f"ipaddress    = {self.ipaddress}\n"
              f"userid       = {self.userid}\n"
              f"passwd       = {self.passwd}\n"
              f"adminMode    = {self.admin_mode}\n"
              f"httpType     = {self.http_type}\n"
              f"brwsrCache   = {self.brwsr_cache}\n"
              f"verbose      = {self.verbose}\n")

        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        if self.http_type == 'https':
            ssl = True
        else:
            ssl = False

        # Start the login process
        ret = self.start_login_process2(sess_id_ref)
        return ret

    def start_login_process2(self, sess_id_ref):
        post_data = {
            "uName": self.userid,
            "pass": self.passwd,
            "adminMode": "3"
        }

        if self.admin_mode != 3:
            post_data["adminMode"] = self.admin_mode

        if self.verbose:
            print(f"Fetching {self.http_type}://{self.ipaddress}/sgmsAuth.xml")

        self.session.headers.update({"User-Agent": "SGMS/8.0"})
        response = self.get_request("sgmsAuth.xml", print_content=False)

        authSessId = None
        authSessId = re.search(f"<authSessId>(.*)</authSessId>", response.text)
        if authSessId:
            authSessId = authSessId.group(1)
            self.sessIdRef = authSessId
            print(f"Found authSessId: {authSessId}\n")
        else:
            print("No authSessId found. The rest of this process will fail.\n")

        if self.verbose:
            print(f"Posting to {self.http_type}://{self.ipaddress}/auth4.cgi\n")

        response = self.post_request("auth4.cgi", post_data=post_data, print_content=False)

        # Adds the "Cookie" header to "SessId=<sessIdRef>" and updates the session cookies with the SessId.
        # Subsequent requests will need this.
        self.session.headers.update({"Cookie": f"SessId={self.sessIdRef}"})
        self.session.cookies.update({"SessId": self.sessIdRef})

        # Gets firewall state info.
        response = self.get_request("firewallState.xml", print_content=False)

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
            if self.verbose:
                print(f"Logged in successfully!\n"
                      f"Serial Number: {serial_number}\n"
                      f"Model: {model}\n"
                      f"Firmware Version: {firmware_version}\n")
            return 1
        else:
            return 0

    def handle_navigation_view2(self):
        nav = self.get_request("navigationView.html", print_content=False)

        # GEN6
        csrf_token_match = re.search(r'csrfToken = "(.*)"', nav.text)
        if csrf_token_match:
            csrf_token = csrf_token_match.group(1)
            self.csrf_token = csrf_token
            print(f"CSRF token found (1): {csrf_token}")
            print()
        else:
            print("No CSRF token found (1).")
            print()

            # GEN5
            nav = self.get_request("outlookView.html", print_content=False)

            csrf_token_match = re.search(r'csrfToken = "(.*)"', nav.text)
            if csrf_token_match:
                csrf_token = csrf_token_match.group(1)
                self.csrf_token = csrf_token
                print(f"CSRF token found (2): {csrf_token}")
                print()
            else:
                print("No CSRF token found (2).")
                print()

    def logout(self):
        print("\nTrying to log out...")

        response = self.get_request("logout.html", print_content=False)

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
        response = self.post_request("main.cgi", post_data=post_data, print_content=False)

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

    def get_request(self, uri, print_content=False):
        if self.verbose:
            print(f"Fetching {self.http_type}://{self.ipaddress}/{uri} ...")
        response = self.session.get(f"{self.http_type}://{self.ipaddress}/{uri}", verify=False)

        # Print the headers
        if print_content:
            print(f"------------------- {uri.upper()} -------------------")
            self.print_response(response, print_content=print_content)
            print("------------------- END -------------------\n\n")
        return response

    def post_request(self, uri, post_data, file_data=None, print_content=False, timeout=60):
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

    def upload_firmware(self, fw_path):
        fm_filename = os.path.split(fw_path)[-1]

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
                                     timeout=300)
        r_code = 0
        rn_code = 0
        try:
            r_code, rn_code = self.parse_xml_response(response)
            return response, r_code, rn_code
        except Exception as e:
            pass

        return response, r_code, rn_code

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

        try:
            response = self.post_request("boot.cgi",
                                         post_data=data,
                                         print_content=True,
                                         timeout=30)
            successful = re.search(r"(The SonicWall is restarting)", response.text)
        except requests.exceptions.Timeout as e:
            print("Timeout error:", e)
            print("The boot action likely started. Please check the device status manually in a few minutes.")
            successful = True
        except requests.exceptions.ConnectionError as e:
            print("Connection error:", e)
            print("The boot action likely started. Please check the device status manually in a few minutes.")
            successful = True

        if successful:
            if self.verbose:
                print("Firmware boot successful!")
            return True
        return False

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
        rc, rn = self.parse_xml_response(response)

        if rc == 1:
            print("Botnet Filtering enabled successfully!")
            rd = {
                "status": {
                    "success": True
                }
            }
            return rd


# Test
if __name__ == "__main__":
    login_object = Login(
        # ipaddress="192.168.0.107",  # 6
        ipaddress="192.168.0.106",  # 5
        userid="admin",
        passwd="password",
        admin_mode="config",
        http_type="https",
        brwsr_cache=0,
        verbose=1,
        sessIdRef=0,
    )
    result = login_object.login2()

    if result == 1:
        print("Login successful! Result:", result)
        print()
    else:
        print("Login failed! Result:", result)
        print()

    # TODO: Do some test functions...


    # Log out
    result = login_object.logout()

    exit()