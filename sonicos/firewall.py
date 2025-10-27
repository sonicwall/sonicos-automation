# Imports
import json
import requests
from datetime import datetime
from os import listdir, path, mkdir
from time import sleep
from common.utils import (
    generate_timestamp,
    tprint,
    write_to_file,
)
from sonicos.api import (
    create_admin_session,
    create_admin_session_chap,
    hide_certificate_warnings,
    get_request,
    post_request,
    put_request,
    patch_request,
    delete_request,
    commit_pending,
    restart_sonicos,
    logout,
    enable_sonicos_api_ssh,
    disable_sonicos_api_ssh,
    check_totp_status,
    enable_totp_ssh,
    download_tsr,
    export_preferences,
    download_audit_log,
    upload_firmware,
    boot_firmware,
    get_ssh_session,
    get_users_ssh,
    force_password_change_ssh
)
from sonicos.utils import (
    ensure_admin_api_session,
    wait_for_upgrade
)
import common.constants as constants
from sonicos.api2 import Login


class Firewall:
    def __init__(self, url, username, password, sshport="22"):
        self.url = url.rstrip("/")
        if "http://" not in self.url and "https://" not in self.url:
            self.url = f"https://{self.url}"
        self.api_base = f"{self.url}/api/sonicos/"
        self.host = url.split("//")[-1].split(":")[0]
        if sshport:
            self.ssh_port = str(sshport)
        self.username = username
        self.password = password
        self.session = None
        self.ssh_session = None
        self.ssh_connection = None
        self.login_session = None
        self.firmware = None
        self.model = None
        self.serial = None
        self.gen = None

    def login(self):
        self.session = ensure_admin_api_session(api_host=self.url,
                                                api_user=self.username,
                                                api_password=self.password)

        if not self.session:
            print(f"{generate_timestamp()}: ERROR: Unable to log in to the firewall.")
            return False
        elif isinstance(self.session, tuple) and self.session[0] is False:
            print(f"{generate_timestamp()}: ERROR: {self.session[1]}")
            return False
        elif isinstance(self.session, tuple):
            print(f"{generate_timestamp()}: INFO: {self.session[1]}")
            self.session = self.session[0]

        if isinstance(self.session, requests.Session):
            print(f"{generate_timestamp()}: INFO: Successfully logged in to the firewall.")
            # return True

        # Get the firewall model, serial number, and firmware version.
        if not self.get_device_info():
            print(f"{generate_timestamp()}: ERROR: Unable to get device information.")
            return False
        else:
            print(f"{generate_timestamp()}: INFO: Device information retrieved successfully.")
            print(f"{generate_timestamp()}: INFO: Model: {self.model}, Serial: {self.serial}, Firmware: {self.firmware}, Generation: {self.gen}")
            return True

    def login2(self):
        self.login_session = Login(ipaddress=self.host,
                                   userid=self.username,
                                   passwd=self.password,
                                   admin_mode="config",
                                   http_type="https",
                                   brwsr_cache=0,
                                   verbose=0,
                                   sessIdRef=0)

        logged_in, rmsg = self.login_session.login2()
        if logged_in == 1:
            print(f"{generate_timestamp()}: INFO: Successfully logged in to the firewall.")
            return True
        else:
            print(f"{generate_timestamp()}: ERROR: Unable to log in to the firewall.")
            return False

    def logout(self):
        url = self.api_base.split("/api/sonicos/")[0]
        return logout(fw=url, session=self.session, firewall_generation=self.gen)

    def commit_pending(self):
        url = self.api_base.split("/api/sonicos/")[0]
        response = commit_pending(url, self.session)
        res_code = response['status']['info'][0]['code']
        res_msg = response['status']['info'][0]['message']
        if res_code == "E_OK" and res_msg == "Changes made.":
            return True, res_msg
        else:
            return False, res_msg

    def restart_sonicos(self):
        url = self.api_base.split("/api/sonicos/")[0]
        return restart_sonicos(url, self.session)

    def get_request(self, endpoint):
        return get_request(self.api_base, self.session, endpoint)

    def post_request(self, endpoint, data):
        return post_request(self.api_base, self.session, endpoint, data)

    def put_request(self, endpoint, data):
        return put_request(self.api_base, self.session, endpoint, data)

    def patch_request(self, endpoint, data):
        return patch_request(self.api_base, self.session, endpoint, data)

    def delete_request(self, endpoint):
        return delete_request(self.api_base, self.session, endpoint)

    def get_device_info(self):
        info = self.get_request("version")
        if info.get("firmware_version", None):
            self.model = info["model"]
            self.serial = info["serial_number"]
            self.firmware = info["firmware_version"]

            if self.firmware.split(" ")[-1].startswith('7'):
                self.gen = 7
            elif self.firmware.split(" ")[-1].startswith('6'):
                self.gen = 6
            elif self.firmware.split(" ")[-1].startswith('8'):
                self.gen = 8

            constants.set_fw_model(self.model)
            constants.set_fw_generation(self.gen)
            return True

        return False

    def get_firewall_info(self):
        return {
            "model": self.model,
            "serial_number": self.serial,
            "firmware": self.firmware,
            "generation": self.gen
        }

    def download_tsr(self, filepath):
        url = self.api_base.split("/api/sonicos/")[0]
        return download_tsr(fw=url, session=self.session, filepath=filepath, firewall_generation=self.gen)

    def export_preferences(self, filepath):
        if self.gen == 5 or self.gen == 6:
            if self.login_session:
                return export_preferences(fw=self.host, session=self.login_session, filepath=filepath, firewall_generation=self.gen)
            else:
                li = self.login2()
                if li:
                    return export_preferences(fw=self.host, session=self.login_session, filepath=filepath, firewall_generation=self.gen)
                else:
                    return False
        elif self.gen == 7 or self.gen == 8:
            url = self.api_base.split("/api/sonicos/")[0]
            return export_preferences(fw=url, session=self.session, filepath=filepath, firewall_generation=self.gen)

    def upload_firmware(self, filepath):
        """
        Uploads the firmware file to the firewall.
        :param filepath: Path to the firmware file.
        :return: True if successful, False otherwise.
        """
        url = self.api_base.split("/api/sonicos/")[0]
        if self.gen == 5 or self.gen == 6:
            print("Not implemented.")
            return False
        elif self.gen == 7 or self.gen == 8:
            return upload_firmware(fw=url, session=self.session, filepath=filepath, firewall_generation=self.gen)
        print("Unhandled firewall generation.")
        return False

    def boot_uploaded_firmware(self):
        """
        Boots the uploaded firmware on the firewall.
        :param uploaded: If True, the firmware has been uploaded and is ready to be booted.
        :return: True if successful, False otherwise.
        """
        url = self.api_base.split("/api/sonicos/")[0]
        if self.gen == 5 or self.gen == 6:
            print("Not implemented.")
            return False
        elif self.gen == 7 or self.gen == 8:
            return boot_firmware(fw=url, session=self.session, firewall_generation=self.gen)

    def wait_for_reboot(self, timeout=480):
        print(f"{generate_timestamp()}: INFO: Waiting for the firewall to come back online.")
        # This is used to track how long we're waiting for the firewall to reboot and calculate the timeout.
        start_time = datetime.now()

        # Initial sleep for the reboot.
        sleep(30)

        # We try to reach the firewall and wait 30 seconds if we can't establish a new session.
        while True:
            try:
                res = requests.get(f"{self.url}", verify=False, timeout=10)
                print(res.status_code, res.reason)
                if res.status_code == 200:
                    print(f"{generate_timestamp()}: INFO: Firewall login page is reachable.")

                    # This section tries to establish a new session after the reboot.
                    logged_in = False
                    login_attempts = 0
                    while not logged_in:
                        logged_in = self.login()
                        if not logged_in and login_attempts <= 5:
                            login_attempts += 1
                            print(f"{generate_timestamp()}: INFO: Unable to log in to the firewall. Waiting to retry...")
                            sleep(30)
                        if login_attempts >= 5:
                            print(f"{generate_timestamp()}: ERROR: Unable to log in to the firewall.")
                            return False
                    print(f"{generate_timestamp()}: INFO: Firewall is back online. (Logged in)")
                    return True

                # If the firewall is not reachable, wait and try again.
                else:
                    print(f"{generate_timestamp()}: INFO: Firewall login page is not reachable ({res.status_code, res.reason}). Waiting...")
                    sleep(30)

            # When the request fails, we wait and try again.
            except requests.exceptions.RequestException as e:
                print(f"{generate_timestamp()}: INFO: Firewall login page is not reachable (timed out). Waiting...")
                sleep(30)

            # If the timeout is reached, exit the loop. The firewall is not reachable after the reboot.
            # Maybe the firewall's IP changed?
            if (datetime.now() - start_time).seconds > timeout:
                print(f"{generate_timestamp()}: ERROR: Timeout reached. Firewall is not back online.")
                return False

    def get_ssh_session(self):
        self.ssh_session, self.ssh_connection = get_ssh_session(self.url, self.ssh_port, self.username, self.password)
        if self.ssh_session:
            return True
        else:
            return False
