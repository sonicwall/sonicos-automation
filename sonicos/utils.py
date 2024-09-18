import requests
from time import sleep
from common.utils import generate_timestamp
from common.arguments import a
from sonicos.api import (
    create_admin_session,
    create_admin_session_chap,
    hide_certificate_warnings,
    commit_pending,
    upload_firmware,
    boot_firmware
)
import common.constants as constants


# This function tries to ensure an admin API session is created.
# It first tries Basic auth. If that fails, it tries CHAP MD5 Digest auth.
# If the SonicOS API service is disabled, it will attempt to enable it via SSH Management.
def ensure_admin_api_session(api_host, api_user=None, api_password=None, sshport='22'):
    if "https://" in api_host:
        api_base = f"{api_host}"
    else:
        api_base = f"https://{api_host}"

    try:
        # Hide the certificate warnings
        hide_certificate_warnings()

        # Create an admin session (Basic auth)
        api_session, json_response = create_admin_session(
            firewall=api_base,
            admin_user=api_user,
            admin_password=api_password,
            sshport=sshport
        )

        # If SonicOS API is not enabled, the attempt may have successfully enabled SonicOS API via SSH.
        # This will check if the API was successfully enabled via SSH and if so, will retry.
        if isinstance(api_session, str):
            if api_session == "E_DISABLED":
                api_session, json_response = create_admin_session(
                    firewall=api_base,
                    admin_user=api_user,
                    admin_password=api_password,
                    sshport=sshport
                )
            elif api_session == "E_GIVE_UP":
                # raise Exception("Unable to enable SonicOS API via SSH. Giving up. Please enable SonicOS API (with Basic and CHAP authentication) manually.")
                print(f"{generate_timestamp()}: Unable to enable SonicOS API via SSH. Giving up. Please enable SonicOS API (with Basic and CHAP authentication) manually.")
                return False
            elif api_session == "E_GEN5":
                print(f"{generate_timestamp()}: The firewall appears to be a GEN5 device. This script currently does not support GEN5.")
                return False

        # If the Basic auth session failed, the object will be None or an Exception. Try CHAP auth instead.
        if api_session is None:
            print(f"{generate_timestamp()}: Unable to create an admin session using Basic auth. Trying CHAP MD5 Digest auth...")
            api_session, json_response = create_admin_session_chap(
                firewall=api_base,
                admin_user=api_user,
                admin_password=api_password,
                sshport=sshport
            )

        # If the CHAP auth session failed, the object will be None or an Exception object.
        if api_session is None:
            raise Exception("Unable to create an admin session using Basic or CHAP MD5 Digest auth.")
        elif isinstance(api_session, Exception):
            raise api_session

        # Check for 'API_AUTH_PASSWORD_UPDATE' in the auth code.
        try:
            if "API_AUTH_PASSWORD_UPDATE" in json_response.get("status", {}).get("info", [{"auth_code": ""}])[0]["auth_code"]:
                print(f"{generate_timestamp()}: Please log in and change the management password, then re-run the tool.")
                exit()
        except KeyError:
            pass

        return api_session

    except KeyboardInterrupt:
        print(f"\n{generate_timestamp()}: Stopped!")
        exit()
    except Exception as e:
        print(f"{generate_timestamp()}: Error creating an API session: {e}")
        # Disabled this exit to allow contining to the next fw.
        # exit()


# Function to handle the upload firmware prompt and associated actions.
def firmware_upgrade_prompt(fw, session):
    # Users should now be asked if they want to upload and boot a new firmware image now.
    # The user would then be prompted to specify a file path to the firmware image.
    print(f"\n{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Would you like to upload and boot a new firmware image now? [y/N]: ", end=' ')
    upgrade = input("")

    if len(upgrade) == 0:
        upgrade = 'n'
    elif len(upgrade) > 0:
        upgrade = upgrade.lower()

    if upgrade == 'y' or upgrade == 'yes':
        print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Please specify the path to the firmware image.")
        image_path = input("Firmware image path: ")
        if len(image_path) == 0:
            print(
                f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: No firmware image path specified. Skipping the firmware upgrade.")
        else:
            print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Uploading the firmware image...")
            try:
                upload_firmware(fw, session, image_path, firewall_generation=constants.get_fw_generation())
            except Exception as e:
                print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Error uploading the firmware image: {e}")
                return False
            print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Done uploading the firmware image.")
            print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Booting the firmware image...")
            try:
                boot_firmware(fw, session, firewall_generation=constants.get_fw_generation())
            except Exception as e:
                print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Error booting the firmware image: {e}")
                return False
            return True

    elif upgrade == 'n' or upgrade == 'no':
        print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Skipping the firmware upgrade.")
        return False
    else:
        print(f"{generate_timestamp()}: {constants.get_fw_model()} - {fw}: Invalid input. Skipping the firmware upgrade.")
        return False
