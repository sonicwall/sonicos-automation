# SonicWall SonicOS Automation


### Overview

The main purpose of this script is to automate the process of forcing local users to change their password on next login.
However, it can also perform other tasks, such as enabling Botnet Filtering, enabling App-based TOTP for SSLVPN users, and upgrading firmware.
Each feature can be enabled or disabled using command line arguments or in each entry in a CSV file.

It uses the SonicOS API with either Basic or CHAP authentication.
If SonicOS API is disabled (and SSH management is enabled), the script will use SSH to *temporarily* enable SonicOS API 
on the target firewall and will perform as many functions as possible via SSH if API is unavailable.
SonicOS API is auto-disabled when done if we auto-enabled it.

It is recommended to run this script after upgrading the firmware on the target firewall to the latest version.
If you use the script to upgrade the firmware, please re-run the script against the target firewall after the upgrade.

This script can be run against a single target firewall or multiple target firewalls.
To run against multiple target firewalls, the script expects a CSV file containing a list of target firewalls with
management credentials, SSH management port, and other options. Please refer to the sample CSV provided for the expected format.

The script will prompt for the management credentials if run against a single target firewall (without an input CSV file).

Results are logged in a text file within the `runs` directory, inside a timestamped directory.

### Features
- Downloads Tech Support Report (TSR), Trace logs, and exports the preferences (EXP).
- Force local users to change password on next login
- Reset password to a temporary password
- Enable Botnet Filtering
- Enable App-based TOTP for SSLVPN users
- Upgrade firmware


### Flow of the script
Identify the number of targets and run the following routine for each valid target:
   1. Check if the target firewall has SonicOS API enabled.
   2. If SonicOS API is disabled, try to enable it using SSH Management.
      - Gives up if unable to enable SonicOS API/unable to SSH into the target firewall.
   3. Retrieve firewall information (model, firmware version, etc.).
   4. Download a TSR. Trace logs, and export the preferences (EXP).
   5. Alerts the user if the target firewall is vulnerable to CVE-2024-40766 / SNWLID-2024-0015.
         - If a firmware image is provided via CLI argument or in the CSV, the script will upgrade the firmware.
         - If the target firewall is not vulnerable to CVE-2024-40766 / SNWLID-2024-0015, the script will proceed.
   6. Retrieve the list of users.
   7. Force all local users to change their password on next login, skipping domain users and special user entries.
      - Optionally, the script can reset each user's password to a specified temporary password. The password can be set using the command line arguments or in the CSV file.
   8. Checks if Botnet Filtering is licensed and enabled. If licensed but not enabled, the script can enable it for you.
   9. Checks if App-based TOTP or Email-based OTP is enabled on the `SSLVPN Services` group. If not enabled, the script can enable it for you.
      - GEN5 does not support TOTP (only Email-based OTP). It requires an email address configured for each user. The script will only recommend enabling Email-based OTP.
   10. If SonicOS API was disabled, disable it again using SSH Management.
   11. Logout any active sessions.


### Prerequisites
- Python 3.6 or later
  - requests module (install using `pip install requests`)
  - paramiko module (install using `pip install paramiko`)
  - Install all requirements using `pip install -r requirements.txt`
- SonicWall GEN5, GEN6 or GEN7 firewall with SonicOS API enabled (or SSH management enabled for automatic enabling/disabling of SonicOS API).
  - Basic and CHAP authentication are supported.
- SSH Management access is recommended and may be required for certain actions. This is especially notable for GEN5 and GEN6.


### Usage
1. Run the script against a single target firewall.
   - `python main.py 192.168.168.168`
   - The script will prompt for the management credentials.
   - You can specify a non-default SSH port using the -s <port> flag.
   - You can enable verbose mode using the -v flag.
   - Enable TOTP for SSLVPN users using the -et flag.
   - Enable Botnet Filtering using the -eb flag.
   - Set a temporary password when setting the force password change flag using the -tp <temp_password> flag.
   - Upgrade firmware using the -uf <firmware_image> argument or providing the path to a firmware image in the CSV.
   - Use the `-h` argument to get more details, including additional CLI arguments.
2. Run the script against multiple target firewalls.
   - `python main.py firewalls.csv`
   - The CSV file should contain a comma-separated list of target firewalls with management credentials.
     - Example:
       ```
       target_fw,admin_user,admin_password,target_ssh_mgmt_port,enable_totp,enable_botnet_filtering,temporary_password,upgrade_to_firmware_image
       192.168.168.168,admin,password,22,false,true,TempPassword,"C:\Users\jdoe\Downloads\firmware_image.sig"
       IPorHostname1,AdminUsername1,AdminPassword1,SSHMgmtPort,true|false,true|false,TemporaryPassword,
       IPorHostname2,AdminUsername2,AdminPassword2,SSHMgmtPort,true|false,true|false,TemporaryPassword,
       IPorHostname3,AdminUsername3,AdminPassword3,SSHMgmtPort,true|false,true|false,TemporaryPassword,"PathToFirmwareImage"
       ```
   - You can prepend lines your CSV file with `#` to comment the line/skip the line.
   - The firmware path option can be left blank to skip the firmware upgrade.


## Support
The scripts and code provided in this repository are offered "as-is" and are not officially supported by SonicWall 
as they fall outside the scope of our technical support services. SonicWall will not provide technical support for these scripts.

For issues related to the scripts, please open an issue in this GitHub repository.


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

