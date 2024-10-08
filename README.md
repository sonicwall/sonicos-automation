# SonicWall SonicOS Automation

## SonicWall Bulk Change Script: Force local user to change password on next login

This script is used to force local users to change their password on next login.
It uses the SonicOS API with either Basic or CHAP authentication.
If SonicOS API is disabled (and SSH management is enabled), the script will use SSH to *temporarily* enable SonicOS API on the target firewall.
SonicOS API is auto-disabled when done if we auto-enabled it.

This script can be run against a single target firewall or multiple target firewalls.
To run against multiple target firewalls, the script expects a CSV file containing a list of target firewalls with management credentials and SSH management port.

The script will prompt for the management credentials if run against a single target firewall (without aN input CSV file).

Results are logged in a text file within the `runs` directory, inside of a timestamped directory.

Additionally, the script can offer suggestions to improve your security posture, such as enabling Botnot Filtering or MFA for SSLVPN users.


### Flow of the script
Identify the number of targets and run the following routine for each valid target:
   1. Check if the target firewall has SonicOS API enabled.
   2. If SonicOS API is disabled, try to enable it using SSH Management.
      - Gives up if unable to enable SonicOS API/unable to SSH into the target firewall.
   3. Retrieve firewall information (model, firmware version, etc.).
   4. Alerts the user if the target firewall is vulnerable to CVE-2024-40766 / SNWLID-2024-0015.
         - For GEN7 firewalls, asks the user if they would like to upgrade now.
            - If so, the user is prompted to provide a file path to the firmware image. The script will upload and boot the image. The script will not proceed with this target. Please re-run the script against this target after the upgrade.
            - If the user chooses not to upgrade, the script will not proceed with this target.
         - For GEN6 firewalls, prompts the user to upgrade the firmware manually. The script will not proceed with this target. Please upgrade the firmware and re-run the script against this target.
         - If the target firewall is not vulnerable to CVE-2024-40766 / SNWLID-2024-0015, the script will proceed.
   5. Use SonicOS API to retrieve the list of users.
   6. Use SonicOS API to force all local users to change their password on next login, skipping domain users and special user entries.
      - Optionally, the script can reset each user's password to a specified temporary password. The password can be set using the command line arguments or in the CSV file.
   7. Checks if Botnet Filtering is licensed and enabled. If licensed but not enabled, the script can enable it for you.
   8. Checks if App-based TOTP or Email-based OTP is enabled on the `SSLVPN Services` group. If not enabled, the script can enable it for you.
   9. If SonicOS API was disabled, disable it again using SSH Management.


### Prerequisites
- Python 3.6 or later
  - requests module (install using `pip install requests`)
  - paramiko module (install using `pip install paramiko`)
  - Install all requirements using `pip install -r requirements.txt`
- SonicWall GEN6 or GEN7 firewall with SonicOS API enabled (or SSH management enabled for automatic enabling/disabling of SonicOS API).
  - Basic and CHAP authentication are supported.
- SSH Management access is recommended and may be required for certain actions. This is especially notable for GEN6.


### Usage
1. Run the script against a single target firewall.
   - `python main.py 192.168.168.168`
   - The script will prompt for the management credentials.
   - You can specify a non-default SSH port using the -s <port> flag.
   - You can enable verbose mode using the -v flag.
   - Use the `-h` argument to get more details, including additional CLI arguments.
2. Run the script against multiple target firewalls.
   - `python main.py firewalls.csv`
   - The CSV file should contain a comma-separated list of target firewalls with management credentials.
     - Example:
       ```
       target_fw,admin_user,admin_password,target_ssh_mgmt_port,enable_totp,enable_botnet_filtering,temporary_password
       192.168.168.168,admin,password,22,false,true,TempPassword,
       IPorHostname1,AdminUsername1,AdminPassword1,SSHMgmtPort,true|false,true|false,TemporaryPassword
       IPorHostname2,AdminUsername2,AdminPassword2,SSHMgmtPort,true|false,true|false,TemporaryPassword
       IPorHostname3,AdminUsername3,AdminPassword3,SSHMgmtPort,true|false,true|false,TemporaryPassword
       ```
   - You can prepend lines your CSV file with `#` to comment the line/skip the line.


## Support
The scripts and code provided in this repository are offered "as-is" and are not officially supported by SonicWall 
as they fall outside the scope of our technical support services. SonicWall will not provide technical support for these scripts.

For issues related to the scripts, please open an issue in this GitHub repository.


## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

