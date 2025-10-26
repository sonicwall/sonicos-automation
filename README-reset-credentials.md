# SonicWall SonicOS Automation
## Essential Credential Reset Tool


### Overview

The Essential Credential Reset Tool (`reset_credentials.py`) is a comprehensive security analysis and remediation script 
designed to help administrators identify and address credential-related security configurations across SonicWall firewalls.
This tool performs automated security assessments based on SonicWall's "Remediation Playbook" and "Essential Credential Reset" 
guidelines and provides detailed reporting on configuration items that require your attention.

The primary purpose is to analyze SonicOS configurations and produce actionable reports rather than automatically making changes.
This approach ensures administrators maintain full control over their security remediation process while receiving 
comprehensive guidance on what needs to be addressed.

It uses the SonicOS API with Basic or CHAP authentication across SonicOS generation 6, and 7.
If SonicOS API is disabled (and SSH management is enabled), the script will use SSH to *temporarily* enable SonicOS API on the target firewall.
SonicOS API is auto-disabled when done if we auto-enabled it.

This script can be run against a single target firewall or multiple target firewalls using a CSV input file.
Results are logged and exported to timestamped directories within the `runs` folder.


### Key Features

#### Security Analysis and Reporting
- **Comprehensive Configuration Audit**: Analyzes various configuration areas for credential-related configuration
- **Detailed Reports**: Outputs findings in both rich summary tables and a markdown-formatted report
- **Rich Summary Tables**: Generates priority-based summary tables with actionable recommendations
- **Export Capabilities**: Optionally, downloads TSR (Tech Support Report), trace logs, and configuration exports from target firewalls prior to making any changes

#### Credential Management
- **Force Local User Password Reset**: Forces all local users to change passwords on next login
- **Temporary Password Assignment**: Can set a specified temporary password to assign to all local users
- **Random Password Generation**: Can create secure temporary random passwords for each user meeting basic complexity requirements
- **TOTP Unbinding**: Can reset TOTP bindings from local users

#### Multi-Firewall Support
- **Batch Processing**: Process single or multiple firewalls using CSV input files
- **Individual Firewall Targeting**: Can target single firewalls via command line arguments


### Web User Interface

The Essential Credential Reset Tool includes a web-based user interface that provides an intuitive way to perform
security analysis and credential management operations without requiring command-line usage.

#### Setup and Usage

To setup the web interface:

```bash
# Clone the repository
git clone https://github.com/sonicwall/sonicos-automation.git

# Navigate to the directory you cloned to
# Create a new virtual environment
python3 -m venv venv

# Active the virtual environment
## On Windows
venv\Scripts\activate

## On macOS/Linux
source venv/bin/activate

# Install required dependencies
pip install -r requirements.txt

# Start the tool - refer to the section below to customize the host/port/debug settings
python3 remediation-app.py
```

To launch the web interface:

```bash
# Start the web server (default: http://127.0.0.1:8080)
python remediation-app.py

# Specify a different port
python remediation-app.py --port 9000

# Bind to all interfaces (allows remote access)
python remediation-app.py --host 0.0.0.0 --port 8080

# Enable debug mode for development
python remediation-app.py --debug
```

Once started, open your web browser and navigate to the displayed URL (typically `http://127.0.0.1:8080`).

#### Web Interface Features

- **Interactive Dashboard**: Modern web interface with intuitive navigation
- **Single Target Operations**: Point-and-click interface for individual firewall analysis
- **Batch Operations**: Upload CSV files and manage multiple firewall operations
- **Real-time Progress**: Live progress monitoring with detailed step-by-step updates  
- **Results Viewer**: Interactive display of analysis results and reports
- **Built-in Help**: Comprehensive help documentation integrated within the web app
- **Download Reports**: Direct download of generated reports, TSR files, and configuration exports

#### Requirements for Web Interface

- Modern web browser (Chrome, Firefox, Safari, Edge)
- Network connectivity between your browser and the server
- Same Python requirements as the command-line tool

Note: The web interface includes comprehensive built-in help and documentation, eliminating the need for external references during operation.


### Security Configuration Areas Analyzed

The tool analyzes the configuration areas as outlined in the "Remediation Playbook" and "Essential Credential Reset" articles 
and provides specific remediation guidance for each finding.

Refer to the following links for detailed information on the configuration areas analyzed:
- [Remediation Playbook](https://www.sonicwall.com/support/knowledge-base/remediation-playbook/250916130050523)
- [Essential Credential Reset](https://www.sonicwall.com/support/knowledge-base/essential-credential-reset/250909151701590)

### Prerequisites

- **Python Requirements**:
  - Python 3.6 or later
  - Required modules: `requests`, `paramiko`, `rich`
  - Install all requirements: `pip install -r requirements.txt`

- **SonicWall Firewall Requirements**:
  - SonicWall Generation 6 or 7 firewall
  - SonicOS API enabled (or SSH management enabled for automatic API enabling)
  - Administrative credentials with sufficient privileges to read configurations and manage users
  - Basic and CHAP authentication are supported for SonicOS API

- **Network Requirements**:
  - HTTPS Management access to target firewall(s)
  - SSH access to target firewall(s) (if API auto-enabling is needed)

- **Web Interface Requirements** (if using web UI):
  - Modern web browser (Chrome, Firefox, Safari, Edge)
  - Network connectivity between your browser and the server hosting the web interface


### Usage

The Essential Credential Reset Tool can be used in two ways:
- **Web Interface**: User-friendly browser-based interface (recommended for most users)
- **Command Line**: Direct script execution for automation and advanced use cases

#### Web Interface Usage
For an intuitive graphical interface, see the [Web User Interface](#web-user-interface) section above and the Documentation page on the web interface.

#### Command Line Usage

##### Single Firewall Target
```bash
# Basic security analysis, interactive admin login, no changes made to the target firewall, most output is printed to console
python reset_credentials.py 192.168.1.1

# With exports enabled
python reset_credentials.py 192.168.1.1 --export-tsr --export-settings --export-tracelogs

# Force password changes with a specified temporary password. Note: password will be modified to meet complexity requirements if needed
python reset_credentials.py 192.168.1.1 --force-password-change --temp-password "TempPass123!"

# Force password changes with random passwords
python reset_credentials.py 192.168.1.1 --force-password-change --randomize-password

# Unbind TOTP from all users
python reset_credentials.py 192.168.1.1 --unbind-totp

# Combined operations
python reset_credentials.py 192.168.1.1 --force-password-change --randomize-password --unbind-totp --export-tsr

# Specify a non-default SSH management port
python reset_credentials.py 192.168.1.1 --sshport 2222

# Silent mode for reduced output
python reset_credentials.py 192.168.1.1 --silent

# Suppress the summmary table output
python reset_credentials.py 192.168.1.1 --no-summary

# Combined operations
python reset_credentials.py 192.168.1.1 --sshport 2222 --force-password-change --randomize-password --unbind-totp --export-tsr --silent --no-summary
```

#### Multiple Firewall Targets (CSV)
##### Multiple Firewall Targets (CSV)
The CSV file can also control the key operations for each firewall
```bash
# Process multiple firewalls from CSV
python reset_credentials.py firewalls.csv

# Verbose output for troubleshooting
python reset_credentials.py firewalls.csv --verbose

# Silent mode for automated processing
python reset_credentials.py firewalls.csv --silent

#### Command Line Arguments
- `target` : Target firewall IP/hostname or CSV file path (positional argument, required).
- `--force-password-change` : Force all local users to change passwords on next login.
- `--temp-password` : Set specific temporary password for users. This password will be modified to meet complexity requirements if needed.
- `--randomize-password` : Generate random temporary passwords for each user meeting complexity requirements.
- `--unbind-totp` : Remove TOTP bindings from all local users.
- `--export-tsr` : Download Tech Support Report (TSR) prior to making any changes or remediation playbook checks.
- `--export-settings` : Export firewall preferences (EXP) file prior to making any changes or remediation playbook checks.
- `--export-tracelogs` : Download trace logs prior to making any changes or remediation playbook checks.
- `--sshport` : SSH management port (default: 22). Used if SonicOS API is disabled and needs to be auto-enabled.
- `--verbose` : Enable more detailed output
- `--silent` : Suppresses non-essential printed output
- `--no-summary` : Suppress the summary table output from the console.


### CSV File Format

The tool supports both header-based and legacy CSV formats for batch processing:

#### Header-Based Format (Recommended)
```csv
target_fw,admin_user,admin_password,target_ssh_mgmt_port,temporary_password,unbind_totp,force_password_change,randomize_temp_password
192.168.1.1,admin,password123,22,TempPass123!,false,true,false
192.168.1.2,admin,password456,2222,,true,true,true
```

#### CSV Field Descriptions
- `target_fw`: Firewall IP address or hostname
- `admin_user`: Administrative username
- `admin_password`: Administrative password (use `<comma>` for literal commas)
- `target_ssh_mgmt_port`: SSH management port (default: 22)
- `temporary_password`: Temporary password for user resets
- `unbind_totp`: Remove TOTP bindings (true/false)
- `force_password_change`: Force password changes (true/false)  
- `randomize_temp_password`: Generate random passwords (true/false)


### Password Complexity Requirements

The tool enforces secure password standards for temporary passwords:

- **Minimum Length**: 12 characters
- **Character Requirements**:
  - At least 1 uppercase letter
  - At least 1 lowercase letter  
  - At least 1 digit
  - At least 1 special character from: `!@$%^&*()-_=+[]{};:,.<>?/`
- **Automatic Corrections**: The tool automatically pads or modifies passwords to meet the above requirements
- **Forbidden Characters**: Automatically replaces characters that may be problematic (`#`, `|`, spaces)


### Output and Reporting

#### Summary Table Output
The tool generates rich summary tables showing:
- **Configuration Area**: What was analyzed.
- **Description**: Brief explanation of the check.
- **Priority**: Critical/High/Medium/Low priority classification.
- **Status**: Current configuration status.
- **Count**: Number of entries found.
- **Action Required**: Specific remediation steps. Refer to the markdown report for links to the relevant knowledge base resources.

#### Markdown Report
A detailed markdown report is generated in the timestamped run directory, including:
- **Firewall Information**: Model, serial number, firmware version, etc.
- **Log and Configuration Exports**: Summary of exported files (TSR, logs, configs).
- **Brief Summary**: Action items identified and completed actions.
- **Recommendations**: Step-by-step guidance for remediation actions.
- **Detailed Findings**: In-depth analysis of each configuration area with references to knowledge base articles
- **User Passwords**: If passwords were randomized, their assigned temporary passwords are included in the report.

### Considerations

#### What This Tool Does
- ✅ **Analyzes configurations** and identifies security concerns
- ✅ **Provides detailed reports** with remediation guidance
- ✅ **Downloads diagnostic files** (TSR, logs, configs)
- ✅ **Manages local user passwords** when explicitly enabled
- ✅ **Removes TOTP bindings** when explicitly enabled

#### What This Tool Does NOT Do
- ❌ **Automatically change server passwords** or shared secrets
- ❌ **Modify VPN policies** or certificates
- ❌ **Update third-party service credentials**
- ❌ **Make configuration changes** without explicit user consent
- ❌ **Store or transmit credentials** beyond the scope of the current execution, input CSV, and local markdown report

#### Best Practices
1. **Review reports thoroughly** before taking remediation actions
2. **Test changes** to critical services after updating credentials
3. **Coordinate with service providers** for credential updates
4. **Maintain backup configurations** before and after making changes
5. **Use secure methods** for credential distribution
6. **Document all remediation actions** taken

Notes:
- The tool is designed to assist administrators in identifying and prioritizing credential-related security tasks. It highlights areas that require attention but does not perform automatic remediation of all identified issues.
- Subsequent runs may yield different findings as configurations are updated, however, many findings will continue to appear even after remediation actions are taken, as the tool is looking for presence of configuration.


### Troubleshooting

#### Common Issues

**Connection Failures**
- Verify firewall IP/hostname and network connectivity
- Check that SonicOS API is enabled or SSH management is available
- Confirm administrative credentials are correct

**Authentication Errors**
- Ensure administrative user has sufficient privileges
- Check for account lockouts or password expiration
- Verify CHAP or Basic authentication are enabled for SonicOS API

**CSV Processing Issues**
- Verify CSV file format matches expected structure
- Check for special characters in passwords (use `<comma>` for commas)
- Ensure file encoding is UTF-8
- Remove any trailing spaces or hidden characters

**Permission Errors**
- Run with appropriate system permissions for file creation
- Ensure write access to the `runs` directory
- Check disk space availability for exports

#### Log Files
Execution logs are automatically created in the timestamped run directory for troubleshooting and audit purposes.
All files are stored locally and not transmitted externally.


### Version Compatibility

| SonicOS Generation | SonicOS API Support | Supported Features                                                                                                     |
|--------------------|---------------------|------------------------------------------------------------------------------------------------------------------------|
| Generation 6       | Limited API         | Complete analysis, except of features that are unavailable on Gen6, such as Clearpass/NAC and Cloud Secure Edge (CSE). |
| Generation 7       | Full API            | Complete analysis can be performed.                                                                                    |


### Support

This script is provided "as-is" and falls outside the scope of official SonicWall technical support services. 


### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
