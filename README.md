# SonicWall SonicOS Automation

## Overview

This collection of scripts automate certain tasks that are repetitive or time-consuming.
Refer to the other readme files for information specific to each script.

## Table of Contents
The table below lists SonicWall Advisories that have corresponding scripts available in this repository.

### SonicWall Advisories and Corresponding Scripts
| SonicWall Advisory                                                                   | Script File                                                       | Script Documentation                                      |
|--------------------------------------------------------------------------------------|-------------------------------------------------------------------|-----------------------------------------------------------|
| [SNWLID-2025-0001](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2025-0001)  | [snwlid-2025-0001_workaround.py](snwlid-2025-0001_workaround.py)  | [README-SNWLID-2025-0001.md](README-SNWLID-2025-0001.md)  |
| [SNWLID-2024-0015](https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015)  | [snwlid-2024-0015.py](snwlid-2024-0015.py)                        | [README-SNWLID-2024-0015.md](README-SNWLID-2024-0015.md)  |


### SonicWall Automation Scripts
| Description                                                                                                                                                                                                                                                  | Script File                                                                               | Script Documentation                                       |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|------------------------------------------------------------|
| Cloud Secure Edge Quickstart Script                                                                                                                                                                                                                          | [cse-quickstart.py](cse-quickstart.py)                                                    | [README-cse-quickstart.md](README-cse-quickstart.md)                       |
| Essential Credential Reset/Remediation Playbook Script<br>Automates:<br> - Bulk password resets<br> - Setting randomized temporary passwords<br> - Bulk TOTP resets<br> - Remediation checks with prioritized guidance and resources for manual remediation. | [remediation-app.py](remediation-app.py)<br>[reset_credentials.py](reset_credentials.py) | [README-reset-credentials.md](README-reset-credentials.md) |


## Support
The scripts and code provided in this repository are offered "as-is" and are not officially supported by SonicWall 
as they fall outside the scope of our technical support services. SonicWall will not provide technical support for these scripts.

For issues related to the scripts, please open an issue in this GitHub repository.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

