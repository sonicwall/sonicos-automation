# SonicWall Cloud Secure Edge Quickstart Script

## Overview

The `cse-quickstart.py` script is designed to automate CSE's configuration. It provides a quick and efficient way to configure CSE on multiple firewalls.

## Features

- Auto-enables CSE if disabled.
- Configures the specified interfaces for CSE. If not specified, it defaults to `X0`.
- Synchronizes and confirms the configuration is applied.
- SonicOS API can be auto-enabled via SSH if it is disabled. It will also be auto-disabled when done.

## Prerequisites

Before running the script, ensure the following:

- Python 3.x is installed on your system.
- Required dependencies are installed. You can install them using:
  ```
  pip install -r requirements.txt
  ```

## Usage

To execute the script, run the following command:

```bash
python cse-quickstart.py TARGET-FIREWALL [options]
```

### Options

- `--interface`: A comma-separated list of interfaces to be configured for CSE. Example: `X0,X2,X4`. Default is `X0`.
- `--sshport`: Firewall's SSH Management port if SonicOS API is disabled. Default is 22.

### Example

Here is an example of how to use the script:

```bash
python cse-quickstart.py 192.168.168.168 --interface X0,X5,X9
```

## Support
The scripts and code provided in this repository are offered "as-is" and are not officially supported by SonicWall 
as they fall outside the scope of our technical support services. SonicWall will not provide technical support for these scripts.

For issues related to the scripts, please open an issue in this GitHub repository.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

