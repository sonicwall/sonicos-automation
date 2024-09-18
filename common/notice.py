# Compares the versions to a required version.
def compare_versions(current_version, required_version, fw_gen=None):
    def version_tuple(v):
        # Split the version into major, minor, patch, and build number
        version_main, build = v.split('-')
        return tuple(map(int, version_main.split('.'))) + (int(build),)

    # Convert the versions to tuples of integers
    current_tuple = version_tuple(current_version)
    required_tuple = version_tuple(required_version)

    # Compare the two versions
    if current_tuple > required_tuple:
        print(f"Info: Version {current_version} is newer than {required_version}. We can proceed!")
        return {"vulnerable": False}

    if current_tuple == required_tuple:
        if fw_gen == 5:
            print(f"Info: {current_version} is the same as the minimum recommended version. We can proceed!")
            return {"vulnerable": False}
        elif fw_gen == 6:
            print(f"Info: Version {current_version} is the same as the minimum recommended version. We can proceed!")
            return {"vulnerable": False}
        # This logic excludes GEN7 because of a special case where I set the minimum/required version to -5036 for the check.
        # It ensures anything after -5035 is OK and any up to -5035 gets flagged.
        # -5036 is arbitrary. It's just a number that is newer than -5035 that works as a line dividing vulnerable/not.
        # GEN7 will use the logic below.

    # GEN7 will use this logic instead of the == logic above.
    # GEN5/6 will still use this logic for the < logic, but == is handled above.
    if current_tuple <= required_tuple:
        append_text = ""
        # I set the minimum/required version to -5036 for the check, so I need to adjust the message for -5035.
        if required_version == "7.0.1-5036" or required_version == "7.0.1-5035":
            required_version = "7.0.1-5035"
            append_text = "and older versions are vulnerable to CVE-2024-40766 (SNWLID-2024-0015).\nPlease upgrade to a newer firmware release, per the SonicWall Security Advisory."
        print(f"Warning: {current_version} is older than the minimum recommended version. {required_version} {append_text}")
        return {"vulnerable": True}
    else:
        print(f"Info: Version {current_version} is newer than {required_version}. We can proceed!")
        return {"vulnerable": False}


# Checks the firmware version and notifies the user if the version is vulnerable to CVE-2024-40766 / SNWLID-2024-0015.
def notice_check(firmware_version, model):
    """
    Check for notices based on the firmware version.
    """
    if firmware_version is None:
        return

    generation = None

    if firmware_version.startswith('7'):
        generation = 7
    elif firmware_version.startswith('6'):
        generation = 6
        firmware_version = firmware_version.strip('n')
    elif firmware_version.startswith('5'):
        generation = 5
        firmware_version = firmware_version.strip('o')

    # Check for CVE-2024-40766 (SNWLID-2024-0015)
    # Version numbers should not include the 'n' or 'o' suffixes for this check.
    r = False
    if generation == 7:
        # Versions 7.0.1-5035 and older are vulnerable. There are newer releases that are not vulnerable.
        # Fixed: Anything after 7.0.1-5035, but we recommend the latest.
        # The min/required version: -5036. This ensures anything after -5035 is OK and any up to -5035 gets flagged.
        # -5036 is arbitrary. It's just a number that is newer than -5035 that works as a line dividing vulnerable/not.
        r = compare_versions(firmware_version, "7.0.1-5036", fw_gen=generation)

    elif generation == 6:
        if "SuperMassive" in model or "NSsp" in model:
            # Versions older than the fixed version will be considered vulnerable. Fixed is 6.5.2.8-2n.
            # The minimum/required version to -2. This ensures anything after -2 is OK and any up to -2 are flagged.
            r = compare_versions(firmware_version, "6.5.2.8-2", fw_gen=generation)
        else:
            # Versions 6.5.4.14-109n and older are vulnerable. Fixed is 6.5.4.15-116n. The min/required version: -116.
            r = compare_versions(firmware_version, "6.5.4.15-116", fw_gen=generation)

    elif generation == 5:
        # Versions 5.9.2.14-12o and older are vulnerable. Fixed is 5.9.2.14-13o. The minimum/required version: -13.
        r = compare_versions(firmware_version, "5.9.2.14-13", fw_gen=generation)

    if r["vulnerable"]:
        cve = "CVE-2024-40766 (SNWLID-2024-0015)"
        details = """An improper access control vulnerability has been identified in the SonicWall SonicOS management access and SSLVPN, potentially leading to unauthorized resource access and in specific conditions, causing the firewall to crash.
This issue affects SonicWall Gen 5 and Gen 6 devices, as well as Gen 7 devices running SonicOS *7.0.1-5035 and older versions*.
This vulnerability is potentially being exploited in the wild. Please apply the patch as soon as possible for affected products. The latest patch builds are available for download on mysonicwall.com."""
        print("\n\n--------------------------------")
        print(f"Notice: {model} running firmware version {firmware_version} *is vulnerable* to {cve}.")
        print(f"Details: {details}")
        print()
        print("Resources:")
        print("- SonicWall Security Advisory: https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2024-0015")
        print("- How to enable MFA for SSLVPN: https://www.sonicwall.com/support/knowledge-base/how-do-i-configure-2fa-for-ssl-vpn-with-totp/190829123329169")
        print()
        print("Recommendations:")
        print("1. Review the SonicWall Security Advisory for this vulnerability.")
        print("2. Take all recommended actions outlined in the Security Advisory, including implementing MFA for SSLVPN.")
        print("3. Update the firmware to the latest version listed on the Security Advisory to address this vulnerability.")
        print("3. Re-run this script targeting this firewall after upgrading the firmware to proceed with forcing all local users to update their password on next login.")
        print("--------------------------------")
        input("Press Enter to continue and confirm you have read the notice.\n")
        return True

    return False


# Version tester
if __name__ == '__main__':
    notice_check("7.0.1-5034", "NSA 3700")
    notice_check("7.0.1-5035", "NSA 3700")
    notice_check("7.0.1-5036", "NSA 3700")
    notice_check("7.0.0-5034", "NSA 3700")
    notice_check("7.0.0-5035", "NSA 3700")
    notice_check("7.0.0-5036", "NSA 3700")
    notice_check("7.1.0-5034", "NSA 3700")
    notice_check("7.1.0-5035", "NSA 3700")
    notice_check("7.1.0-5036", "NSA 3700")
    print("\n\n")
    notice_check("6.5.2.7-1n", "SuperMassive 9800")
    notice_check("6.5.2.7-2n", "NSsp 12800")
    notice_check("6.5.2.8-1n", "NSsp 12400")
    notice_check("6.5.2.8-2n", "SuperMassive 9800")
    notice_check("6.5.2.8-3n", "SuperMassive 9800")
    print("\n\n")
    notice_check("6.5.4.15-115", "NSA 2600")
    notice_check("6.5.4.15-116", "NSA 3600")
    notice_check("6.5.4.15-117", "NSA 2600")
    notice_check("6.5.4.14-117", "TZ 3600")
    notice_check("6.5.3.14-117", "TZ 400")
    notice_check("6.5.3.14-116", "TZ 400")
    print("\n\n")
    notice_check("5.9.2.14-13", "NSA 3700")