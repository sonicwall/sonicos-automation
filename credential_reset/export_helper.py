from common.utils import generate_timestamp
from sonicos.api import (
    download_tsr,
    download_tracelog,
    export_preferences,
)
from sonicos.api2 import Login
import common.constants as constants




def export_tsr_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, silent=False, tag: str = ""):
    """Export TSR if enabled in arguments."""
    result = {'tsr_downloaded': False}

    if not args.export_tsr:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TSR download disabled.")
        return result

    if not silent:
        print(f"{generate_timestamp()}: Downloading TSR...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    if tag == "":
        tsr_file_name = f"{dm}-{sn}-tsr.wri"
    else:
        tsr_file_name = f"{dm}-{sn}-{tag}-tsr.wri"

    tsr_downloaded = download_tsr(api_base,
                                  api_session,
                                  filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tsr_file_name}",
                                  firewall_generation=firewall_info['firewall_generation'],
                                  silent=silent)

    if tsr_downloaded:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: TSR downloaded to {tsr_file_name}")
        result['tsr_downloaded'] = True
        result['tsr_file_name'] = f"{constants.START_TIMESTAMP_FOLDER}/{tsr_file_name}"

    return result


def export_tracelogs_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, silent=False, tag: str = ""):
    """Export trace logs if enabled in arguments."""
    result = {'trace_logs_downloaded': False}

    if not args.export_tracelogs:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Trace log download disabled.")
        return result

    if not silent:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Downloading trace logs...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    if tag == "":
        tracelog_filename = f"{dm}-{sn}-tracelog-current.txt"
    else:
        tracelog_filename = f"{dm}-{sn}-{tag}-tracelog-current.txt"

    trace_logs_downloaded = download_tracelog(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{tracelog_filename}",
                                              log_selection="current",
                                              firewall_generation=firewall_info['firewall_generation'],
                                              silent=silent)

    if trace_logs_downloaded:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Trace logs downloaded.")
        result['trace_logs_downloaded'] = True
        result['tracelog_filename'] = f"{constants.START_TIMESTAMP_FOLDER}/{tracelog_filename}"

    return result


def export_settings_if_enabled(api_session, api_base: str, args, target_numbers: tuple, firewall_info: dict, username: str, password: str, silent=False, tag: str = ""):
    """Export settings if enabled in arguments."""
    result = {'settings_exported': False}

    if not args.export_settings:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings export disabled.")
        return result

    if not silent:
        print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Exporting settings...")
    dm = firewall_info['device_model'].replace(" ", "")
    sn = firewall_info['serial_number']
    if tag == "":
        prefs_file_name = f"{dm}-{sn}-prefs.exp"
    else:
        prefs_file_name = f"{dm}-{sn}-{tag}-prefs.exp"

    prefs_downloaded = False
    firewall_generation = firewall_info['firewall_generation']

    if firewall_generation == 6:
        verbose_int = 1 if args.verbose else 0

        alternate_session = Login(
            ipaddress=api_base,
            userid=username,
            passwd=password,
            admin_mode="config",
            http_type="https",
            brwsr_cache=0,
            verbose=verbose_int,
            sessIdRef=0
        )

        logged_in, rmsg = alternate_session.login2()
        if logged_in == 1:
            if not silent:
                print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Successfully logged in to the firewall for settings export.")
            prefs_downloaded = export_preferences(api_base,
                                                  alternate_session,
                                                  filepath=f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}",
                                                  firewall_generation=firewall_generation,
                                                  silent=silent)
    else:
        # GEN5 and GEN7 use existing session
        prefs_downloaded = export_preferences(api_base,
                                              api_session,
                                              filepath=f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}",
                                              firewall_generation=firewall_generation, silent=silent)

    if prefs_downloaded:
        if not silent:
            print(f"({target_numbers[0]}/{target_numbers[1]}) {generate_timestamp()}: Settings exported.")
        result['settings_exported'] = True
        result['prefs_file_name'] = f"{constants.START_TIMESTAMP_FOLDER}/{prefs_file_name}"

    return result

