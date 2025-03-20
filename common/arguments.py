import argparse


def get_parser(arg_set="all", description="", parse=True):
    """
    Return an argument parser object. Use an arg_set to control which arguments are returned. Default is all arguments.
    Note that when returning all arguments, some may not function depending on the script they are passed to.

    arg_set: A string defining which set of arguments to return.
    description: A string defining the description of the script.
    parse: If True, parse the arguments and return the ArgumentParser object. If False, return the ArgumentParser object.
        This is useful when you want to add additional arguments to the parser before parsing.

    :return: ArgumentParser object
    """
    arg_set = arg_set.lower()

    ap = argparse.ArgumentParser(description=description)

    ap.add_argument("target", type=str, default="",
                    help="Provide a target firewall IP address/name and port (if other than port 443) or CSV file containing 'ip,username,password,sshport' of each firewall.")

    if arg_set == "snwlid-2025-0001" or arg_set == "snwlid-2024-0015":
        ap.add_argument("-s", "--sshport", type=str, default='22',
                        help="If SonicOS API is disabled, the script will attempt to use SSH Management on port 22 to *temporarily* enable SonicOS API. Use this argument to specify a different SSH port. This has no effect if using a CSV file.")

    if arg_set == "snwlid-2024-0015":
        ap.add_argument("-et", "--enable_totp", action='store_true',
                        help="If set, the script will enable Two-Factor Authentication (TOTP) on the 'SSLVPN Services' group. SSLVPN users will be prompted to set up the TOTP on their next login.")

        ap.add_argument("-eb", "--enable_botnet_filtering", action='store_true',
                        help="If set, the script will enable Botnet Filtering (if licensed and disabled).")

        ap.add_argument("-fpc", "--force_password_change", action='store_true',
                        help="If set, the script will enable the logic that forces a password change for each local user, skipping domain users and expired users.")

        ap.add_argument("-tp", "--temp_password", type=str, default='',
                        help="If set, the script will reset each user's password to the specified temporary password. This has no effect if using a CSV file.")

        ap.add_argument("-uf", "--upgrade_firmware", type=str, default="",
                        help="If set and a valid path is specified, the script will attempt to upgrade the firmware to the specified image. This has no effect if using a CSV file.")

        ap.add_argument("-df", "--download_firmware", action='store_true',
                        help="If set, the script will download the recommended firmware image for the current release track. This has no effect if using a CSV file.")

    if arg_set == "snwlid-2025-0001" or arg_set == "snwlid-2024-0015":
        ap.add_argument("-es", "--export_settings", action='store_true',
                        help="If set, the script will export the firewall settings to a .exp file.")

    if arg_set == "snwlid-2024-0015":
        ap.add_argument("-etl", "--export_tracelogs", action='store_true',
                        help="If set, the script will export the firewall trace logs.")

    if arg_set == "snwlid-2025-0001" or arg_set == "snwlid-2024-0015":
        ap.add_argument("-etsr", "--export_tsr", action='store_true',
                        help="If set, the script will export the Tech Support Report (TSR).")

    if arg_set == "snwlid-2024-0015":
        ap.add_argument("-w", "--wait_for_upgrade", action='store_true',
                        help="If set, the script will wait for the firmware upgrade to complete and confirm reachability.")

    ap.add_argument("-v", "--verbose", action='store_true',
                    help="Enable verbose output. This will print additional information to the console.")

    if parse:
        args = ap.parse_args()
    else:
        # Allows for adding more arguments before calling parse_args().
        args = ap
    return args


#a = get_parser()