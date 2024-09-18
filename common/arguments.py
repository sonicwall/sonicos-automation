import argparse


def get_parser():
    """
    Return an argument parser object.
    :return: ArgumentParser object
    """
    ap = argparse.ArgumentParser(description="""SonicWall Force Password Change Script.
    This tool automates the task of forcing all local users to change their password on next login. Please refer to the README for more detailed help.""")

    ap.add_argument("target", type=str, default="",
                    help="Provide a target firewall IP address/name and port (if other than port 443) or CSV file containing 'ip,username,password,sshport' of each firewall.")

    ap.add_argument("-s", "--sshport", type=str, default='22',
                    help="If SonicOS API is disabled, the script will attempt to use SSH Management on port 22 to *temporarily* enable SonicOS API. Use this argument to specify a different SSH port. This has no effect if using a CSV file.")

    ap.add_argument("-et", "--enable_totp", action='store_true',
                    help="If set, the script will enable Two-Factor Authentication (TOTP) on the 'SSLVPN Services' group. SSLVPN users will be prompted to set up the TOTP on their next login.")

    ap.add_argument("-eb", "--enable_botnet_filtering", action='store_true',
                    help="If set, the script will enable Botnet Filtering. This currently has no effect. The next version will include this feature.")

    ap.add_argument("-tp", "--temp_password", type=str, default='',
                    help="If set, the script will reset each user's password to the specified temporary password. This has no effect if using a CSV file.")

    ap.add_argument("-v", "--verbose", action='store_true',
                    help="Enable verbose output. This will print additional information to the console.")

    args = ap.parse_args()
    return args


a = get_parser()