from os import path
import paramiko
from time import mktime, sleep
from datetime import datetime
from common.constants import (
    START_TIMESTAMP_FOLDER,
    set_fw_generation,
    set_fw_model,
    SKIP_TO_NTH_COMMIT,
    PROMPT_LEVEL
)
from common.utils import generate_timestamp, write_to_file
from common.arguments import a
from common.exceptions import SSHConnectionError
from common.config import config


# Connects and returns the authenticated SSH session.
def connect_ssh(host, port, soniccore_user="", soniccore_pass="", sonicos_user="", sonicos_pass="",
                soniccore_prelogin="no"):
    """
    Connects and returns the authenticated SSH session (Channel object) and SSH connection (SSHClient object).
    :param host: Name or IP address of the firewall to connect to.
    :param port: SSH port number to use.
    :param soniccore_user: SonicCore username.
    :param soniccore_pass: SonicCore password.
    :param sonicos_user: SonicOS username.
    :param sonicos_pass: SonicOS password.
    :param soniccore_prelogin: Set to "yes" to use SonicCore pre-login.
    :return:
    """
    # Verbose log
    if a.verbose:
        print(f"{generate_timestamp()}: DEBUG: Connecting to {host}:{port}...")
    # Set up SSH connection
    c = paramiko.SSHClient()
    c.load_system_host_keys()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    # If target firewall is NSv, we use prelogin to first log into SonicCore.
    if str(soniccore_prelogin).lower() == "yes":
        print(f"{generate_timestamp()}: SonicCore pre-login. Connecting to {host}:{port}... Logging in as {soniccore_user}")
        c.connect(host, port=port, username=soniccore_user, password=soniccore_pass, look_for_keys=False)
    else:
        print(f"{generate_timestamp()}: Connecting to {host}:{port}... Logging in as {sonicos_user}")
        c.connect(host, port=port, username=sonicos_user, password=sonicos_pass, look_for_keys=False)

    # Start an interactive shell
    c_channel = c.invoke_shell()

    if a.verbose:
        print(f"{generate_timestamp()}: DEBUG: Created channel...")

    # Get login SSH output.
    authentication_output = get_command_results(c_channel)

    if a.verbose:
        print(f"{generate_timestamp()}: DEBUG: \n->{authentication_output}<-\n")

    # Check if there was an authentication failure.
    if 'Password:' in authentication_output[-20:] and '\n' in authentication_output[-1]:
        print(f"{generate_timestamp()}: Authentication failed. Check the firewall's username/password.")
        exit()

    # Check if Access denied.
    if 'Access denied' in authentication_output:
        print(f"{generate_timestamp()}: Access denied. Check the firewall's username/password.")

    # Check if session was closed/timed out.
    if '% Session timed out.' in authentication_output:
        print(f"{generate_timestamp()}: Session timed out or the firewall closed the connection.")

    # Check for a "--MORE--" prompt, and send a space to continue.
    if "--MORE--" in authentication_output:
        print(f"{generate_timestamp()}: Encountered CLI pagination. Sending a space to continue.")
        # Sends a space and replaces the existing authentication_output variable.
        authentication_output = send_cmd(c_channel, " ", silent=True)

    # Check if "Pre-Login Policy Banner" is enabled. This is coupled with code in get_command_results().
    if 'Accept The Policy Banner (yes)?' in authentication_output:
        print(f"{generate_timestamp()}: Pre-Login Policy Banner is enabled. Accepting...")
        send_cmd(c_channel, "yes\r", silent=True)

    # Handle configuration mode preempt prompt. This is coupled with code in get_command_results().
    # Not applicable when elevating to config mode. Probably useless code.
    if 'Do you wish to preempt them (yes/no)?' in authentication_output:
        print(f"{generate_timestamp()}: Preempting the active admin session during authentication.")
        send_cmd(c_channel, "yes\r", silent=True)

    # If the channel is not closed, continue.
    if c_channel.closed:
        print(f"{generate_timestamp()}: Can't continue. SSH connection closed.")
        exit()
    else:
        # Authenticate to the SonicCore prompt
        if str(soniccore_prelogin).lower() == "yes":
            print(f"{generate_timestamp()}: Authenticating (SonicOS).")
            send_cmd(c_channel, f"{sonicos_user}\r{sonicos_pass}\r", silent=True)

        # Disable CLI paging
        print(f"{generate_timestamp()}: Disabling CLI paging for this session.")
        send_cmd(c_channel, "no cli pager session\r", silent=True)

        # Getting firmware version information.
        print(f"{generate_timestamp()}: Getting firmware version information.")
        cmd_results = send_cmd(c_channel, "show version\r", silent=True, get_cmd_response=True)

        version = cmd_results.split("firmware-version ")[1].split("\n")[0].strip('"')  # SonicOS x.x.x.x-xxxx
        model = cmd_results.split("model ")[1].split("\n")[0].strip('"')  # TZ xxx, NSa xxx, etc.
        print(f"{generate_timestamp()}: Model/Firmware Version: {model} - {version}")
        version = version.split(" ")[-1]  # x.x.x.x-xxxx

        if version.startswith('7'):
            set_fw_generation(7)
        elif version.startswith('6'):
            set_fw_generation(6)
        set_fw_model(model)

        # Go into configuration mode.
        print(f"{generate_timestamp()}: Entering configuration mode (config).")
        send_cmd(c_channel, "config\r", silent=True)

    # Return interactive shell (c_channel) and the SSHClient connection object (c).
    return c_channel, c


# Get the command results and return as a str object.
# Found this code snippet here: https://www.accadius.com/reading-the-ssh-output/
def get_command_results(channel):
    global PROMPT_LEVEL
    global SKIP_TO_NTH_COMMIT

    # Interval and maxcount are not used by the code.
    interval = float(config['SSH-ADVANCED']['interval'])
    maxseconds = int(config['SSH-ADVANCED']['max seconds'])
    bufsize = int(config['SSH-ADVANCED']['buffer size']) # Initial value was 1024 bytes
    maxcount = maxseconds / interval

    # Keep track of the number of times we've polled/number of sleeps at 0.200 seconds.
    sleep_count = 0

    # Sleep count max is the threshold at which we'll report that no activity has been received.
    # After polling every 0.200 for sleep_count_max times, if at a commit we reset the counter and wait again.
    # For non-commit cmds, report the firewall is not responding/stuck at a prompt.
    # This logic helps detect inactivity/long-running commits. 60 sec / 0.200 = 300 polls.
    sleep_count_max = float(config['SSH-ADVANCED']['activity sleep threshold seconds']) / 0.200

    # Set a blank old_rbuffer to start. During the while loop, the old_rbuffer will be compared to the new_rbuffer.
    # This is used to determine if we are receiving new data in the buffer between sleep_count polls.
    old_rbuffer = ''

    # Poll until completion or timeout
    # Note that we cannot directly use the stdout file descriptor
    # because it stalls at 64K bytes (65536).
    input_idx = 0
    timeout_flag = False
    start = datetime.now()
    start_secs = mktime(start.timetuple())
    output = ''
    channel.setblocking(0)
    while True:
        if channel.recv_ready():
            #data = channel.recv(bufsize).decode('ascii')
            # Poornima reported an issue decoding something in the address objects.
            # There may have been a special character or something, so I added ignore.
            # We'll have to monitor to see if there is any difference in output w/ ignore.
            # Matthew R. also ran into this with a 9650 while pulling address groups or service objects.
            data = channel.recv(bufsize).decode('ascii', 'ignore')
            output += data

        if channel.exit_status_ready():
            break

        # Timeout check
        now = datetime.now()
        now_secs = mktime(now.timetuple())
        et_secs = now_secs - start_secs
        if et_secs > maxseconds:
            timeout_flag = True
            break

        rbuffer = output.rstrip(' ')

        # Checks for an error response at the end of the buffer.
        if len(rbuffer) > 0 and ('% Error:' in rbuffer
                                 or '% Error encountered processing command:' in rbuffer
                                 or '% Warning:' in rbuffer
                                 or '% The following command must be configured:' in rbuffer):

            # Check for '% Error: Read only.' and use a less distracting message. This common error shouldn't hurt.
            if ('% Error: Read only.' in rbuffer or '% Error: Nat Policy is read-only.' in rbuffer):
                rb_cmd = rbuffer.split('\n')[0]
                rb_prompt = rbuffer.split('\n')[-1]
                print(f"{generate_timestamp()}: WARNING: Read only --> '{rb_prompt} {rb_cmd}'")
                if a.verbose:
                    print(f"{generate_timestamp()}: DEBUG: See details below. Review the saved SSH session output for more context. Use CTRL+C to quit.")
                    # print(Panel(style_cli_buffer(rbuffer), title="DEBUG: Command Sent and Warning/Error Response"))
                    print("\n-----")
                    print(rbuffer)
                    print("-----")
                    print()
            else:
                # I don't expect this to be hit as long as there's a buffer length over 0.
                print(f"{generate_timestamp()}: WARNING: See details below. Review the saved SSH session output for more context. Use CTRL+C to quit.")
                # print(Panel(style_cli_buffer(rbuffer), title="Command Sent and Warning/Error Response"))
                print("\n-----")
                print(rbuffer)
                print("-----")
                print()

            # If there's an issue creating a service object, print this message.
            # % Error: The end of the port range cannot be less than the beginning of the
            if "% Error: The end of the port range cannot be less than the beginning" in rbuffer:
                print(f"{generate_timestamp()}: INFO: Check the port range. If this is a protocol that does not use a port range, then this is a bug.")

            # The match object is empty but can't be. I saw this while pushing an empty application list object.
            if "% Error: One or more applications must be set via the 'application' command." in rbuffer:
                print(f"{generate_timestamp()}: INFO: Check the match object's configuration. Object may be empty.")

            # When the referenced name is an object, but was referenced as a group. I saw this while pushing "show service-groups".
            if "is an object, should not use as a group." in rbuffer:
                print(f"{generate_timestamp()}: INFO: Check the match object's configuration. This may be a default object you can ignore.")
                SKIP_TO_NTH_COMMIT = 1

            # Handle anti-spyware configuration. Without signatures, many signature config commands will fail.
            if ("product id" in rbuffer or "product name" in rbuffer) and "(config-anti-spyware)#" in rbuffer:
                print(f"{generate_timestamp()}: INFO: The 'product id' or 'product name' was not accepted. Make sure the Anti-Spyware signatures have been downloaded or manually uploaded.")
                SKIP_TO_NTH_COMMIT = 1

            # Handle interfaces that do not exist on the destination firewall.
            if "interface" in rbuffer and "% Error: No matching command found." in rbuffer and rbuffer.split("\n")[0].startswith("interface "):
                interface_name = rbuffer.split("\n")[0].split("interface ")[1].strip()
                print(f"{generate_timestamp()}: INFO: {interface_name.upper()} interface does not exist on the destination firewall. Skipping {interface_name.upper()}.")
                SKIP_TO_NTH_COMMIT = 1

            # If an Access Rule changes cannot commit the pending changes need to be cleared.
            # The access-rule command is at the first config CLI level.
            if "access-rule ipv" in rbuffer:
                print(f"{generate_timestamp()}: INFO: Sent 'cancel'. Going back to 'config' CLI level.")
                send_cmd(channel, "cancel\r", silent=True)

                # If the prompt level is "top", re-enter config mode.
                if PROMPT_LEVEL == "top":
                    print(f"{generate_timestamp()}: INFO: Sent 'config'. Re-entering 'config'.")
                    send_cmd(channel, "config\r", silent=True)

                # At this point, the subsequent commands are still sent, which can cause a domino effect of bad commands.
                # To prevent the rest of the commands from being sent I use a flag to skip to the next item (access rule, etc.)
                # "% Error: From Zone: Invalid priority! Higher priority VPN default rule will override this policy."
                # "% Error: From Zone: Rule overlap, rule not added."
                if ("% Error: No matching command found." in rbuffer
                        or "Management policy with the given manual priority is not allowed" in rbuffer
                        or "invalid priority" in rbuffer.lower()
                        or "% Error: No" in rbuffer.lower()):
                    # If the error is "No matching command found", then the access-rule command failed, probably
                    # because a referenced object name doesn't exist (likely not the only possible reason).
                    # To skip the whole rule, skip to the second commit command.
                    SKIP_TO_NTH_COMMIT = 2
                elif "Rule overlap, rule not added." in rbuffer:
                    # If the error is "Rule overlap, rule not added", then the access-rule command failed, probably
                    # because a referenced object name doesn't exist (likely not the only possible reason).
                    # To skip the whole rule, skip to the first commit command.
                    SKIP_TO_NTH_COMMIT = 0
                else:
                    # When the error was "% Error: From Zone: Management policy with the given manual priority is not allowed"
                    # the access-rule command was successful, but the first commit failed. To skip the whole rule, skip to the next commit command.
                    # In this context, "first/next commit" means the second commit command in the rule's config.
                    SKIP_TO_NTH_COMMIT = 1

            # If a NAT Policy changes cannot commit the pending changes need to be cleared.
            # The nat-policy command is at the first config CLI level.
            if "nat-policy ipv" in rbuffer:
                print(f"{generate_timestamp()}: INFO: Sent 'cancel'. Going back to 'config' CLI level.")
                send_cmd(channel, "cancel\r", silent=True)

                # If the prompt level is "top", re-enter config mode.
                if PROMPT_LEVEL == "top":
                    print(f"{generate_timestamp()}: INFO: Sent 'config'. Re-entering 'config'.")
                    send_cmd(channel, "config\r", silent=True)

                # At this point, the subsequent commands are still sent, which can cause a domino effect of bad commands.
                # To prevent the rest of the commands from being sent I use a flag to skip to the next item (access rule, etc.)
                # "% Error: From Zone: Invalid priority! Higher priority VPN default rule will override this policy."
                # "% Error: From Zone: Rule overlap, rule not added."
                if ("% Error: No matching command found." in rbuffer
                        or "Management policy with the given manual priority is not allowed" in rbuffer
                        or "invalid priority" in rbuffer.lower()
                        or "% Error: Cannot modify NAT policy" in rbuffer
                        or "% Error: No" in rbuffer):
                    SKIP_TO_NTH_COMMIT = 1
                else:
                    # When the error was "% Error: From Zone: Management policy with the given manual priority is not allowed"
                    # the nat-policy command was successful, but the first commit failed. To skip the whole rule, skip to the next commit command.
                    # In this context, "first/next commit" means the second commit command in the rule's config.
                    SKIP_TO_NTH_COMMIT = 1


            # If an IP Helper policy fails, the rest of the commands in the policy will fail and the exit will
            # kick the CLI back to the config level. To prevent that, skip to the next policy.
            if "policy protocol" in rbuffer:
                SKIP_TO_NTH_COMMIT = 1

            # If an SSO Bypass rule fails due to an invalid object selection, the rest of the cmds will fail.
            # The exit will kick the CLI back to the config level. To prevent that, skip to the next SSO Bypass rule.
            if "security-service-bypass" in rbuffer:
                SKIP_TO_NTH_COMMIT = 1

            # Escapes the current CLI level to the previous mode and continues with the next command.
            # This command will not be logged since an output file was not passed.
            if "% Type 'cancel' at any time to abort current" in rbuffer:
                print(f"{generate_timestamp()}: INFO: Sent 'cancel'. Pushing the remaining commands.")
                send_cmd(channel, "cancel\r", silent=True)

            # Escapes the current CLI level to the previous mode and continues with the next command.
            # This command will not be logged since an output file was not passed.
            if "% Error: Creating" in rbuffer or "% Error: Route advertisement daemon prefix:" in rbuffer:
                # For CLI push. If the commit fails, try "commit best-effort" and then "cancel".
                if "commit best-effort" not in rbuffer:
                    # First try commit best-effort.
                    print(f"{generate_timestamp()}: INFO: Commit failed. Trying 'commit best-effort'.")
                    send_cmd(channel, "commit best-effort\r", silent=True)

                # If the commit best-effort fails, commit best-effort will be in the buffer.
                # For this route advertisement error, skip to the next commit and cancel.
                elif "commit best-effort" in rbuffer and "% Error: Route advertisement daemon prefix:" in rbuffer:
                    print(f"{generate_timestamp()}: INFO: Commit with best-effort failed. Skipping to next commit.")
                    SKIP_TO_NTH_COMMIT = 1
                    send_cmd(channel, "cancel\r", silent=True)

                # Else, cancel the pending changes.
                else:
                    print(f"{generate_timestamp()}: INFO: Sent 'cancel'. Exiting 'config' to clear the pending changes that failed.")
                    send_cmd(channel, "cancel\r", silent=True)

                # If the prompt level is "top", re-enter config mode.
                if PROMPT_LEVEL == "top":
                    print(f"{generate_timestamp()}: INFO: Sent 'config'. Re-entering 'config'. Pushing the remaining commands.")
                    send_cmd(channel, "config\r", silent=True)

        # Disabling "require-valid-certificate" presents a prompt. Send 'yes' and continue with the next command.
        # This command will not be logged since an output file was not passed.
        if len(rbuffer) > 0 and "User passwords will be sent to the LDAP server for authentication" in rbuffer:
            print(f"{generate_timestamp()}: Acknowledging the LDAP 'no require-valid-certificate' warning.")
            send_cmd(channel, "yes\r", silent=True)

            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for a prompt at the end of the buffer.
        if len(rbuffer) > 0 and ('@' in rbuffer[-70:] and rbuffer[-1] == '>'):  # Got a prompt
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Handle GEN5 prompts. Checks for a prompt at the end of the buffer.
        if len(rbuffer) > 0 and (rbuffer[-1] == '>'):  # Got a prompt
            if a.verbose:
                print(f"{generate_timestamp()}: GEN5 '>' prompt[/]")
            break

        # Checks for routing prompts (like "ARS OSPF>").
        if len(rbuffer) > 0 and "import-cli-ftp-" not in rbuffer[-50:] and (
                ('ARS NSM' in rbuffer[-70:] and rbuffer[-1] == '>') or
                ('ARS OSPF' in rbuffer[-70:] and rbuffer[-1] == '>') or
                ('ARS OSPFv3' in rbuffer[-70:] and rbuffer[-1] == '>') or
                ('ARS BGP' in rbuffer[-70:] and rbuffer[-1] == '>') or
                ('ARS RIP' in rbuffer[-70:] and rbuffer[-1] == '>') or
                ('ARS RIPng' in rbuffer[-70:] and rbuffer[-1] == '>')
            ):
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for a configuration mode prompt at the end of the buffer.
        if len(rbuffer) > 0 and (rbuffer[-2:] == ')#' or rbuffer[-2:] == ']#') and "import-cli-ftp-" not in rbuffer[-50:]:
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-100:])
            # print("\nPrompt found:", rbuffer[-50:])
            # print("--------------------")
            break

        # Handling for CLI pagination/"--MORE--" prompt. Breaks out of the while loop the same way a prompt does.
        if len(rbuffer) > 0 and ('--MORE--' in rbuffer[-12:]):
            break

        # Checks for the Pre-login Policy Banner. Breaks out of the while loop the same way a prompt does.
        if len(rbuffer) > 0 and ('Accept The Policy Banner (yes)?' in rbuffer[-70:] and rbuffer[-1] == ':'):
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for the Block Until Verdict confirmation prompt.
        if len(rbuffer) > 0 and ('This may cause delays in download times for my users and may require users to retry the download.' in rbuffer[-250:]
                                 and ("]:" in rbuffer[-4:] or "):" in rbuffer[-4:])):
            print(f"{generate_timestamp()}: Accepting Capture ATP's Block Until Verdict warning prompt.")
            send_cmd(channel, "yes\r", silent=True)
            break

        # Handle Gen5 or another login prompt. Without this, program reports no activity when this prompt is received.
        if len(rbuffer) > 0 and ('User:' in rbuffer[-5:]):
            print(f"{generate_timestamp()}: Detected another login prompt.")
            break

        # Checks for failed SSH login.
        if len(rbuffer) > 0 and ('Password:' in rbuffer[-20:] and 'Using username' in rbuffer[-140:]):
            # print(f"{generate_timestamp()}: SSH Login failed.")
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for max login attempts.
        if len(rbuffer) > 0 and ('% Maximum login attempts exceeded.' in rbuffer[-70:]):
            print(f"{generate_timestamp()}: Maximum login attempts exceeded. Too many failed logins.")
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for configuration mode preempt prompt on GEN5. Breaks out of the while loop the same way a prompt does.
        if len(rbuffer) > 0 and ('Do you wish to preempt them ?' in rbuffer[-70:]):
            print(f"{generate_timestamp()}: Preempting the active admin session.")
            send_cmd(channel, "yes\r", silent=True)
            break

        # Checks for configuration mode preempt prompt. Breaks out of the while loop the same way a prompt does.
        if len(rbuffer) > 0 and ('Do you wish to preempt them (yes/no)?' in rbuffer[-70:] and rbuffer[-1] == ':'):
            print(f"{generate_timestamp()}: Preempting the active admin session.")
            send_cmd(channel, "yes\r", silent=True)
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for 'uncommitted changes found. Commit them now before exiting(yes/no/cancel)?' prompt.
        # Breaks out of the while loop the same way a prompt does.
        if len(rbuffer) > 0 and ('Uncommitted changes found.' in rbuffer[-85:] and "[cancel]" in rbuffer[-15:]):
            print(f"{generate_timestamp()}: Answering 'Uncommitted changes' prompt with 'yes'.")
            send_cmd(channel, "yes\r", silent=True)
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Checks for "Restarting now..." and "Restarting in". Breaks out of the while loop the same way a prompt does.
        # This should handle restarting now, in x min/hours/days, or at 2023:12:01:17:00:00 (YYYY:MM:DD:HH:MM:SS)
        if len(rbuffer) > 0 and ('Restarting now...' in rbuffer[-50:] or 'Restarting in' in rbuffer[-50:]):
            print(f"{generate_timestamp()}: Restart text detected.")
            channel.close()
            # Diagnostic prints
            # print("--------------------")
            # print("Sample:\n", rbuffer[-40:])
            # print("\nPrompt found:", rbuffer[-19:])
            # print("--------------------")
            break

        # Try to handle any unknown prompt not handled above by requesting user input.
        if len(rbuffer) > 0 and ("]:" in rbuffer[-4:] or "):" in rbuffer[-4:]):
            print(f"{generate_timestamp()}: Unknown prompt found. Please enter the required input. See the following for context.")
            msg = f"\n(CLI prompt level: {PROMPT_LEVEL}) Enter a response to this prompt and hit Enter. Sending Enter without text may issue a default response.\nNote: You may be unable to see the text you type. Each keystroke may echo the progress line."
            # print(Panel(style_cli_buffer(rbuffer.rstrip(":")) + msg, title="Command Sent and Prompt Received - Type a response and hit Enter."))
            # user_input = Prompt.ask("Enter your response and hit Enter...[/]\n\n\n\n")
            print("\n------")
            print(rbuffer.rstrip(":"), msg)
            print("------")
            print()
            user_input = input("Enter your response and hit Enter... (you may not be able to see the text you type)\n\n\n\n")
            send_cmd(channel, user_input + "\r", silent=False)
            print()
            break

        # For any other unknown text that isn't handled above, print it out and break if the function has been running for more than 10 seconds.
        # if len(rbuffer) > 0 and (time.time() - start_time > 10):
        #     print(f"{generate_timestamp()}: Unknown text found. See the following for context.")
        #     print(Panel(rbuffer, title="MAY HAVE GOTTEN STUCK HERE WITHOUT THIS IF STATEMENT"))
        #     break

        # Testing this out... If the sleep below is hit over 50 times (0.200 seconds * 300 counts = 60 sec), print a message, a Panel, and quit
        # If I break instead, the msg will just repeat itself while moving to the next command.
        # It is best to stop and manually work through the problem.
        if sleep_count >= sleep_count_max and old_rbuffer != rbuffer:
            # This prints out when there hasn't been any new activity for 300 iterations (0.200 seconds * 300 counts = 60 sec)
            # but the old_rbuffer is different than the current rbuffer. That means new data is being received.
            print(f"{generate_timestamp()}: Still receiving data...")

        # This is the condition that is hit if no new data is received within the allotted window (0.200 seconds * 300 counts = 60 sec)
        # The idea is that if the old_rbuffer is the same as the current rbuffer, then no new data has been received.
        if sleep_count >= sleep_count_max and old_rbuffer == rbuffer:
            # Commits can take time if they large changes and the buffer will be the same during this time.
            if "commit" in rbuffer:
                # This prints out and resets the sleep counter back to 0. The message will re-appear if the counter hits 300 again.
                print(f"{generate_timestamp()}: No new data received in {0.200 * sleep_count_max} seconds. Device appears to be committing changes...")
                sleep_count = 0
                continue

            # When the sleep counter hits the allotted threshold and we're not at a commit, a different message is printed.
            # This is where the program will exit because it is likely stuck at a prompt or the device stopped responding.
            print(f"{generate_timestamp()}: No activity in {0.200 * sleep_count_max} seconds. The CLI may have gotten stuck at an unhandled prompt or the device stopped responding.")
            msg = f"\nTrying to re-establish the SSH connection."
            # print(Panel(style_cli_buffer(rbuffer.rstrip(":")[-1000:]) + msg, title="No activity detected - Check CLI buffer below.[/]"))
            print("\n------ No activity detected ------")
            print(rbuffer.rstrip(":")[-1000:], msg)
            print("------")

            if a.verbose:
                print(f"{generate_timestamp()}: DEBUG: Unmodified buffer:\n{rbuffer}\n")

            # print("Trying to recover from the error... (before returning the error)")
            # final_cleanup()
            # exit(1)
            #raise Exception()  # TODO: Remove or comment this raise before committing! For testing purposes only.
            return SSHConnectionError("No activity detected. Trying to recover.")

        # Reset the sleep counter if new data was received.
        if sleep_count >= sleep_count_max and old_rbuffer != rbuffer:
            sleep_count = 0

        try:
            sleep(0.200)
        except KeyboardInterrupt:
            print(f"{generate_timestamp()}: Stopped!")
            exit(1)

        # Set the old_rbuffer to the current rbuffer for the next loop.
        old_rbuffer = rbuffer
        sleep_count += 1

    if channel.recv_ready():
        data = channel.recv(bufsize)
        output += data.decode('ascii')

    # Keep track of the latest prompt level. This is used to determine if we are in config mode or not and avoid accidental logout.
    # Get the last line of the output.
    try:
        last_line = output.splitlines()[-1].strip()
    except IndexError:
        last_line = None

    if last_line:
        # Sets the prompt level.
        # If the last line of the output contains @ and ends with a >, set the prompt level to 'top'.
        if '@' in last_line and '>' in last_line[-4:]:
            PROMPT_LEVEL = 'top'

        # Else if the last line of the output contains 'config(' and ends with a ')#', set the prompt level to 'config'.
        elif 'config(' in last_line and ')#' in last_line[-4:]:
            PROMPT_LEVEL = 'config'

    # Return the output and remove the extra line carriage from each line.
    return output.replace('\r', '')


# Send command data to the SSH channel. Get the response.
def send_cmd(shell, data, output_file='', silent=False, get_cmd_response=True):
    global PROMPT_LEVEL
    global SKIP_TO_NTH_COMMIT

    # If the SKIP_TO_NTH_COMMIT flag is set, skip sending the command.
    if SKIP_TO_NTH_COMMIT > 0:
        if "commit" not in data.lower():
            print(f"{generate_timestamp()}: Skipping command: {data}")
            return
        else:
            # Decrement the counter as we've hit a commit command.
            SKIP_TO_NTH_COMMIT = SKIP_TO_NTH_COMMIT - 1

            # If we are at 0, then we are done skipping and can continue. We are at the commit we want to be at.
            if SKIP_TO_NTH_COMMIT != 0:
                return

    # This checks if the command being sent is 'exit', and warns if the user is at the top level prompt.
    if data.lower().strip("\r").strip("\n") == 'exit':
        if PROMPT_LEVEL == 'top':
            # print(f"{generate_timestamp()}: WARNING: Attempting to send 'exit' the top level prompt. This will log you out of the firewall.")
            # if Confirm.ask("Do you want to skip the 'exit' and continue pushing commands? Hit Enter after you input your choice. (y to continue/n to log out)\nYou are likely to experience errors or see this again if you continue to send commands.\n\n\n\n", default=False):
            #     print(f"{generate_timestamp()}: Skipping 'exit' command and continuing.")
            #     data = data.replace('exit', '')
            # else:
            #     print(f"{generate_timestamp()}: Logging out. If this was not expected, please check for errors prior to the logout.")
            print(f"{generate_timestamp()}: Logging out. If this was not expected, please check for errors prior to the logout.")

    # Print out the command name if silent is False
    if not silent:
        # If we don't get the command response, we shouldn't try to write it to a file.
        if get_cmd_response is False:
            # Setting output_file to None will help display the print message below.
            output_file = None

        if output_file:
            print(f"{generate_timestamp()}: Sending '{data}' --> {output_file}")
        else:
            print(f"{generate_timestamp()}: Sending '{data}'")

    # Send the command
    shell.send(data)

    # Get the response from the firewall if get_cmd_response is True.
    if get_cmd_response:
        # Get the response from the firewall.
        command_results = get_command_results(shell)

        # Write response output to a file, if output_file is set and the command_results is not an SSHConnectionError.
        if output_file and not (isinstance(command_results, SSHConnectionError)):
            write_to_file(command_results, filename=path.join(START_TIMESTAMP_FOLDER, output_file))

        # Return the command results.
        if isinstance(command_results, SSHConnectionError):
            # If the command_results is an SSHConnectionError, raise it.
            # The exception will be caught by the calling function and handled there.
            raise command_results
        else:
            return command_results

    # When get_cmd_response is False, we don't wait for the response.
    # This is helpful when we want to send something to the SSH channel and move on without blocking.
    else:
        return