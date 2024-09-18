from os import path
from common.arguments import a
from common.utils import generate_timestamp


VERSION_STRING = '0.5'

# Base folder path for the application.
BASE_PATH = path.dirname(path.dirname(path.abspath(__file__)))

# Run folder (where the output directories will be created).
RUNS_FOLDER = path.join(BASE_PATH, 'runs')

# Get the launch timestamp
START_TIMESTAMP = generate_timestamp()

# Create a folder for the current run.
START_TIMESTAMP_FOLDER = path.join(RUNS_FOLDER.split('/')[-1], START_TIMESTAMP.replace(' ', '_').replace(':', '-'))

# Prompt level variable keeps track of the current prompt level.
PROMPT_LEVEL = ''

# These next SKIP_TO_NEXT_* variables controls whether Phase 3 Push should skip sending commands to the firewall.
# This is used to skip subsequent lines temporarily.
# For example, when a rule fails to commit, the rest of the rule's commands should be skipped.
# This var skips to the nth commit command. 0 means don't skip. 1 skip to next commit. 2 skip to the 2nd commit, etc.
# Decrement the counter after each commit command, so it hits 0 and resets to not skipping.
SKIP_TO_NTH_COMMIT = 0

# This variable is used to override the destination firewall IP.
DEST_FW_RECONNECT_TO_IP = None

# Track the firewall generation and model.
FIREWALL_GENERATION = None
FIREWALL_MODEL = None

# Track if SonicOS API was auto-enabled by the script.
AUTOENABLED_SONICOS_API = False


# Updates the firewall generation variable from the main script.
def set_fw_generation(generation):
    global FIREWALL_GENERATION
    FIREWALL_GENERATION = generation
    if a.verbose:
        print("Setting firewall generation to", generation)
    return FIREWALL_GENERATION


# Returns the firewall generation variable.
def get_fw_generation():
    global FIREWALL_GENERATION
    return FIREWALL_GENERATION


# Updates the firewall model variable from the main script.
def set_fw_model(model):
    global FIREWALL_MODEL
    FIREWALL_MODEL = model
    if a.verbose:
        print("Setting firewall model to", model)
    return FIREWALL_MODEL


# Returns the firewall model variable.
def get_fw_model():
    global FIREWALL_MODEL
    return FIREWALL_MODEL


# Updates the AUTOENABLED_SONICOS_API variable from the main script.
def set_autoenabled_sonicos_api(autoenabled):
    global AUTOENABLED_SONICOS_API
    AUTOENABLED_SONICOS_API = autoenabled
    if a.verbose:
        print("Setting AUTOENABLED_SONICOS_API to", autoenabled)
    return AUTOENABLED_SONICOS_API


# Returns the AUTOENABLED_SONICOS_API variable.
def get_autoenabled_sonicos_api():
    global AUTOENABLED_SONICOS_API
    return AUTOENABLED_SONICOS_API

