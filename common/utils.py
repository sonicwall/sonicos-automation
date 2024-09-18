from datetime import datetime, timezone


# Timestamp generator. Use the split parameter to return a timestamp without trailing milliseconds.
def generate_timestamp(split=True):
    """
    Returns a timestamp string.
    :param split: If True, return a timestamp string without trailing milliseconds.
    :return: Timestamp string
    """

    # This returns a timestamp without trailing milliseconds.
    if split:
        current_time = datetime.now(timezone.utc).astimezone()
        current_time = str(current_time).split('.')[0]
    else:
        # This returns a timestamp with trailing milliseconds for tracking request time.
        current_time = str(datetime.now())

    return current_time


# Decorator to prepend print statements with a timestamp.
def timestamp(func):
    """
    Decorator to prepend print statements with a timestamp.
    :param func: Function to decorate.
    :return: Decorated function.
    """
    def wrapper(*args, **kwargs):
        # Prints with rich, but ends without a newline. Prepends the timestamp.
        # print(f"{generate_timestamp()}: ", end='')
        print(f"{generate_timestamp()}: ", end='')
        return func(*args, **kwargs)
    return wrapper

@timestamp
def tprint(*args, **kwargs):
    """
    Print with a prepended timestamp.
    """
    return print(*args, **kwargs)


# Write output to file
def write_to_file(data, filename=''):
    """
    Open a specified file and write/append data to it.
    :param data: Data to write to the file.
    :param filename: File name to write to.
    """
    with open(filename, 'a') as file:
        file.writelines(data)


# Function that returns the config level based on the number of spaces provided.
# CLI commands are indented by 4 spaces. The config level is the number of spaces divided by 4.
def get_config_indent_level(spaces):
    """
    Function that returns the config level based on the number of spaces provided.
    CLI commands are indented by 4 spaces. The config level is the number of spaces divided by 4.
    :param spaces: Number of spaces to divide by 4.
    :return: Config level.
    """
    # Divide the number of spaces by 4 and return the integer.
    return int(spaces / 4)


