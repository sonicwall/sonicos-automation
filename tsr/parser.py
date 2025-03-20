import re


# This function is used to parse a TSR file for a given string and return a list of results
def parse_file(text_file, look_for) -> list:
    """Parses a TSR file for a given regex string and returns a list of results.
    :param tsr_file: The TSR file to parse.
    :type text_file: str
    :param look_for: The regex string (or list of them) to search for.
    :type look_for: str, regex, or list of strings/regex
    :return: A list of results.
    :rtype: list
    """
    if isinstance(look_for, str):
        look_for = [look_for]

    results = []
    with open(text_file, 'r') as file:
        for line in file:
            for search_string in look_for:
                if re.search(search_string, line):
                    results.append(line)

    # Deduplicates the results
    results = list(set(results))

    return results
