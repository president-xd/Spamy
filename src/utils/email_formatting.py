import textwrap

# Formating
TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

# Formating data
DATA_TAB_1 = '\t  '
DATA_TAB_2 = '\t\t  '
DATA_TAB_3 = '\t\t\t  '
DATA_TAB_4 = '\t\t\t\t  '

def format_multi_line(prefix, string, size=80):
    """
    Format the multi-line data.
    :param prefix: The prefix for each line.
    :param string: The string to format.
    :param size: The size of each line.
    :return: The formatted string.
    """
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r' {:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    if string is not None:
        return '\n'.join(prefix + line for line in textwrap.wrap(string, size)
                        if string is not None)
    else:
        return "No payload data"