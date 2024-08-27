from email_formatting import *
from email_extraction import *

def print_received(received_headers):
    for i, received in enumerate(received_headers):
        # Split the received header into its components
        parts = received.split(' by ')
        from_part = parts[0]  # "from mail.example.com (mail.example.com [192.0.2.1])"
        by_part = parts[1] if len(parts) > 1 else ""  # "by mail.receiver.com with ESMTP id abc123"

        # Print the "from" part
        from_part_lines = from_part.split(' (', 1)
        print(f"{TAB_3} {i+1}: from {from_part_lines[0]}")

        if len(from_part_lines) > 1:
            formatted_from_part = format_multi_line(TAB_4, '(' + from_part_lines[1], 80)
            print(formatted_from_part)

        # Print the "by" part with the rest of the header
        by_part_lines = by_part.split(' for ')
        print(f"{TAB_3} by {by_part_lines[0]}")

        if len(by_part_lines) > 1:
            rest_part = by_part_lines[1]
            rest_part_lines = rest_part.split(';', 1)
            formatted_rest_part = format_multi_line(TAB_4, 'for ' + rest_part_lines[0], 80)
            print(formatted_rest_part)

            if len(rest_part_lines) > 1:
                formatted_additional_info = format_multi_line(TAB_4, '; ' + rest_part_lines[1].strip(), 80)
                print(formatted_additional_info)

def print_dkim_signature(dkim_components):
    print(f"{TAB_3} Domain (d): ")
    print(format_multi_line(DATA_TAB_4, dkim_components.get('d', 'N/A')))
    print(f"{TAB_3} Headers (h): ")
    print(format_multi_line(DATA_TAB_4, dkim_components.get('h', 'N/A')))
    print(f"{TAB_3} Body Hash (bh): ")
    print(format_multi_line(DATA_TAB_4, dkim_components.get('bh', 'N/A')))
    print(f"{TAB_3} Signature (b): ")
    print(format_multi_line(DATA_TAB_4, dkim_components.get('b', 'N/A')))


def print_spf(spf_header):
    print(f"{TAB_3}  Result:")
    print(format_multi_line(DATA_TAB_4, spf_header))

def print_necessary_headers(headers):
    print(f"{TAB_1} Headers:")
    print(f"{TAB_2} From: {extract_from(headers)}")
    print(f"{TAB_2} To: {extract_to(headers)}")
    print(f"{TAB_2} Date: {extract_date(headers)}")
    print(f"{TAB_2} Message-ID: {extract_message_id(headers)}")
    print(f"{TAB_2} Received: ")
    print_received(extract_received(headers))
    print(f"{TAB_2} DKIM-Signature: ")
    print_dkim_signature(parse_dkim_signature(extract_dkim_signature(headers)))



