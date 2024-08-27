from email.header import decode_header  # For decoding email headers
from email.utils import parseaddr
from email_analysis import *

def extract_dmarc_header(headers):
    # Extract the domain from the 'From' header
    from_address = extract_from(headers)
    domain = from_address.split('@')[-1] if '@' in from_address else ''
    return check_dmarc_policy(domain)

def parse_dkim_signature(dkim_signature):
    components = {}
    for part in dkim_signature.split(';'):
        key_value = part.strip().split('=', 1)
        if len(key_value) == 2:
            key, value = key_value
            components[key.strip()] = value.strip()
    return components

def extract_from(headers):
    raw_from = headers.get('From', 'No From header found')
    
    if isinstance(raw_from, str):
        decoded_from = decode_header(raw_from)
        from_str = ''.join(
            part[0].decode(part[1] or 'utf-8') if isinstance(part[0], bytes) else str(part[0])
            for part in decoded_from
        )
    else:
        from_str = str(raw_from)
    
    name, email_addr = parseaddr(from_str)
    return email_addr if email_addr else 'No valid email found'

def extract_to(headers):
    return headers.get('To', 'No To header found')

def extract_date(headers):
    return headers.get('Date', 'No Date header found')

def extract_message_id(headers):
    return headers.get('Message-ID', 'No Message-ID header found')

def extract_received(headers):
    received_headers = headers.get('Received', [])
    if isinstance(received_headers, str):
        received_headers = [received_headers]
    return received_headers

def extract_dkim_signature(headers):
    dkim_signature = headers.get('DKIM-Signature', 'No DKIM-Signature header found')
    return dkim_signature

def extract_spf(headers):
    return headers.get('Received-SPF', 'No SPF header found')