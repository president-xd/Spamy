from email_decoder import *
import re
from hash_finder import *

# Regex Patterns
LINK_REGEX = r'href=["\'](https?://[^\s"\']*)["\']'

# Extract links from the email body
def get_links(body):
    return re.findall(LINK_REGEX, body)

# Extract email headers
def get_headers(msg):
    headers = {}
    for key, val in msg.items():
        headers[key] = val
    return headers

# Extract email attachments
def get_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                attachment_hash = hash_attachment(content)
                attachments.append((filename, attachment_hash))
    return attachments

def get_email_body(msg):
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                content = part.get_payload(decode=True)
                body = decode_content(content, part.get_content_charset())
                break
    else:
        content = msg.get_payload(decode=True)
        body = decode_content(content, msg.get_content_charset())
    return body

