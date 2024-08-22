import imaplib  # For connecting to the IMAP server
import email  # For parsing the emails
from email.header import decode_header  # For decoding email headers
import re  # For analyzing email content
import hashlib  # For creating digests
import quopri  # For decoding quoted-printable emails
import time
from datetime import datetime
import json
import concurrent.futures
import requests
from urllib.parse import urlparse


# Global Settings
THRESHOLD_SCORE = 75  # Spam score threshold

# Regex Patterns
LINK_REGEX = r'href=\"((?:\S)*)\"'
MAIL_REGEX = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'

BLACKLISTED_LINKS = [
    "malicious.com",
    "phishing.com",
    "suspicious-domain.net"
]

BLACKLISTED_EMAILS = [
    "spam@example.com",
    "phisher@malicious.com",
    "scammer@fraudulent.org"
]



# Supported investigation tools
INVESTIGATION_TOOLS = {
    "Virustotal": "https://www.virustotal.com/gui/search/",
    "Abuseipdb": "https://www.abuseipdb.com/check/",
    "Urlscan": "https://urlscan.io/search/#"
}

# Connect to Gmail
def connect_to_gmail(email_address, app_password):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_address, app_password)
        return mail
    except imaplib.IMAP4.error as e:
        print(f"Login failed: {str(e)}")
        return None

def check_and_analyze_emails(mail, investigate=False):
    mail.select("inbox")
    result, data = mail.search(None, "ALL")  # Fetch all emails
    email_count = 1
    if result == "OK":
        for num in data[0].split():
            result, msg_data = mail.fetch(num, "(RFC822)")
            if result == "OK":
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]
                        
                        if isinstance(raw_email, bytes):
                            msg = email.message_from_bytes(raw_email)
                            subject = decode_header(msg["subject"])[0][0] or "<No Subject>"
                            from_ = msg.get("From")
                            
                            # Analyze the email
                            analysis_result = analyze_email(msg, investigate)
                            
                            # Print formatted email info
                            print(f"Email {email_count} ==> From: {from_}, Subject: {subject}")
                            if analysis_result:
                                print("Malicious content detected. Moving to spam...\n")
                                move_to_spam(mail, num)
                            else:
                                print("No malicious content detected.\n")
                            
                            # Print analysis data in indented form
                            analysis_data = get_analysis_data(msg, investigate)
                            formatted_analysis_data = json.dumps(analysis_data, indent=4)
                            print("Analysis Data:\n" + formatted_analysis_data)
                            
                            email_count += 1
                        else:
                            print(f"Error: Expected bytes, got {type(raw_email)} instead. Content: {raw_email}")
            else:
                print(f"Error fetching email with ID {num}: {result}")

    print(f"Total number of emails analyzed: {email_count}")

def analyze_email(msg, investigate=False):
    score = 0
    analysis_data = {"Headers": {}, "Links": {}, "Attachments": {}, "Digests": {}}
    headers = get_headers(msg, investigate)
    if headers.get("score"):
        score += headers["score"]
    analysis_data["Headers"] = headers

    body = get_email_body(msg)
    links = get_links(body, investigate)
    if links.get("score"):
        score += links["score"]
    analysis_data["Links"] = links

    attachments = get_attachments(msg, investigate)
    if attachments.get("score"):
        score += attachments["score"]
    analysis_data["Attachments"] = attachments

    digests = get_digests(body)
    analysis_data["Digests"] = digests

    # Print analysis_data with indentation for readability
    print(f"Total Score: {score}")
    print("Analysis Data:")
    print(json.dumps(analysis_data, indent=4))

    return score >= THRESHOLD_SCORE

def get_analysis_data(msg, investigate=False):
    score = 0
    analysis_data = {"Headers": {}, "Links": {}, "Attachments": {}, "Digests": {}}

    # Get and analyze headers
    headers = get_headers(msg, investigate)
    if headers.get("score"):
        score += headers["score"]
    analysis_data["Headers"] = headers

    # Get and analyze email body
    body = get_email_body(msg)
    links = get_links(body, investigate)
    if links.get("score"):
        score += links["score"]
    analysis_data["Links"] = links

    # Get and analyze attachments
    attachments = get_attachments(msg, investigate)
    if attachments.get("score"):
        score += attachments["score"]
    analysis_data["Attachments"] = attachments

    # Get email digests (hash values)
    digests = get_digests(body)
    analysis_data["Digests"] = digests

    return analysis_data

# Extract and analyze headers
def get_headers(msg, investigate=False):
    headers = {}
    score = 0

    # Extract headers
    for key, val in msg.items():
        headers[key.lower()] = val

    # Analyze sender
    sender = headers.get("from")
    if sender and check_suspicious_sender(sender):
        score += 50

    # Analyze spoofing (Reply-To vs From)
    reply_to = headers.get("reply-to")
    if reply_to and sender and not check_same_address(reply_to, sender):
        score += 25

    # Investigate sender IP if available
    if investigate and headers.get("x-sender-ip"):
        headers["x-sender-ip-investigation"] = generate_investigation_links(headers["x-sender-ip"])

    return {"data": headers, "score": score}

# Extract email body
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

# Decode content with fallback
def decode_content(content, charset):
    if charset is None:
        charset = "utf-8"
    try:
        return content.decode(charset)
    except UnicodeDecodeError:
        # Fallback to a more lenient decoding strategy
        try:
            return content.decode('utf-8', errors='ignore')
        except UnicodeDecodeError:
            return content.decode('latin1', errors='ignore')

# Collect and analyze links from the email body
def get_links(body, investigate=False):
    """
    This function will detect and score links, score based on the number of links,
    and return links, score, and investigation links.
    """
    links = re.findall(LINK_REGEX, body)
    score = len(links) * 10

    if investigate:
        investigation_links = {}
        for i, link in enumerate(links, start=1):
            investigation_links[i] = {}
            # Check if the link is HTTPS
            if link.startswith("https://"):
                investigation_links[i]["HTTPS"] = True
            else:
                investigation_links[i]["HTTPS"] = False
            # Check if the link has a valid domain
            try:
                parsed_url = urlparse(link)
                domain = parsed_url.netloc
                investigation_links[i]["ValidDomain"] = bool(domain)
            except ValueError:
                investigation_links[i]["ValidDomain"] = False
            # Check if the link is blacklisted
            if link in BLACKLISTED_LINKS:
                investigation_links[i]["Blacklisted"] = True
            else:
                investigation_links[i]["Blacklisted"] = False
                # Check if the link is a known phishing link
            investigation_links[i] = investigate_item(link)
            investigation_links[i]["Phishing"] = any(tool_result.get("Phishing", False) for tool_result in investigation_links[i].values())
            else:
                investigation_links[i]["Phishing"] = False
            # Investigate the link using external tools
            investigation_links[i]["VirusTotal"] = generate_investigation_links(link)
    else:
        investigation_links = {}

    return {"data": links, "score": score, "investigation_links": investigation_links}

def get_attachments(msg, investigate=False):
    score = 0
    attachments = []
    investigation_links = {}

    # Check if the email has multiple parts (attachments, text, etc.)
    if msg.is_multipart():
        # Walk through the email parts
        for part in msg.walk():
            # Check the content disposition to find attachments
            content_disposition = str(part.get("Content-Disposition"))

            # If the part is an attachment
            if "attachment" in content_disposition:
                filename = part.get_filename()  # Get the filename of the attachment
                content = part.get_payload(decode=True)  # Decode the attachment content

                # Calculate MD5 and SHA256 hash of the attachment content
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

                # Store the attachment information
                attachments.append({
                    "filename": filename,
                    "md5": md5_hash,
                    "sha256": sha256_hash
                })

                # Add to the score due to the presence of an attachment
                score += 20

                # If investigation is enabled, check the attachment using VirusTotal
                if investigate:
                    investigation_links[filename] = investigate_attachment(filename, md5_hash, sha256_hash)

    # Return the attachments data, score, and investigation results
    return {"data": attachments, "score": score, "investigation": investigation_links}


def investigate_attachment(filename, md5_hash, sha256_hash):
    investigation_results = {}
    try:
        # Virustotal Analysis
        vt_url = f"{INVESTIGATION_TOOLS['Virustotal']}{sha256_hash}"
        headers = {'x-apikey': '165a3b18909ef58f61f7d05c82878fbd95bab4e3ef9e196a216f0f344d74f1d1'}
        response = requests.get(vt_url, headers=headers)
        
        if response.status_code == 200:
            vt_result = response.json()
            investigation_results['Virustotal'] = vt_result
        else:
            investigation_results['Virustotal'] = f"Virustotal check failed with status code {response.status_code}."

    except Exception as e:
        investigation_results['Virustotal'] = f"Error: {str(e)}"

    return investigation_results

# Enhanced investigation with parallel processing
def parallel_investigation(items):
    results = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_item = {executor.submit(investigate_item, item): item for item in items}
        for future in concurrent.futures.as_completed(future_to_item):
            item = future_to_item[future]
            try:
                result = future.result()
                results[item] = result
            except Exception as e:
                results[item] = str(e)
    return results

def investigate_item(item):
    links = generate_investigation_links(item)
    investigation_results = {}
    for tool, url in links.items():
        response = requests.get(url)
        if response.status_code == 200:
            investigation_results[tool] = response.json()
        else:
            investigation_results[tool] = "Failed to retrieve data"
    return investigation_results

# Use the parallel investigation in your existing analysis functions
def get_links(body, investigate=False):
    links = re.findall(LINK_REGEX, body)
    score = 0

    if links:
        score += len(links) * 10

    if investigate:
        investigation_links = parallel_investigation(links)
    else:
        investigation_links = {}

    return {"data": links, "score": score, "investigation": investigation_links}

# Extract and analyze attachments
def get_attachments(msg, investigate=False):
    score = 0
    attachments = []
    investigation_links = {}

    if msg.is_multipart():  # Check if the message is multipart
        for part in msg.walk():  # Walk through the parts
            content_disposition = str(part.get("Content-Disposition"))

            if "attachment" in content_disposition:  # Check if the part is an attachment
                filename = part.get_filename()
                content = part.get_payload(decode=True)

                # Calculate hash values
                md5_hash = hashlib.md5(content).hexdigest()
                sha256_hash = hashlib.sha256(content).hexdigest()

                attachments.append({
                    "filename": filename,
                    "md5": md5_hash,
                    "sha256": sha256_hash
                })

                # Score based on the attachment presence
                score += 20

                if investigate:
                    investigation_links[filename] = {
                        "md5": f"{INVESTIGATION_TOOLS['Virustotal']}{md5_hash}",
                        "sha256": f"{INVESTIGATION_TOOLS['Virustotal']}{sha256_hash}"
                    }

    return {"data": attachments, "score": score, "investigation": investigation_links}


# Get email digests
def get_digests(body):
    md5 = hashlib.md5(body.encode("utf-8")).hexdigest()
    sha256 = hashlib.sha256(body.encode("utf-8")).hexdigest()
    return {"md5": md5, "sha256": sha256}

# Check for suspicious sender domains
def check_suspicious_sender(sender):
    suspicious_domains = ["suspicious.com", "phishing.com"]
    return any(domain in sender for domain in suspicious_domains)

# Check if two email addresses are the same
def check_same_address(address1, address2):
    return re.findall(MAIL_REGEX, address1)[0].lower() == re.findall(MAIL_REGEX, address2)[0].lower()

# Generate investigation links
def generate_investigation_links(item):
    links = {}
    for tool, url in INVESTIGATION_TOOLS.items():
        links[tool] = f"{url}{item}"
    return links

# Move an email to the spam folder
def move_to_spam(mail, email_id):
    result = mail.store(email_id, "+X-GM-LABELS", "\\Spam")
    if result[0] == "OK":
        mail.store(email_id, "+FLAGS", "\\Deleted")
        mail.expunge()

# Main function to connect and start analyzing emails
if __name__ == "__main__":
    email_address = "lasharimohsin19@gmail.com"
    app_password = "qxma fuag xjzt ejif"

    # Connect to Gmail
    mail = connect_to_gmail(email_address, app_password)
    if mail:
        while True:
            check_and_analyze_emails(mail, investigate=True)
            time.sleep(60)  # Check emails every minute

        # Close the connection when done
        mail.close()
        mail.logout()
