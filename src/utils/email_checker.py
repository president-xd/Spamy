from getter import *
import email
from email_decoder import *
from email.header import decode_header
from data_printing import *
from email_analysis import *
import os

# Define a list or set of malicious file extensions
MALICIOUS_EXTENSIONS = {
    '.exe', '.bat', '.js', '.vbs', '.scr', '.cmd', '.dll', '.msi',
    '.pif', '.cpl', '.ocx', '.reg', '.ps1', '.app', '.pl',
    '.asp', '.cgi', '.hta', '.wsf', '.wsh', '.jar', '.apk',
    '.sh', '.cgi', '.xap', '.jar', '.bin', '.dat', '.gadget',
    '.lnk', '.torrent', '.sys', '.tmp', '.msu', '.dmg', '.iso',
    '.7z', 'rar', 'zip', '.tar', '.gz', '.arj', '.ace'
}

THRESHOULD = 20

def mark_as_spam(mail, email_id):
    try:
        # Select the inbox
        mail.select("inbox")
        
        # Copy the email to the Spam folder
        result, data = mail.copy(email_id, "Spam")
        if result == "OK":
            # Mark the email for deletion in the inbox
            mail.store(email_id, '+FLAGS', '\\Deleted')
            # Permanently remove marked emails
            mail.expunge()
            print(f"Email with ID {email_id} marked as spam.")
        else:
            print(f"Failed to mark email with ID {email_id} as spam.")
    except Exception as e:
        print(f"An error occurred: {e}")


def check_and_extract_emails(email_address, mail, VIRUS_TOTAL_API, THRESHOLD):
    try:
        mail.select("inbox")
        result, data = mail.search(None, "ALL")  # Fetch all emails
        if result != "OK":
            print(f"Error selecting inbox: {result}")
            return

        email_count = 0
        for num in data[0].split():
            result, msg_data = mail.fetch(num, "(RFC822)")
            if result == "OK":
                for response_part in msg_data:
                    if isinstance(response_part, tuple):
                        raw_email = response_part[1]

                        if isinstance(raw_email, bytes):
                            msg = email.message_from_bytes(raw_email)
                            from_ = msg.get("From")
                            to_ = msg.get("To")
                            subject = decode_header(msg["Subject"])[0][0] or "<No Subject>"
                            date_ = msg.get("Date")
                            message_id = msg.get("Message-ID")
                            received_headers = msg.get_all("Received", [])
                            dkim_signature = msg.get("DKIM-Signature", "")
                            spf_header = msg.get("Received-SPF", "")
                            dmarc_header = msg.get("DMARC", "")

                            # Print formatted email info
                            email_count += 1
                            print(f"EMAIL {email_count}: {from_} ==> {to_} Subject: {subject}")

                            # Extract and print necessary headers
                            headers = get_headers(msg)
                            print_necessary_headers(headers)

                            # Extract and print links
                            body = get_email_body(msg)
                            links = get_links(body)
                            total_link_score = 0.0
                            if links:
                                print(f"{TAB_2} LINKS:")
                                for link in links:
                                    print(format_multi_line(DATA_TAB_3, link))

                                    # Analyze each link
                                    is_malicious, score = analyze_link(link, VIRUS_TOTAL_API)
                                    print(f"{TAB_3} Malicious: {is_malicious}, Score: {score}")
                                    total_link_score += score
                                    print("\n")

                            else:
                                print(f"{TAB_2} LINKS:")
                                print(f"{DATA_TAB_3} No links found.")

                            # Extract and print attachments
                            total_attachment_score = 0.0
                            attachments = get_attachments(msg)
                            if attachments:
                                print(f"{TAB_2} Attachments:")
                                for filename, file_hash in attachments:
                                    file_root, file_extension = os.path.splitext(filename)
                                    # Check if the file extension is malicious
                                    is_malicious_extension = file_extension.lower() in MALICIOUS_EXTENSIONS
                                    extension_score = 1.0 if is_malicious_extension else 0.0
                                    
                                    print(format_multi_line(TAB_3, "Name: ", filename))
                                    print(f"{TAB_3} Extension: {file_extension}")
                                    
                                    # Analyze the attachment if it is not already flagged by the extension
                                    if not is_malicious_extension:
                                        is_malicious, score = analyze_attachment(file_hash, VIRUS_TOTAL_API)
                                        score += extension_score  # Add the extension score to the analysis score
                                    else:
                                        is_malicious = True
                                        score = extension_score
                                    print(f"{TAB_3} Hash: {file_hash}")
                                    print(f"{TAB_3} Malicious: {'Yes' if is_malicious else 'No'}")
                                    print(f"{TAB_3} Score: {score:.2f}")
                                    total_attachment_score += score

                            else:
                                print(f"{TAB_2} Attachments:")
                                print(f"{DATA_TAB_3} No attachments found.")
                            
                            # Calculate individual scores
                            to_score = validate_to(to_, email_address)
                            received_headers_score = analyze_received_headers(received_headers)
                            dkim_score = validate_dkim_signature(dkim_signature, body)
                            spf_score = validate_spf_header(spf_header, from_)
                            dmarc_score = validate_dmarc_header(dmarc_header, from_)

                            # Print additional analysis
                            print(f"============================================================================================================================================================")    
                            print(f"{DATA_TAB_4}{DATA_TAB_3} Additional Analysis:")
                            print(f"============================================================================================================================================================")
                            print(f"{TAB_3} To Address Score: {to_score}")
                            print(f"{TAB_3} Received Headers Score: {received_headers_score}")
                            print(f"{TAB_3} DKIM Signature Score: {dkim_score}")
                            print(f"{TAB_3} SPF Record Score: {spf_score}")
                            print(f"{TAB_3} DMARC Policy Score: {dmarc_score}")

                            # Total score calculation
                            total_score = (total_link_score + total_attachment_score +
                                           to_score + received_headers_score +
                                           dkim_score + spf_score + dmarc_score)

                            # Determine if the email should be marked as spam
                            if total_score >= THRESHOLD:
                                print(f"{TAB_2} Result: Spam")
                                mark_as_spam(mail, num)
                                print(f"{DATA_TAB_2} Email Sent to Spam Successfully.......")
                            else:
                                print(f"{TAB_2} Result: Not Spam")

                            print(f"============================================================================================================================================================")
                            print("\n")
                        else:
                            print(f"Error: Expected bytes, got {type(raw_email)} instead. Content: {raw_email}")
            else:
                print(f"Error fetching email with ID {num}: {result}")
    except Exception as e:
        print(f"An error occurred: {e}")