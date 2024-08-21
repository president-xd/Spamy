import imaplib
import email
import re
import time

# Global variables to store IMAP connection and credentials
mail = None
username = None
password = None

# Function to connect to the IMAP server
def connect_to_server(email_address, email_password, server="imap.gmail.com"):
    global mail
    mail = imaplib.IMAP4_SSL(server)
    try:
        mail.login(email_address, email_password)
        print("Login successful.")
        return True
    except imaplib.IMAP4.error as e:
        print(f"Login failed: {e}")
        return False

# Function to select a mailbox folder
def select_folder(folder):
    global mail
    mail.select(folder)

# Function to move emails to a specified folder
def move_emails(msg_ids, destination_folder):
    global mail
    for msg_id in msg_ids:
        mail.copy(msg_id, destination_folder)
        mail.store(msg_id, '+FLAGS', '\\Deleted')
    mail.expunge()

# Function to read spam words from a text file
def read_spam_words(filename):
    with open(filename, 'r') as file:
        spam_words = file.read().splitlines()
    return spam_words

# Function to read phishing domains from a text file
def read_phishing_domains(filename):
    with open(filename, 'r') as file:
        phishing_domains = file.read().splitlines()
    return phishing_domains

# Function to check for links in the email body
def contains_links(email_body):
    url_pattern = r'(https?://\S+)'
    urls = re.findall(url_pattern, email_body)
    return len(urls) > 0

# Function to check if an email contains a phishing link
def contains_phishing_link(email_body, phishing_domains):
    url_pattern = r'(https?://\S+)'
    urls = re.findall(url_pattern, email_body)
    for url in urls:
        for domain in phishing_domains:
            if domain.lower() in url.lower():
                return True
    return False

# Function to retrieve and process new emails
def retrieve_and_process_new_emails(spam_words, additional_phishing_domains=None):
    global mail
    select_folder("INBOX")
    result, data = mail.search(None, 'ALL')
    if result == "OK":
        msg_ids = data[0].split() if data else []
        if msg_ids:
            phishing_domains = read_phishing_domains("phishing_domains.txt")
            if additional_phishing_domains:
                phishing_domains += additional_phishing_domains
            for msg_id in msg_ids:
                result, data = mail.fetch(msg_id, "(RFC822)")
                if result == "OK":
                    raw_email = data[0][1]
                    if raw_email is None:
                        print(f"Failed to fetch email data for message ID: {msg_id}")
                        continue
                    msg = email.message_from_bytes(raw_email)
                    if not msg['Subject']:
                        move_emails([msg_id], "[Gmail]/Spam")
                        print("Email with no subject moved to spam folder.")
                        continue
                    email_body = ""
                    for part in msg.walk():
                        if part.get_content_type() == "text/plain":
                            email_body += part.get_payload(decode=True).decode()
                    if len(email_body.split()) < 2:
                        move_emails([msg_id], "[Gmail]/Spam")
                        print(f"Email with subject '{msg['Subject']}' moved to spam folder because it has less than 2 words in the body.")
                        continue
                    if contains_links(email_body):
                        move_emails([msg_id], "[Gmail]/Spam")
                        print(f"Email with subject '{msg['Subject']}' moved to spam folder because it contains a link.")
                        continue
                    if contains_phishing_link(email_body, phishing_domains):
                        move_emails([msg_id], "[Gmail]/Spam")
                        print(f"Email with subject '{msg['Subject']}' moved to spam folder because it contains a phishing link.")
                        continue
                    spam_found = False
                    for word in spam_words:
                        if word.lower() in email_body.lower():
                            move_emails([msg_id], "[Gmail]/Spam")
                            print(f"Email with subject '{msg['Subject']}' moved to spam folder because it contains a spam word: {word}.")
                            spam_found = True
                            break
                    if not spam_found:
                        print(f"Email with subject '{msg['Subject']}' processed successfully.")
                else:
                    print(f"Failed to fetch email data for message ID: {msg_id}")
        else:
            print("No new emails found.")
    else:
        print("Error searching emails:", result)

def main():
    global username, password
    
    # Get user credentials
    username = input("Enter your email address: ")
    password = input("Enter your email password: ")

    # Connect to the server
    if connect_to_server(username, password):
        # Read spam words
        spam_words = read_spam_words("spam_words.txt")
        
        # Main loop
        while True:
            retrieve_and_process_new_emails(spam_words)
            print("Waiting for 5 minutes before checking again...")
            time.sleep(300)  # Wait for 5 minutes before checking again

if __name__ == "__main__":
    main()