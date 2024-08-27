import imaplib

def connect_to_gmail(email_address, app_password):
    try:
        mail = imaplib.IMAP4_SSL("imap.gmail.com")
        mail.login(email_address, app_password)
        return mail
    except imaplib.IMAP4.error as e:
        print(f"Login failed: {str(e)}")
        return None