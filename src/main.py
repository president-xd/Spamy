from email_connection import *
from email_checker import *
import time

VIRUS_TOTAL_API = "165a3b18909ef58f61f7d05c82878fbd95bab4e3ef9e196a216f0f344d74f1d1"

if __name__ == "__main__":
    email_address = "lasharimohsin19@gmail.com"
    app_password = "qxma fuag xjzt ejif"  # Consider using environment variables for security

    # Connect to Gmail
    mail = connect_to_gmail(email_address, app_password)
    if mail:
        try:
            while True:
                check_and_extract_emails(email_address, mail, VIRUS_TOTAL_API, THRESHOLD=20)  
                time.sleep(60)  # Check emails every minute
        except KeyboardInterrupt:
            print("Stopping email extraction.")
        finally:
            try:
                # Close the connection when done
                mail.close()
            except imaplib.IMAP4.error as e:
                print(f"Error closing connection: {e}")
            finally:
                mail.logout()
    else:
        print("Failed to connect to Gmail.")