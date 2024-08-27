from utils.email_connection import *
from utils.email_checker import *
import time

VIRUS_TOTAL_API = ""

if __name__ == "__main__":
    banner()
    print("App password is necessary for this tools this can be obained by turning your 2-Factor Authentication of your Google account.")
    email_address = input("Enter your email: ")
    app_password = input("Enter your app passwords: ")
    VIRUS_TOTAL_API = input("Enter your Virus Total API: ")

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
