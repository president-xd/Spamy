import dns.resolver
import dkim
import requests
from rate_limiting import make_request_with_retry
from hash_finder import hash_attachment

def check_virustotal(link, api_key):
    url = "https://www.virustotal.com/vtapi/v2/url/report"
    params = {"apikey": api_key, "resource": link}
    response = make_request_with_retry(url, params, api_key, retries=5, backoff=1)
    
    if response and response.status_code == 200:
        result = response.json()
        positives = result.get("positives", 0)
        total = result.get("total", 0)
        score = (positives / total) * 100 if total > 0 else 0
        malicious = positives > 0
        return malicious, score
    else:
        return False, 0  # Default to not malicious if the request fails

# Extract email attachments
def get_attachments(msg):
    attachments = []
    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition"))
            if "attachment" in content_disposition:
                filename = part.get_filename()
                content = part.get_payload(decode=True)
                attachment_hash = hash_attachment(content)  # Update the attachment hash calculation
                attachments.append((filename, attachment_hash))
    return attachments

def check_urlscan(link):
    url = f"https://urlscan.io/api/v1/search/?q={link}"
    response = requests.get(url)
    
    if response.status_code == 200:
        result = response.json()
        malicious = any(item.get("verdicts", {}).get("overall", {}).get("malicious", False) for item in result.get("results", []))
        score = 100 if malicious else 0
        return malicious, score
    else:
        return False, 0  # Default to not malicious if the request fails

def analyze_link(link, VIRUS_TOTAL_API):
    vt_malicious, vt_score = check_virustotal(link, VIRUS_TOTAL_API)
    us_malicious, us_score = check_urlscan(link)
    
    is_malicious = vt_malicious or us_malicious
    combined_score = (vt_score + us_score) / 2  # Average score between VirusTotal and Urlscan
    
    return is_malicious, combined_score

def check_virustotal_hash(file_hash, api_key):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    params = {"apikey": api_key, "resource": file_hash}
    response = make_request_with_retry(url, params, api_key, retries=5, backoff=1)
    
    if response and response.status_code == 200:
        result = response.json()
        positives = result.get("positives", 0)
        total = result.get("total", 0)
        score = (positives / total) * 100 if total > 0 else 0
        malicious = positives > 0
        return malicious, score
    else:
        return False, 0  # Default to not malicious if the request fails
 # Default to not malicious if the request fails

def check_abuse_ch(file_hash):
    url = f"https://abuse.ch/api/lookup/sha256/{file_hash}/"
    response = requests.get(url)
    
    if response.status_code == 200:
        result = response.json()
        malicious = result.get("malicious", False)
        score = 100 if malicious else 0
        return malicious, score
    else:
        return False, 0  # Default to not malicious if the request fails

def analyze_attachment(file_hash, api_key):
    vt_malicious, vt_score = check_virustotal_hash(file_hash, api_key)
    abuse_ch_malicious, abuse_ch_score = check_abuse_ch(file_hash)
    
    is_malicious = vt_malicious or abuse_ch_malicious
    combined_score = (vt_score + abuse_ch_score) / 2  # Average score between VirusTotal and Abuse.ch
    
    return is_malicious, combined_score

def is_domain_blacklisted(domain):
    # Replace with an actual API or service for domain reputation checking
    url = f"https://some-domain-reputation-api.com/check?domain={domain}"
    response = requests.get(url)
    
    if response.status_code == 200:
        result = response.json()
        return result.get("blacklisted", False)
    else:
        return False  # Default to not blacklisted if the request fails

def verify_from_address(email_from):
    domain = email_from.split('@')[-1] if '@' in email_from else ""
    
    if domain:
        blacklisted = is_domain_blacklisted(domain)
        return 0 if blacklisted else 100  # 0 for blacklisted, 100 for safe
    return 0  # Invalid email format


def validate_message_id(message_id, existing_ids):
    if message_id in existing_ids:
        return 100  # Not unique
    existing_ids.add(message_id)
    return 0  # Unique

def analyze_received_headers(received_headers):
    suspicious_sources = ["sbl.spamhaus.org", "bl.spamcop.net", "ips.backscatterer.org",
                          "dnsbl.sorbs.net", "b.barracudacentral.org", "bl.spamcop.net",
                          "http.dnsbl.sorbs.net", "smtp.dnsbl.sorbs.net", "socks.dnsbl.sorbs.net",
                          "sbl.spamhaus.org", "zen.spamhaus.org", "ubl.unsubscore.com",
                          "dul.dnsbl.sorbs.net", "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net",
                          "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net", "relays.mail-abuse.org",
                          "multi.uribl.com", "relays.mail-abuse.org", "bl.emailbasura.org",
                          "b.barracudacentral.org", "bl.spamcop.net", "bl.spamcannibal.org",
                          "psbl.surriel.com", "zen.spamhaus.org", "sbl.spamhaus.org",
                          "bl.spamcannibal.org", "sbl.spamhaus.org", "dnsbl.sorbs.net",
                          "multi.uribl.com", "bl.spamcop.net", "http.dnsbl.sorbs.net",
                          "smtp.dnsbl.sorbs.net", "socks.dnsbl.sorbs.net", "pbl.spamhaus.org",
                          "rbl.interserver.net", "dnsbl.rabl.net", "dnsbl.kempt.net",
                          "all.s5h.net", "rbl.efnetrbl.org", "tor.dnsbl.sectoor.de", "dnsbl.cyberlogic.net",
                          "tor.dnsbl.sectoor.de", "dnsbl.sorbs.net", "relays.mail-abuse.org",
                          "multi.uribl.com", "relays.mail-abuse.org", "sbl.spamhaus.org",
                          "zen.spamhaus.org", "ubl.unsubscore.com", "dul.dnsbl.sorbs.net",
                          "dnsbl-1.uceprotect.net", "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net",
                          "dnsbl.cyberlogic.net", "blackholes.mail-abuse.org", "b.barracudacentral.org",
                          "bl.spamcop.net", "bl.spamcannibal.org", "psbl.surriel.com",
                          "zen.spamhaus.org", "sbl.spamhaus.org", "bl.spamcannibal.org",
                          "sbl.spamhaus.org", "dnsbl.sorbs.net", "multi.uribl.com",
                          "bl.spamcop.net", "http.dnsbl.sorbs.net", "smtp.dnsbl.sorbs.net",
                          "socks.dnsbl.sorbs.net", "pbl.spamhaus.org", "rbl.interserver.net",
                          "dnsbl.rabl.net", "dnsbl.kempt.net", "all.s5h.net",
                          "rbl.efnetrbl.org", "tor.dnsbl.sectoor.de", "dnsbl.cyberlogic.net",
                          "tor.dnsbl.sectoor.de", "sbl.spamhaus.org", "zen.spamhaus.org",
                          "ubl.unsubscore.com", "dul.dnsbl.sorbs.net", "dnsbl-1.uceprotect.net",
                          "dnsbl-2.uceprotect.net", "dnsbl-3.uceprotect.net", "dnsbl.cyberlogic.net",
                          "bl.spamcop.net"]
    for header in received_headers:
        if any(source in header for source in suspicious_sources):
            return 100  # Suspicious

    return 0  # No suspicious sources found

def validate_dkim_signature(dkim_signature, email_body):
    try:
        if isinstance(email_body, str):
            email_body = email_body.encode('utf-8')
        if isinstance(dkim_signature, str):
            dkim_signature = dkim_signature.encode('utf-8')
        is_valid = dkim.verify(email_body, dkim_signature)
        return 100 if is_valid else 0
    except Exception as e:
        print(f"DKIM verification failed: {e}")
        return 0


def validate_to(mail_to, recipent_mail):
    return 100 if mail_to == recipent_mail else 0

def check_dmarc_policy(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            if "v=DMARC1" in rdata.to_text():
                return 100  # DMARC record exists
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return 0  # No DMARC record
    return 0  # No valid DMARC record found

def check_dmarc_policy(domain):
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            if "v=DMARC1" in rdata.to_text():
                return 100  # DMARC record exists
        return 0  # DMARC record not found
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
        return 0  # DNS query failed or no DMARC record found

def validate_dmarc_header(dmarc_header, from_):
    domain = from_.split('@')[-1] if '@' in from_ else ""
    return check_dmarc_policy(domain)


def check_spf_record(domain):
    try:
        answers = dns.resolver.resolve(f"{domain}", "TXT")
        for rdata in answers:
            if rdata.to_text().startswith("v=spf1"):
                return 100  # SPF record exists
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return 0  # No SPF record
    return 0  # No valid SPF record found

def validate_spf_header(spf_header, email_from):
    domain = email_from.split('@')[-1]
    return check_spf_record(domain)