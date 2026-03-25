import email
import re
from email import policy
from email.parser import BytesParser

def parse_email(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    results = {
        "subject": str(msg["subject"]),
        "from": str(msg["from"]),
        "to": str(msg["to"]),
        "reply_to": str(msg["reply-to"]),
        "date": str(msg["date"]), 
        "urls": extract_urls(msg),
        "attachments": extract_attachments(msg),
        "headers": extract_headers(msg)
        

    }

    return results

def extract_urls(msg):
    urls = []
    url_pattern = re.compile(r'https?://[^\s<>"\']+')

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ["text/plain", "text/html"]:
                body = part.get_content()
                found = url_pattern.findall(body)
                urls.extend(found)

    else:
        body=msg.get_content()
        found = url_pattern.findall(body)
        urls.extend(found)

    return list(set(urls))

def extract_attachments(msg):
    attatchments = []

    for part in msg.walk():
        if part.get_content_disposition() == "attachment":
            attatchments.append({
                "filename": part.get_filename(),
                "type": part.get_content_type()
            })
    return attatchments

def extract_headers(msg):
    headers = {}
    for header in ["recieved", "x-originating-ip", "x-mailer", "message-id"]:
        value = msg.get(header)
        if value:
            headers[header] = str(value)
        
        return headers

