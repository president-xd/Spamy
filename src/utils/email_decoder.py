
# Decode content with fallback
def decode_content(content, charset):
    if charset is None:
        charset = "utf-8"
    try:
        return content.decode(charset)
    except UnicodeDecodeError:
        return content.decode('utf-8', errors='ignore')