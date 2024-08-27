import hashlib

def hash_attachment(file_content):
    sha256_hash = hashlib.sha256()
    # Directly update the hash with the content, since file_content is already in bytes
    sha256_hash.update(file_content)
    return sha256_hash.hexdigest()