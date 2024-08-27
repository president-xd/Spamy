import requests
import time

# Rate Limiting
def make_request_with_retry(url, params, api_key, retries=5, backoff=1):
    headers = {"apikey": api_key}
    for attempt in range(retries):
        try:
            response = requests.get(url, params=params, headers=headers)
            if response.status_code == 429:  # Rate limit exceeded
                print(f"Rate limit exceeded, retrying in {backoff} seconds...")
                time.sleep(backoff)
                backoff *= 2  # Exponential backoff
                continue
            response.raise_for_status()
            return response  # Return the response object itself
        except requests.RequestException as e:
            print(f"Request failed: {e}")
            time.sleep(backoff)
            backoff *= 2
    return None