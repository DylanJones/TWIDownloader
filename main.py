#!/usr/bin/env python
import os
from bs4 import BeautifulSoup
import base64
import re
import requests
import logging
from argparse import ArgumentParser
from pathlib import Path
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# ANSI color codes
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GRAY = '\033[37m'  # Changed from 90 (dark gray) to 37 (light gray) for better visibility
    BOLD = '\033[1m'
    RESET = '\033[0m'

def colored(text, color):
    """Return colored text"""
    return f"{color}{text}{Colors.RESET}"

def print_success(msg):
    """Print success message with green color and emoji"""
    print(f"{Colors.GREEN}✓{Colors.RESET} {msg}")

def print_error(msg):
    """Print error message with red color and emoji"""
    print(f"{Colors.RED}✗{Colors.RESET} {msg}")

def print_warning(msg):
    """Print warning message with yellow color and emoji"""
    print(f"{Colors.YELLOW}⚠{Colors.RESET}  {msg}")

def print_info(msg):
    """Print info message with blue color and emoji"""
    print(f"{Colors.BLUE}ℹ{Colors.RESET}  {msg}")

def print_step(msg):
    """Print step message"""
    print(f"{Colors.CYAN}→{Colors.RESET} {msg}")

# Custom formatter for verbose logging
class VerboseFormatter(logging.Formatter):
    def format(self, record):
        if record.levelno == logging.DEBUG:
            return f"{Colors.GRAY}  ⋯ {record.getMessage()}{Colors.RESET}"
        elif record.levelno == logging.WARNING:
            return f"{Colors.YELLOW}  ⚠ {record.getMessage()}{Colors.RESET}"
        elif record.levelno == logging.ERROR:
            return f"{Colors.RED}  ✗ {record.getMessage()}{Colors.RESET}"
        else:
            return f"  {record.getMessage()}"

log = logging.getLogger("downloader")
handler = logging.StreamHandler()
handler.setFormatter(VerboseFormatter())
log.addHandler(handler)
log.setLevel(logging.INFO)

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
DOCUMENT_DIR = Path('/sdcard/Books/Wandering Inn')
PARSER = 'html.parser'
N_RECENT = 2

def get_creds():
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # if the creds are expired and a refresh might work, try that first.
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except RefreshError:
            creds = None
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)
    if creds and creds.valid:
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds

def parse_email(json):
    """
    Parse email to extract post URLs and password
    """
    # Decode b64 to utf8 text
    html = base64.urlsafe_b64decode(json['payload']['body']['data']).decode('utf8')
    # Bingo's emails used to come in a bit differently.
    # html = base64.urlsafe_b64decode(json['payload']['parts'][1]['body']['data']).decode('utf8')
    # Parse
    html = BeautifulSoup(html, features=PARSER)
    # Find the one with "password" in it
    pw_tag = html.find(string=re.compile('Password:'))
    
    # Return early if there's no password in the post
    if pw_tag is None:
        log.debug("No password found in email - assuming public post")
        password = ""
    else:
        # Check if the password got lumped in with this tag; if so, extract it now
        if match := re.search(r'Password:\s*(\w+)', pw_tag.text):
            password = match.group(1)
        else:
            # Password wasn't in this tag, assume it's the text of the next one
            pw_tag = pw_tag.next
            while not pw_tag.text.strip().isalnum():
                pw_tag = pw_tag.next
            password = pw_tag.text.strip()
        log.debug(f"Password found: {colored(password, Colors.CYAN)}")
    
    # Extract post link(s)
    links = [x.text for x in html.find_all('a', string=re.compile('https://wanderinginn.com'))]
    log.debug(f"Found {len(links)} post link(s)")
    return links, password

def make_request(url, password):
    """
    Make an authenticated request to a post.
    
    The Wandering Inn uses a hybrid Patreon+password system where:
    - Posts can be protected by Patreon membership
    - Password can bypass the Patreon gate
    - Password submitted directly to page URL with 'hybrid_pass' parameter
    
    Returns the HTML content if successful, raises RuntimeError if authentication fails.
    """
    sess = requests.session()
    sess.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0',
        'Referer': url
    })
    
    # First, check if the post needs a password at all
    log.debug("Fetching post...")
    response = sess.get(url)
    
    if response.status_code != 200:
        log.error(f"HTTP {response.status_code} - Failed to retrieve page")
        raise RuntimeError(f"error: got response code {response.status_code}")
    
    html_content = response.content.decode('utf8')
    
    # Check if password protection is present
    has_patreon_gate = 'Unlock with Patreon' in html_content or 'Patreon Exclusive' in html_content
    has_hybrid_system = 'HYBRID_BAD_PASSWORD' in html_content or 'hybrid-password-form' in html_content
    
    # If no password protection, we're done
    if not has_patreon_gate and not has_hybrid_system:
        log.debug("No password protection - public post")
        return html_content
    
    # Post is password-protected - submit password to hybrid system
    if not password:
        log.error("Post requires password but none provided")
        raise RuntimeError("Post is password-protected but no password was provided")
    
    log.debug("Password protection detected")
    print_step("Submitting password...")
    post_response = sess.post(
        url,
        data={'hybrid_pass': password},
        allow_redirects=True
    )
    log.debug(f"Password submission status: {post_response.status_code}")
    
    # Get the updated content
    html_content = post_response.content.decode('utf8')
    
    # Verify authentication success
    if 'HYBRID_BAD_PASSWORD = "1"' in html_content:
        print_error("Incorrect password")
        raise RuntimeError("Password authentication failed - incorrect password")
    
    # Check content length to verify we got the post
    content_size_kb = len(html_content) / 1024
    if len(html_content) < 10000:
        log.warning(f"Content seems short ({content_size_kb:.1f} KB) - password may not have worked")
    else:
        log.debug(f"Received {content_size_kb:.1f} KB of content")
    
    log.debug("Authentication successful")
    return html_content

def extract_title(html):
    """
    """
    html = BeautifulSoup(html, features=PARSER)
    #return html.find(class_='entry-title').text.replace('Protected: ', '').replace('Patron Early Access: ', '').strip()
    return html.find(property='og:title').attrs['content'].replace('Protected: ', '').replace('Patron Early Access: ', '').strip()

def download_and_save(mail):
    """
    Given the mail json, parse out the password and post URL, make the authenticated
    request, then save it to the disk under the correct filename.
    """
    
    # Decode and parse html
    try:
        result = parse_email(mail)
        if not result:
            print_info("No links found in email")
            return
        urls, password = result
    except Exception as e:
        print_error(f"Error parsing email: {e}")
        log.debug(f"Mail ID: {mail['id']}, snippet: {mail['snippet']}")
        import traceback; traceback.print_exc()
        return
    
    new_file = False
    for url in urls:
        # Extract just the post name from URL for display
        post_name = url.split('/')[-2] if url.endswith('/') else url.split('/')[-1]
        
        print_step(f"Downloading {colored(post_name, Colors.BOLD)}...")
        log.debug(f"URL: {url}")
        
        try:
            post_content = make_request(url, password)
            
            # Save temp copy for debugging
            with open('tmp.html', 'w') as f:
                f.write(post_content)
            
            title = extract_title(post_content)
            post_path = DOCUMENT_DIR / (title + '.html')
            
            if not os.path.exists(post_path):
                with open(post_path, 'w') as f:
                    f.write(post_content)
                print_success(f"Saved: {colored(title, Colors.BOLD)}")
                new_file = True
            else:
                print_info(f"Already exists: {title}")
                
        except RuntimeError as e:
            print_error(f"Failed to download: {e}")
            continue
            
    return new_file

def main():
    global matches, match, mail, result, messages, service
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    parser = ArgumentParser('TWIDownloader')
    parser.add_argument('--verbose', action="store_true", default=False)
    parser.add_argument("-n", type=int, help="number of posts to download", default=3)
    args = parser.parse_args()
    
    if args.verbose:
        log.setLevel(logging.DEBUG)
    
    # Header
    print()
    print(f"{Colors.BOLD}{Colors.CYAN}╔══════════════════════════════════════════╗{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}║   The Wandering Inn Post Downloader      ║{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.CYAN}╚══════════════════════════════════════════╝{Colors.RESET}")
    print()
    
    print_step("Connecting to Gmail...")
    creds = get_creds()
    print_success("Connected to Gmail")
    
    # Call the Gmail API
    print_step(f"Checking for new posts (last {args.n} emails)...")
    service = build('gmail', 'v1', credentials=creds)
    messages = service.users().messages()
    
    # Get the list of emails from bingo
    # Apparently no-reply sends them now?
    try:
        matches = messages.list(userId='me', q='from: bingo@patreon.com').execute()['messages'][:args.n]
        matches += messages.list(userId='me', q='from: no-reply@patreon.com').execute()['messages'][:args.n]
        print_success(f"Found {len(matches)} emails to process")
    except Exception as e:
        print_error(f"Failed to fetch emails: {e}")
        return
    
    if not matches:
        print_info("No new emails found")
        return
    
    print()
    
    # Only the most recent emails
    n_new = 0
    for i, match in enumerate(matches, 1):
        print(f"{Colors.BOLD}[{i}/{len(matches)}]{Colors.RESET}")
        
        # Ask for the full email
        mail = messages.get(id=match['id'], userId='me').execute()
        res = download_and_save(mail)
        n_new += 1 if res else 0
        print()
    
    # Summary
    print(f"{Colors.BOLD}{'─' * 40}{Colors.RESET}")
    if n_new > 0:
        print_success(f"Downloaded {colored(str(n_new), Colors.BOLD)} new post(s)")
    else:
        print_info("No new posts downloaded (all already exist)")
    print()
    
    # the only print statement in our program, for other scripts to consume :p
    print(n_new)

if __name__ == '__main__':
    f = Path(__file__).absolute()
    os.chdir(f.parent)
    main()
