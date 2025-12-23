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

log = logging.getLogger("downloader")
log.addHandler(logging.StreamHandler())
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
        log.debug("Failed to find password tag in email!")
        log.debug("assuming post has no password...")
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

        log.debug(f"Password found: {repr(password)}")

    # Extract post link(s)
    links = [x.text for x in html.find_all('a', string=re.compile('https://wanderinginn.com'))]
    log.debug("Post link(s) found: %s", links)

    return links, password


def make_request(url, password):
    """
    """
    sess = requests.session()
    sess.headers.update({'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0'})
    # Submit password
    response = sess.post('https://wanderinginn.com/wp-login.php?action=postpass&wpe-login=true', data={'post_password': password, 'Submit': 'Submit'})

    # Get response
    response = sess.get(url)
    if response.status_code != 200:
        log.debug(sess.headers)
        raise RuntimeError(f"error: got response code {response.status_code}, check password extraction and auth logic")
    return response.content.decode('utf8')


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
            log.info("no links found in this email, returning")
            return
        urls, password = result
    except:
        log.error(f"Error parsing mail id {mail['id']} (snippet: {mail['snippet']})")
        import traceback; traceback.print_exc()
        return

    new_file = False
    for url in urls:
        log.debug(f"post url: {url}...")
        post_content = make_request(url, password)
        with open('tmp.html', 'w') as f:
            f.write(post_content)
        title = extract_title(post_content)
        post_path = DOCUMENT_DIR / (title + '.html')
        log.info(f"Saving post {title}...")

        if not os.path.exists(post_path):
            new_file = True
            with open(post_path, 'w') as f:
                f.write(post_content)
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

    creds = get_creds()

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # Call the Gmail API
    service = build('gmail', 'v1', credentials=creds)
    messages = service.users().messages()
    # Get the list of emails from bingo
    # Apparently no-reply sends them now?
    matches = messages.list(userId='me', q='from: bingo@patreon.com').execute()['messages'][:args.n]
    matches += messages.list(userId='me', q='from: no-reply@patreon.com').execute()['messages'][:args.n]

    # Only the most recent 3 emails
    n_new = 0
    for match in matches:
        # Ask for the full email
        mail = messages.get(id=match['id'], userId='me').execute()
        res = download_and_save(mail)
        n_new += 1 if res else 0
    # the only print statement in our program, for other scripts to consume :p
    print(n_new)


if __name__ == '__main__':
    f = Path(__file__).absolute()
    os.chdir(f.parent)
    main()

