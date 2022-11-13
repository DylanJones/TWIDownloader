import os
from bs4 import BeautifulSoup
import base64
import re
import requests
import argparse

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_creds():
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return creds


def parse_email(json):
    """
    """
    # Decode b64 to utf8 text
    html = base64.urlsafe_b64decode(json['payload']['parts'][1]['body']['data']).decode('utf8')
    # Parse
    html = BeautifulSoup(html, features='lxml')

    # Find the one with "password" in it
    pw_tag = html.find(string=re.compile('Password:'))

    # Return early if there's no password in the post
    if pw_tag is None:
        return

    # Check if the password got lumped in with this tag; if so, extract it now
    if match := re.search(r'Password: ([^ ]+)', pw_tag.text):
        password = match.group(1)
    else:
        # Password wasn't in this tag, assume it's the text of the next one
        password = pw_tag.next.text

    # Extract post link
    link = html.find_all('a', string=re.compile('https://wanderinginn.com'))[0].text

    return link, password


def make_request(url, password):
    """
    """
    sess = requests.session()
    # Submit password
    sess.post('https://wanderinginn.com/wp-pass.php', data={'post_password': password, 'Submit': 'Enter'})

    # Get response
    return sess.get(url).content.decode('utf8')


def extract_title(html):
    """
    """

    html = BeautifulSoup(html, features='lxml')
    return html.find(class_='entry-title').text.replace('Protected: ', '')


def download_and_save(mail):
    """
    Given the mail json, parse out the password and post URL, make the authenticated
    request, then save it to the disk under the correct filename.
    """

    # Decode and parse html
    try:
        result = parse_email(mail)
        if not result:
            return
        url, password = result
    except:
        print(f"Error parsing mail id {mail['id']} (snippet: {mail['snippet']})")
        import traceback; traceback.print_exc()
        return

    post_content = make_request(url, password)
    title = extract_title(post_content)
    post_path = os.path.join(DOCUMENT_DIR, title + '.html')
    print(f"Saving post {title}...")

    if not os.path.exists(post_path):
        with open(post_path, 'w') as f:
            f.write(post_content)
            return True


def main():
    global matches, match, mail, result, messages, service
    """Shows basic usage of the Gmail API.
    Lists the user's Gmail labels.
    """
    creds = get_creds()

    try:
        # Call the Gmail API
        service = build('gmail', 'v1', credentials=creds)
        messages = service.users().messages()
        # Get the list of emails from bingo
        matches = messages.list(userId='me', q='from: bingo@patreon.com').execute()

        for match in matches['messages']:
        # Ask for the full email
            # mail = messages.get(id=matches['messages'][0]['id'], userId='me').execute()
            mail = messages.get(id=match['id'], userId='me').execute()
            download_and_save(mail)


    except HttpError as error:
        # TODO(developer) - Handle errors from gmail API.
        print(f'An error occurred: {error}')


if __name__ == '__main__':
    main()
