from __future__ import print_function
from apiclient.discovery import build
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
import logging
import pickle
import os.path
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from apiclient import errors
import json
import time
import base64
from email.parser import Parser
from utils import Logger
import re
from flask import redirect

# If modifying these scopes, delete the file token.pickle.
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


class Email():
    def __init__(self, fr, to, subj, idno):
        self.fr = fr
        self.to = to
        self.subj = subj
        self.idno = idno
        self.urls = []

    def __repr__(self):
        return(f"From: {self.fr}, To: {self.to}, subj: {self.subj}, id: {self.idno}")


# ...


# Path to client_secrets.json which should contain a JSON document such as:
#   {
#     "web": {
#       "client_id": "[[YOUR_CLIENT_ID]]",
#       "client_secret": "[[YOUR_CLIENT_SECRET]]",
#       "redirect_uris": [],
#       "auth_uri": "https://accounts.google.com/o/oauth2/auth",
#       "token_uri": "https://accounts.google.com/o/oauth2/token"
#     }
#   }
CLIENTSECRETS_LOCATION = './client_secrets.json'
REDIRECT_URI = 'http://localhost:8000/'
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    # Add other requested scopes.
]


class GetCredentialsException(Exception):
    """Error raised when an error occurred while retrieving credentials.

    Attributes:
      authorization_url: Authorization URL to redirect the user to in order to
                         request offline access.
    """

    def __init__(self, authorization_url):
        """Construct a GetCredentialsException."""
        self.authorization_url = authorization_url


class CodeExchangeException(GetCredentialsException):
    """Error raised when a code exchange has failed."""


class NoRefreshTokenException(GetCredentialsException):
    """Error raised when no refresh token has been found."""


class NoUserIdException(Exception):
    """Error raised when no user ID could be retrieved."""


def get_stored_credentials(user_id):
    """Retrieved stored credentials for the provided user ID.

    Args:
      user_id: User's ID.
    Returns:
      Stored oauth2client.client.OAuth2Credentials if found, None otherwise.
    Raises:
      NotImplemented: This function has not been implemented.
    """
    # TODO: Implement this function to work with your database.
    #       To instantiate an OAuth2Credentials instance from a Json
    #       representation, use the oauth2client.client.Credentials.new_from_json
    #       class method.
    raise NotImplementedError()


def store_credentials(user_id, credentials):
    """Store OAuth 2.0 credentials in the application's database.

    This function stores the provided OAuth 2.0 credentials using the user ID as
    key.

    Args:
      user_id: User's ID.
      credentials: OAuth 2.0 credentials to store.
    Raises:
      NotImplemented: This function has not been implemented.
    """
    # TODO: Implement this function to work with your database.
    #       To retrieve a Json representation of the credentials instance, call the
    #       credentials.to_json() method.
    raise NotImplementedError()


def exchange_code(authorization_code):
    """Exchange an authorization code for OAuth 2.0 credentials.

    Args:
      authorization_code: Authorization code to exchange for OAuth 2.0
                          credentials.
    Returns:
      oauth2client.client.OAuth2Credentials instance.
    Raises:
      CodeExchangeException: an error occurred.
    """
    flow = flow_from_clientsecrets(CLIENTSECRETS_LOCATION, ' '.join(SCOPES))
    flow.redirect_uri = REDIRECT_URI
    try:
        credentials = flow.step2_exchange(authorization_code)
        return credentials
    except FlowExchangeError as error:
        logging.error('An error occurred: %s', error)
        raise CodeExchangeException(None)


def get_user_info(credentials):
    """Send a request to the UserInfo API to retrieve the user's information.

    Args:
      credentials: oauth2client.client.OAuth2Credentials instance to authorize the
                   request.
    Returns:
      User information as a dict.
    """
    user_info_service = build(
        serviceName='oauth2', version='v2',
        http=credentials.authorize(httplib2.Http()))
    user_info = None
    try:
        user_info = user_info_service.userinfo().get().execute()
    except errors.HttpError as e:
        logging.error('An error occurred: %s', e)
    if user_info and user_info.get('id'):
        return user_info
    else:
        raise NoUserIdException()


def get_authorization_url(email_address, state):
    """Retrieve the authorization URL.

    Args:
      email_address: User's e-mail address.
      state: State for the authorization URL.
    Returns:
      Authorization URL to redirect the user to.
    """
    flow = flow_from_clientsecrets(CLIENTSECRETS_LOCATION, ' '.join(SCOPES))
    flow.params['access_type'] = 'offline'
    flow.params['approval_prompt'] = 'force'
    flow.params['user_id'] = email_address
    flow.params['state'] = state
    return flow.step1_get_authorize_url(REDIRECT_URI)


def get_credentials(authorization_code, state):
    """Retrieve credentials using the provided authorization code.

    This function exchanges the authorization code for an access token and queries
    the UserInfo API to retrieve the user's e-mail address.
    If a refresh token has been retrieved along with an access token, it is stored
    in the application database using the user's e-mail address as key.
    If no refresh token has been retrieved, the function checks in the application
    database for one and returns it if found or raises a NoRefreshTokenException
    with the authorization URL to redirect the user to.

    Args:
      authorization_code: Authorization code to use to retrieve an access token.
      state: State to set to the authorization URL in case of error.
    Returns:
      oauth2client.client.OAuth2Credentials instance containing an access and
      refresh token.
    Raises:
      CodeExchangeError: Could not exchange the authorization code.
      NoRefreshTokenException: No refresh token could be retrieved from the
                               available sources.
    """
    email_address = ''
    try:
        credentials = exchange_code(authorization_code)
        user_info = get_user_info(credentials)
        email_address = user_info.get('email')
        user_id = user_info.get('id')
        if credentials.refresh_token is not None:
            store_credentials(user_id, credentials)
            return credentials
        else:
            credentials = get_stored_credentials(user_id)
            if credentials and credentials.refresh_token is not None:
                return credentials
    except CodeExchangeException as error:
        logging.error('An error occurred during code exchange.')
        # Drive apps should try to retrieve the user and credentials for the current
        # session.
        # If none is available, redirect the user to the authorization URL.
        error.authorization_url = get_authorization_url(email_address, state)
        raise error
    except NoUserIdException:
        logging.error('No user ID could be retrieved.')
    # No refresh token has been retrieved.
    authorization_url = get_authorization_url(email_address, state)
    raise NoRefreshTokenException(authorization_url)


class GmailScraper():

    def __init__(self):
        self.service = None
        self.logger = Logger("Email Scraper")
        self.message_ids = []
        self.emails = []

    def login(self):
        creds = None
        # The file token.pickle stores the user's access and refresh tokens, and is
        # created automatically when the authorization flow completes for the first
        # time.
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)
        # If there are no (valid) credentials available, let the user log in.
        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(
                    'credentials.json', SCOPES)
                creds = flow.run_local_server(port=0)
            # Save the credentials for the next run
            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

        self.service = build('gmail', 'v1', credentials=creds)

    def startScraping(self):
        self.login()
        self.message_ids = []
        self.emails = []
        senderemail = input(
            "Please enter the sender's full email to search for ")
        numdays = int(
            input("Please enter the integer number of days passed to search through "))
        delay = int(
            input("Please enter the integer number of seconds to delay scrapes "))
        print(
            f"This program will search for emails from {senderemail} from the past {numdays} days and continue to scan for new emails every {delay} seconds")
        input("Press Enter to continue...")

        while True:
            try:
                # Call the Gmail API
                self.logger.info("Checking...")

                # Get ID's of all emails matching the query string q
                results = self.service.users().messages().list(
                    userId='me', q=f"from:{senderemail} newer_than:{numdays}d").execute()

                # Try to get all id's into a list, if we cant, then there arent any emails.
                try:
                    new_ids = list(
                        map(lambda msg: msg['id'], results['messages']))
                except KeyError:
                    print("No messages found")
                    new_ids = []

                # Loop through each id number in the new_ids list
                for id_no in new_ids:

                    # if the current id is not in the list of collected ids then we found a new one
                    if id_no not in self.message_ids:
                        self.logger.success("New Email Found!")

                        # Add the new id to list of found ID's
                        self.message_ids.append(id_no)

                        # use the message id to get the actual message, including any attachments
                        # using raw format returns a consistent dict with a dict with a "raw" key which contains the entire email content
                        # the value corresponding to the raw key is encoded in b64
                        message = self.service.users().messages().get(
                            userId='me', id=id_no, format="raw").execute()

                        # decode b64 to get a byte string
                        msg_bytes = base64.urlsafe_b64decode(message["raw"])

                        # decode bytes to utf-8
                        msg_str = msg_bytes.decode("utf-8")

                        # Parse the utf-8 string with the email parser NOTE: maybe a better way to do this instead of decoding twice...
                        headers = Parser().parsestr(msg_str)

                        # Use Regex to find urls
                        resulturls = re.findall(
                            'http[s]?://(?:[a-zA-Z]|[0-9]|[/@.&+]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(msg_str))

                        # instantiate email object
                        newemail = Email(
                            headers['from'], headers['to'], headers['subject'], id_no)

                        print()
                        print(f"To: {headers['to']}")
                        print(f"From: {headers['from']}")
                        print(f"Subject: {headers['subject']}")
                        print(f"emailID: {id_no}")

                        # add urls to the newemail object
                        for result in resulturls:
                            newemail.urls.append(result)
                            print(f"URL found {result}")

                        # Store the email in the object.
                        self.emails.append(newemail)

                # Wait the specified time, IDK what the ratelimit is for Google's api but just to be safe...
                time.sleep(delay)
            except KeyboardInterrupt:
                print(f"Keyboard interrupt used. Emails found: {self.emails}")
                return


def main():
    scraper = GmailScraper()
    scraper.startScraping()


if __name__ == '__main__':
    main()
