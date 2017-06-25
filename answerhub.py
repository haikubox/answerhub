import logging
import requests
import json
import urllib3
from urlparse import urlparse
from hashlib import sha256

class AnswerHub:
  """ REST API client for AnswerHub site"""

  API_URL_PATH = '/services/v2'

  def __init__(self, ah_url, ah_user, ah_password):
    """ Create class object

        Arguments:
          ah_url: base URL for AnswerHub site (without API path)
          ah_user: username for basic authentication
          ah_password: password for basic authentication
    """
    self._setup_logging()

    self.base_url = ah_url.strip('/')
    self.api_url = self.base_url + self.API_URL_PATH
    self.log.debug("create session to REST API on '{}' for user '{}'".format(self.api_url, ah_user))
    self.api = self._api_session(self.api_url, ah_user, ah_password)

  def _setup_logging(self):
    """ Inherit whatever logging setup in calling module """
    self.log = logging.getLogger(__name__)
    self.log.addHandler(logging.NullHandler())

  def _api_session(self, url, user, password, cert_verify=False):
    """ Authenticate to REST API

        Arguments:
          url: site base URL (without API path)
          user: username for basic authentication
          password: password for basic authentication
          cert_verify: whether to verify SSL/TLS site certificate; might want to turn this off for self-signed certs
        Returns:
          s: authenticated session
             please mind, before the actual API call is made, we do not know, if authentication was successfull
    """
    # disable HTTPS warnings
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    s = requests.Session()
    s.verify = cert_verify # whether to ignore site certificate
    s.auth = (user, password)

    return s

  def _get_csrf(self):
    """ Obtain and return CSRF token for admin forms

      Returns:
        csrf_token: CSRF string recevied on successful authentication
    """
    if self.csrf_token is None:
      self.ping()
    return self.csrf_token

  def _admin_form(self, url, form_data):
    """ Wrapper to post AnswerHub admin forms, if REST API wouldn't work

      Arguments:
        url: form url
        form_data: form payload to post
      Returns:
        r: response object
    """
    # some REST API functions do not work, some are missing
    # so we will try to exploit admin forms and API
    # this wrapper ensures CSRF token is added to all admin requests
    csrf_token = self._get_csrf()
    form_data.update({'TH_CSRF': csrf_token})
    r = self.api.post(url, data=form_data)
    return r

  def ping(self):
    """ Test connectivity to site after authentication """
    r = self.api.get(self.base_url)
    self.log.debug("ping site: {}".format(r))
    # set CSRD token from Cookies
    self.csrf_token = r.cookies.get('TH_CSRF')
    if self.csrf_token is None:
      self.log.debug("cookies do not have TH_CSRF, it might break admin forms hacks")
    else:
      self.log.debug("obtained TH_CSRF: {}".format(self.csrf_token))

    return r.ok

  def get_user_by_name(self, user_name):
    """ Get user information by username

      Arguments:
        user_name: string representing user name
      Returns:
        ok: True/False - whether request succeeded
        info:  user info in JSON or error details
    """
    url = self.api_url + '/user/getByUsername.json'
    r = self.api.get(url, params={'username': user_name})

    self.log.debug("get user info: {}".format(r.url))

    if r.ok:
      info = r.json()
    else:
      info = "<{} [{}]>".format(r.reason, r.status_code)

    return r.ok, info

  def get_user_email(self, user_name, user_id):
    """ Get user email by name and id
    REST API does not expose email (only hashes), so try admin API instead
    IMPORTANT: DZone can change this API any time without notice

      Arguments:
        user_name: string representing user name
        user_id: id of user in AnswerHub
      Returns:
        ok: True/False - whether request succeeded
        info: email or error details
    """

    url = self.base_url + '/admin/users/allUserslist.json'
    r = self.api.get(url, params={'q': user_name, 'full': 'true'})

    self.log.debug("get user email: {}".format(r.url))

    if r.ok:
      # extract first email for matching user id
      # ['emails']['id'] returned is not INT, but STRING, so need cast during comparison
      info = ''
      for uid, email in r.json()['emails'].iteritems():
        if int(uid) == user_id:
          info = email
          break
    else:
      info = "<{} [{}]>".format(r.reason, r.status_code)

    return r.ok, info

  def deactivate_user(self, user_id):
    """ Deactivate user by id

      Arguments:
        user_id: id of user in AnswerHub
      Returns:
        ok: True/False - whether request succeeded
        info: request details
    """
    url = self.api_url + '/user/{}/deactivateUser.json'.format(user_id)
    r = self.api.put(url)

    self.log.debug("deactivate user: {}".format(r.url))

    info = "<{} [{}]>".format(r.reason, r.status_code)

    return r.ok, info

  def remove_user_from_group(self, user_id, group_id):
    """ Removes user from group

      Arguments:
        user_id: id of user in AnswerHub
        group_id: id of group in AnswerHub
      Returns:
        ok: True/False - whether request succeeded
        info: request details
    """
    url = self.api_url + '/group/{}/remove.json'.format(group_id)
    r = self.api.put(url, params={'users': user_id})

    self.log.debug("remove user from group: {}".format(r.url))

    info = "<{} [{}]>".format(r.reason, r.status_code)

    return r.ok, info

  def update_user_email(self, user_id, email):
    """ Updates user email

      Arguments:
        user_id: id of user in AnswerHub
        email: new email
      Returns:
        ok: True/False - whether request succeeded
        info: request details
    """
    headers = {'Accept': 'application/json', 'Content-type': 'application/json'}
    url = self.api_url + '/user/{}.json'.format(user_id)
    r = self.api.put(url, data={'emailHash': sha256(email).hexdigest()})

    self.log.debug("update user with data [{}]: {}".format(r.request.body, r.url))

    info = "<{} [{}]>".format(r.reason, r.status_code)

    return r.ok, info

  def admin_update_user_email(self, user_id, email, user_name=None):
    """ Updates user email - admin version (non REST API)

      Arguments:
        user_id: id of user in AnswerHub
        email: new email
        user_name: if provided, method will call API to check email again and confirm it was updated
      Returns:
        ok: True/False - whether request succeeded
        info: request details
    """

    url = self.base_url + '/admin/users/view/{}.html'.format(user_id)
    r = self._admin_form(url, {'email': email})

    # due to redirect on form submission, body of redirect will be empty
    # so we need to go deeper...
    body = r.request.body
    if body is None and len(r.history) > 0:
      body = r.history[0].request.body

    self.log.debug("update user with data [{}]: {}".format(body, r.url))

    info = "<{} [{}]>".format(r.reason, r.status_code)

    if r.ok and user_name is not None:
      # looks like request was successful, let's try to verify, if email changed
      status, new_email = self.get_user_email(user_name, user_id)
      if email != new_email:
        r.ok = False
        info = "Email did not change after update"

    return r.ok, info