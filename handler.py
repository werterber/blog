import webapp2
from templates import render_str
import utils
from user import User

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)
    
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = utils.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and utils.check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def send_form(self, template, **kw):
        """protection against CSFR attack"""
        kw['token'] = utils.make_token()
        self.response.headers.add_header('Set-Cookie',
            'token=%s; Path=/' % kw['token'])
        self.render(template, **kw)

    def valid_form(self):
        """protection against CSFR attack"""
        token_cookie = self.request.cookies.get('token')
        token_form = self.request.get('token')
        return token_form == token_cookie

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))