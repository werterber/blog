#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import logging

import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import images

import utils

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

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

class MainPage(Handler):
    def get(self):
        self.render('uvodni_strana.html')

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = utils.make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and utils.valid_pw(name, pw, u.pw_hash):
            return u

class Signup(Handler):
    def get(self):
        self.send_form("signup-form.html")

    def post(self):
        have_error = False
        if not self.valid_form():
            have_error = True


        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not utils.valid_username(self.username):
            params['error_username'] = u"Neplatné uživatelské jméno."
            have_error = True

        if not utils.valid_password(self.password):
            params['error_password'] = u"Neplatné uživatelské heslo."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = u"Hesla se neshodují."
            have_error = True

        if not utils.valid_email(self.email):
            params['error_email'] = u"Toto není platná emailová adresa."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = u'Tento uživatel už existuje.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/vitejte')

class Login(Handler):
    def get(self):
        self.send_form('login-form.html')

    def post(self):
        if self.valid_form():
            username = self.request.get('username')
            password = self.request.get('password')

            u = User.login(username, password)
            if u:
                self.login(u)
                self.redirect('/vitejte')
            else:
                msg = u'Neplatné přihlašovací údaje.'
                self.render('login-form.html', error = msg)
        else:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.write('Not matching tokens')

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class ChangePassword(Handler):
    def get(self):
        if self.user:
            self.render('changePassword.html', username = self.user.name)
        else:
            self.redirect('/prihlaseni')

    def post(self):
        oldPassword = self.request.get('oldPassword')
        newPassword = self.request.get('newPassword')
        verifyPassword = self.request.get('verifyPassword')

        u = self.user

        if User.login(self.user.name, oldPassword):
            if newPassword == verifyPassword:
                u.pw_hash = utils.make_pw_hash(self.user.name, newPassword)
                u.put()
                self.redirect('/vitejte')
            else:
                self.response.headers['Content-Type'] = 'text/plain'
                self.response.write('Hesla se neshodují.')
        else:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.write('Not logged')
        

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username = self.user.name)
        else:
            self.redirect('/signup')
 
class Piece(db.Model):
    author = db.StringProperty()
    name = db.StringProperty()
    photo = db.BlobProperty()
    measurements = db.StringProperty()
    material = db.StringProperty()
    crafted = db.IntegerProperty()
    date = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_name(cls, name):
        p = Piece.all().filter('name =', name).get()
        return p

    def render(self):
        return render_str("piece.html", p = self)

class Image(webapp2.RequestHandler):
    def get(self):
        Piece_key = db.Key(self.request.get('img_id'))
        piece = db.get(Piece_key)
        if piece.photo:
            self.response.headers['Content-Type'] = 'image/png'
            self.response.out.write(piece.photo)
        else:
            self.response.out.write('Není obrázek.')

class Galery(Handler):
    def get(self):
        #arts = Piece.all().fetch(10)
        arts = db.GqlQuery("SELECT * FROM Piece ORDER BY date DESC LIMIT 35")
        arts = list(arts)
        if not arts:
            self.write("Galerie je prázdná.")
        else:
            self.render("Galery.html", arts = arts)

class newPiece(Handler):
    def get(self):
        if self.user.name == "Jiri":
            self.send_form("piece-form.html")
        else:
            self.redirect("/prihlaseni")

    def post(self):
        if not self.user:
            self.redirect("/galerie")

        if self.valid_form():
            piece = Piece()
            piece.author = self.user.name
            piece.name = self.request.get("name")
            piece.measurements = self.request.get("measurements")
            piece.material = self.request.get("material")
            piece.crafted = int(self.request.get("crafted"))
            photo = self.request.get('img')
            piece.photo = images.resize(photo, 500, 500)

            if piece.photo and piece.name:
                piece.put()
                self.redirect('/piece%s' % str(piece.key().id()))
            else:
                self.response.out.write(
                    'Něco se pokazilo.')
        else:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.write('Not matching tokens')

class PostPiece(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Piece', int(post_id))
        piece = db.get(key)

        if not piece:
            self.error(404)
            return

        self.render("permalink.html", piece = piece)

class SearchtheDatabase(Handler):
    def get(self):
        if self.user:
            name = self.request.get('name')
            result = Piece.by_name(name)
            self.render("search-database.html", name=name, result=result)
        else:
            self.redirect('/prihlaseni')

class ListPieces(Handler):
    def get(self):
        results = list(db.GqlQuery("SELECT* FROM Piece"))
        self.render("list-database.html", results = results)

class EditPiece(Handler):
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Piece', int(post_id))
            piece = db.get(key)
            self.send_form("edit-piece.html", piece = piece)

    def post(self, post_id):
        if self.valid_form() and self.user:
            key = db.Key.from_path('Piece', int(post_id))
            piece = db.get(key)
            piece.author = self.user.name
            piece.name = self.request.get("name")
            piece.measurements = self.request.get("measurements")
            piece.material = self.request.get("material")
            piece.crafted = int(self.request.get("crafted"))
            
            if piece.photo and piece.name:
                piece.put()
                self.redirect('/piece%s' % str(piece.key().id()))
            else:
                self.response.out.write(
                    'Něco se pokazilo.')
        else:
            self.response.headers['Content-Type'] = 'text/plain'
            self.response.write('Not matching tokens or login')

app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/signup', Register),
    ('/vitejte', Welcome),
    ('/prihlaseni', Login),
    ('/odhlaseni', Logout),
    ('/password-change', ChangePassword),
    #Images and Galery stuff
    ('/img', Image),
    ('/galerie', Galery),
    ('/novaSocha', newPiece),
    ('/piece([0-9]+)', PostPiece),
    ('/hledat', SearchtheDatabase),
    ('/seznam', ListPieces),
    ('/edit-piece([0-9]+)', EditPiece)

], debug=True)
