"""Ptyhon file for Multi-user blog final Project- Udacity FSWD Nanodegree"""

# Imports:
import os
import re
import random
import hashlib
import hmac
import time
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

"""Secret phrase to make Hashing for secure:
   Would be placed in another modual to keep hidden:"""
secret = 'wouldntuliketoknow'


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


"""Create/Verify Cookies"""


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """Sweet Handlers for makeing datastore calls:"""
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    """Functions for handleing Cookies:
    Cookies expire when browser is closed:"""
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # Create user cookie when logging in:
    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    # Delete user cookie
    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    """Check if user logged in or not and:
    if the cookie matches the hashed value:"""
    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_id = self.read_secure_cookie('user_id')
        self.user = user_id and User.by_id(int(user_id))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    """Main Page Handler:"""
    def get(self):
        # self.write('Hello, Udacity!')
        return self.redirect('/blog')


"""Make salt(random string):"""


def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))


def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)


def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)


def users_key(group='default'):
    return db.Key.from_path('users', group)


class User(db.Model):
    """Class for user info:"""
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, user_id):
        return cls.get_by_id(user_id, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(), name=name, pw_hash=pw_hash, email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


"""Blog Stuff"""


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


class Post(db.Model):
    """Post Model:"""
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    blogger_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    comments = db.IntegerProperty()
    liked = db.ListProperty(int, required=True)
    image = db.StringProperty(required=False)

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=blog_key())

    def render(self, user, permalink):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("post.html", post=self, user=user,
                          blogger=User.by_id(int(self.blogger_id)),
                          permalink=permalink)


class Comment(db.Model):
    """Comment Model:"""
    blogger_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    liked = db.ListProperty(int, required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, pid):
        return Comment.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        self.liked_count = len(self.liked)
        return render_str("comment.html", comment=self, user=user,
                          blogger=User.by_id(int(self.blogger_id),))


class BlogFront(BlogHandler):
    """Blog Front Page:"""
    def get(self):
        posts = Post.all().order('-created')
        if self.user:
            return self.render('front.html', posts=posts, user=self.user,
                               username=self.user.name)
        else:
            return self.render('front.html', posts=posts, user=self.user)


class PostPage(BlogHandler):
    """Post Page:"""
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        comments = Comment.all().filter(
            'post_id =', int(post_id)).order('created')
        return self.render("permalink.html", post=post, comments=comments,
                           username=self.user.name)


class NewPost(BlogHandler):
    """New Post Page(Logged in User):"""
    def get(self):
        if self.user:
            return self.render("newpost.html", username=self.user.name)
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/login')

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            post = Post(parent=blog_key(), subject=subject,
                        content=content, blogger_id=self.user.key().id())
            post.put()
            print post.key().id()
            return self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Subject and Content, Please!"
            return self.render("newpost.html", subject=subject,
                               content=content, error=error)

"""EDITS & Deletes"""


class EditPost(BlogHandler):
    """Edit Post(creater only):"""
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)
            if post is not None:
                if post.blogger_id != self.user.key().id():
                    return self.redirect("/blog")
                return self.render("edit.html", post=post,
                                   username=self.user.name)
            else:
                return self.redirect("/blog")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)
        if post.blogger_id != self.user.key().id():
                return self.redirect("/blog")
        subject = self.request.get('subject')
        content = self.request.get('content')
        if subject and content:
            post.subject = subject
            post.content = content
            post.put()
            return self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "Subject and Content, Please!"
            return self.render("edit.html", post=post, error=error)


class DeletePost(BlogHandler):
    """"Delete Post(creater only):"""
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)
            if post is not None:
                if post.blogger_id != self.user.key().id():
                    return self.redirect("/blog")
                return self.render("delete.html", post=post,
                                   username=self.user.name)
            else:
                return self.redirect("/blog")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)
        if post.blogger_id != self.user.key().id():
                return self.redirect("/blog")
        post.delete()
        return self.redirect('/blog')


class NewComment(BlogHandler):
    """Comment on Post:"""
    def post(self):
        if not self.user:
            return self.redirect('/blog')
        post_id = int(self.request.get('post_id'))
        content = self.request.get('content')
        if post_id and content:
            comment = Comment(parent=blog_key(), post_id=post_id,
                              content=content,
                              blogger_id=self.user.key().id())
            comment.put()
        return self.redirect('/blog/%s' % str(post_id))


class EditComment(BlogHandler):
    """Edit a Post Comment(creater only):"""
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)
            if comment is not None:
                if comment.blogger_id != self.user.key().id():
                    return self.redirect("/blog")
                return self.render("editcomment.html", comment=comment,
                                   username=self.user.name)
            else:
                return self.redirect("/blog")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)
        if comment.blogger_id != self.user.key().id():
                return self.redirect("/blog")
        content = self.request.get('content')
        if content:
            comment.content = content
            comment.put()
            return self.redirect('/blog/%s' % str(comment.post_id))
        else:
            error = "Blog Content Needed, Thank You."
            return self.render("editcomment.html", comment=comment,
                               error=error)


class DeleteComment(BlogHandler):
    """Delete Comment(creater only):"""
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)
            if comment is not None:
                if comment.blogger_id != self.user.key().id():
                    return self.redirect("/blog")
                return self.render("deletecomment.html", comment=comment,
                                   username=self.user.name)
            else:
                return self.redirect("/blog")
        else:
            return self.redirect("/login")

    def post(self):
        if not self.user:
            return self.redirect('/blog')
        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)
        if comment.blogger_id != self.user.key().id():
                return self.redirect("/blog")
        comment.delete()
        return self.redirect('/blog/%s' % str(comment.post_id))


class Like(BlogHandler):
    """Like a Post(not the creater):"""
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id
            user_id = self.user.key().id()
            if user_id != item.blogger_id and user_id not in item.liked:
                item.liked.append(user_id)
                item.put()
            if self.request.get('permalink') == 'True':
                return self.redirect('/blog/%s' % str(post_id))
            else:
                return self.redirect('/blog')
        else:
            return self.redirect("/login")


class Unlike(BlogHandler):
    """Unlike a Post(not the creater):"""
    def get(self):
        if self.user:
            if self.request.get('post_id'):
                item_id = post_id = int(self.request.get('post_id'))
                item = Post.by_id(item_id)
            elif self.request.get('comment_id'):
                item_id = int(self.request.get('comment_id'))
                item = Comment.by_id(item_id)
                post_id = item.post_id

            user_id = self.user.key().id()
            if user_id in item.liked:
                item.liked.remove(user_id)
                item.put()

            if self.request.get('permalink') == 'True':
                return self.redirect('/blog/%s' % str(post_id))
            else:
                return self.redirect('/blog')
        else:
            return self.redirect("/login")

"""Functions for handling regular expressions:"""
USER_RE = re.compile(r"^[a-zA-Z0-9 +]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')


def valid_email(email):
    return not email or EMAIL_RE.match(email)


class Signup(BlogHandler):
    """Signup Handler:"""
    def get(self):
        return self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username, email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            return self.render('signup-form.html', **params)
        else:
            return self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    """Register Handler:"""
    def done(self):
        """make sure the user doesn't already exist"""
        user = User.by_name(self.username)
        if user:
            msg = 'That user already exists.'
            return self.render('signup-form.html', error_username=msg)
        else:
            user = User.register(self.username, self.password, self.email)
            user.put()

            self.login(user)
            return self.redirect('/blog')


class Login(BlogHandler):
    """Login Handler:"""
    def get(self):
        return self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        user = User.login(username, password)
        if user:
            print username
            self.login(user)
            return self.redirect('/blog')
        else:
            msg = 'Invalid login'
            return self.render('login-form.html', error=msg)


class Bloggers(BlogHandler):
    """Show registered users Handler:"""
    def get(self):
        users = db.GqlQuery("select * from User")
        if self.user:
            return self.render('users.html', users=users,
                               username=self.user.name)
        else:
            return self.render('users.html', users=users)


class Logout(BlogHandler):
    """Logout Handler:"""
    def get(self):
        self.logout()
        return self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/delete', DeletePost),
                               ('/blog/edit', EditPost),
                               ('/blog/newcomment', NewComment),
                               ('/blog/editcomment', EditComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/blog/like', Like),
                               ('/blog/unlike', Unlike),
                               ('/login', Login),
                               ('/signup', Register),
                               ('/users', Bloggers),
                               ('/logout', Logout),
                               ],
                              debug=True)
