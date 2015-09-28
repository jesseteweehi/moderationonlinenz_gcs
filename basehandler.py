import webapp2
from webapp2_extras import sessions
from google.appengine.api import users

import os
import jinja2
import models as m

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class Handler(webapp2.RequestHandler):
    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)

        try:
            # Dispatch the request.
            webapp2.RequestHandler.dispatch(self)
        finally:
            # Save all sessions.
            self.session_store.save_sessions(self.response)
   
    @webapp2.cached_property
    def session(self):
        # Returns a session using the default cookie key.
        return self.session_store.get_session()

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)
        
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    @property
    def user(self):
        return users.get_current_user()
    
    @property
    def loginurl(self,url):
        return self.redirect(users.create_login_url(url))

    def ancestor(self):
        return m.models.MetaSchool.get_key(self.session.get('school-id'))

    def check_u(self):
        try:
            uid = self.session.get('user')
            parent = self.session.get('school-id')
            udl = m.models.User.by_id(int(uid),parent)
            if uid and udl:
                return udl
            else:
                return False
        except (TypeError,AttributeError):
            return False

    def checkout(self):
        self.session.clear()
