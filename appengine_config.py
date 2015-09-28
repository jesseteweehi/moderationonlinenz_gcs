from google.appengine.api import namespace_manager
from webapp2_extras import sessions
import models as m

def webapp_add_wsgi_middleware(app):
	from google.appengine.ext.appstats import recording
	app = recording.appstats_wsgi_middleware(app)
	return app


def namespace_manager_default_namespace_for_request():
	session = sessions.get_store()
	s = session.get_session()
	name = s.get('school-id')
	if name:
		return name
	else:
		return namespace_manager.google_apps_namespace()
	