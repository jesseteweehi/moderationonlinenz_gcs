import re
import random
import hashlib
import hmac
from string import letters
from google.appengine.ext import ndb
from google.appengine.api import memcache

class AllSchools(ndb.Model):
	schools = ndb.StringProperty(repeated=True)

class MetaSchool(ndb.Model):
	"""School entity to use as ancestor"""
	name = ndb.StringProperty(required = True)
	idnumber = ndb.StringProperty(required = True)
	date = ndb.DateTimeProperty(auto_now_add=True)

	@classmethod
	def get_key(cls,s):
		u = MetaSchool.query().filter(MetaSchool.idnumber == s).get()
		return u.key

class CritiqueModel(ndb.Model):
	name = ndb.StringProperty(indexed=False)
	school = ndb.StringProperty(indexed=False)
	materials = ndb.StringProperty(indexed=False)
	check1 = ndb.BooleanProperty(indexed=False)
	check2 = ndb.BooleanProperty(indexed=False)
	check3 = ndb.BooleanProperty(indexed=False)
	check4 = ndb.BooleanProperty(indexed=False)
	check5 = ndb.BooleanProperty(indexed=False)
	check6 = ndb.BooleanProperty(indexed=False)
	check7 = ndb.BooleanProperty(indexed=False)
	check8 = ndb.BooleanProperty(indexed=False)
	check9 = ndb.BooleanProperty(indexed=False)

	critique_standard = ndb.KeyProperty()

	finished = ndb.BooleanProperty(indexed=False)

	created = ndb.DateTimeProperty(auto_now_add=True)
	modified = ndb.DateTimeProperty(auto_now=True)

class SampleandReviewModel(ndb.Model):
	name = ndb.StringProperty(indexed=False)
	school = ndb.StringProperty(indexed=False)
	check1 = ndb.BooleanProperty(indexed=False)
	check2 = ndb.BooleanProperty(indexed=False)
	check3 = ndb.BooleanProperty(indexed=False)
	check4 = ndb.BooleanProperty(indexed=False)
	check5 = ndb.BooleanProperty(indexed=False)

	samples_url = ndb.StringProperty(indexed=False)
	samples_other = ndb.StringProperty(indexed=False)

	location_url = ndb.StringProperty(indexed=False)
	location_other = ndb.StringProperty(indexed=False)

	sample_standard = ndb.KeyProperty()

	finished = ndb.BooleanProperty(indexed=False)

	created = ndb.DateTimeProperty(auto_now_add=True)
	modified = ndb.DateTimeProperty(auto_now=True)

class VerificationModel(ndb.Model):
	student = ndb.StringProperty(indexed=False)

	verifier_name = ndb.StringProperty(indexed=False)
	verifier_school = ndb.StringProperty(indexed=False)
	verification_other_school = ndb.BooleanProperty(indexed=False)
	verifiers_grade = ndb.StringProperty(indexed=False)

	markers_grade = ndb.StringProperty(indexed=False)
	reported_grade = ndb.StringProperty(indexed=False)

	difference_grade = ndb.ComputedProperty(lambda self: self.check_difference(self.markers_grade,self.verifiers_grade))

	tic = ndb.StringProperty(indexed=False)

	discussion = ndb.TextProperty()

	verification_standard = ndb.KeyProperty()

	finished = ndb.BooleanProperty(indexed=False)

	created = ndb.DateTimeProperty(auto_now_add=True)
	modified = ndb.DateTimeProperty(auto_now=True)

	@staticmethod
	def check_difference(marker,verifier):
		if not marker or marker is 'No Grade':
			return False
		else:
			if marker != verifier:
				return True

##### user stuff
def make_salt(length = 5):
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	"""
	Makes a hash containing name, pw and salt.
	returns salt and hash
	"""
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	"""
	Returns pw_hash, splits hash and salt and confirms that the name, password and salt when hashed equals the pw_hash.
	"""
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

class User(ndb.Model):
	school = ndb.StringProperty(required = True)
	pw_hash = ndb.StringProperty(required = True)
	outside_hash = ndb.StringProperty()
	admin = ndb.StringProperty(repeated=True)
	pleb = ndb.StringProperty(repeated=True)


	@classmethod
	def by_id(cls, uid, p):
		parent = MetaSchool.get_key(p)
		return User.get_by_id(uid, parent=parent)

	@classmethod
	def by_name(cls, s):
		u = User.query().filter(User.school == s).get()
		return u

	@classmethod
	def by_code(cls, code):
		u = User.query().filter(User.outside_hash == code)
   
	@staticmethod
	def update(name, pw):
		pw_hash = make_pw_hash(name, pw)
		return pw_hash

	@classmethod
	def register(cls, name, pw):
		pw_hash = make_pw_hash(name, pw)
		return User(parent = MetaSchool.get_key(name[-4:]),
					school = name,
					pw_hash = pw_hash,)

	@classmethod
	def login(cls, s, pw):
		u = cls.by_name(s)
		if u and valid_pw(s, pw, u.pw_hash):
			return u

	@classmethod
	def check_code(cls, name, code):
		u = cls.by_name(name)
		if u and valid_pw(name, code, u.outside_hash):
			return u


def check_before(l,before,cursor):
	if cursor == 0:
		return None
	else:
		if not before:
			return check_before(l,l[cursor-1],cursor-1)
		else:
			return before


def check_after(l,after,cursor):
	if cursor == len(l)-1:
		return None
	else:
		if not after:
			return check_after(l,l[cursor+1],cursor+1)
		else:
			return after

def before_after(n):
	before = n - 1
	after = n + 1
	return before,after


def cursor_find(l,cursor):
	if len(l) > 2:
		cursor_num = l.index(cursor)
		if cursor_num == 0:
			return None, l[cursor_num + 1]
		elif cursor_num == len(l)-1:
			return l[cursor_num-1], None
		else:
			before, after = before_after(cursor_num)
		if l[before] and l[after]:
			return l[before], l[after]
		if not l[before] and not l[after]:
			return check_before(l,l[before],cursor_num), check_after(l,l[after], cursor_num)
		if not l[before]:
			return check_before(l,l[before],cursor_num), l[after]
		if not l[after]:	
			return l[before], check_after(l,l[after],cursor_num)
	else:
		before = None
		after = None
		return before,after

class Standard(ndb.Model):
	
	year = ndb.StringProperty()

	standard_type = ndb.StringProperty()

	subject_id = ndb.StringProperty()
	subject_title = ndb.StringProperty()

	standard_no = ndb.StringProperty()
	version = ndb.StringProperty(indexed=False)
	level = ndb.StringProperty()
	credits = ndb.IntegerProperty(indexed=False)
	title = ndb.TextProperty(indexed=False)

	critique_key = ndb.KeyProperty()
	critique_started = ndb.BooleanProperty(default=False)
	critique_finished = ndb.BooleanProperty(default=False)
	critique_email = ndb.StringProperty()

	sample_key = ndb.KeyProperty()
	sample_started = ndb.BooleanProperty(default=False)
	sample_finished = ndb.BooleanProperty(default=False)
	sample_email = ndb.StringProperty()

	verification_key = ndb.KeyProperty(repeated=True)
	verification_finished = ndb.ComputedProperty(lambda self: len(self.verification_key))
	verification_difference = ndb.ComputedProperty(lambda self: self.detect_difference(self.verification_key))
	verification_other_school = ndb.ComputedProperty(lambda self: self.other_school(self.verification_key))
	verification_total = ndb.IntegerProperty(default=0)

	tic = ndb.StringProperty()

	@classmethod
	def standard_shuffle(self, key):
		keys_list = self.get_default_filter()
		if key in keys_list:
			before, after = cursor_find(keys_list,key)
		else:
			before = None
			after = None
		return before, after

	@staticmethod
	def other_school(l):
		verification_list = ndb.get_multi(l)
		n = 0
		for child in verification_list:
			if child.verification_other_school:
				n = n + 1
		return n

	@staticmethod
	def detect_difference(l):
		verification_list = ndb.get_multi(l)
		full = []
		for child in verification_list:
			if child.difference_grade:
				full.append(child)
		return len(full)

	@classmethod
	def default_filter(self):
		full = []
		standards=Standard.query()		
		standards = standards.order(Standard.subject_title)
		standards = standards.order(Standard.subject_id)
		standards = standards.order(Standard.standard_no)
		for child in standards:
			full.append(child.key)
		return full

	@classmethod
	def get_default_filter(self):
		data = memcache.get('standard_shuffle')
		if data is not None:
			return data
		else:
			data = self.default_filter()
			memcache.add('standard_shuffle', data, 300)
			return data

	@classmethod
	def reset_standard_shuffle(self):
		data = self.default_filter()
		memcache.set('standard_shuffle', data, 300)
				
	@classmethod
	def default_filter_page(self, cursor):
		standards=Standard.query()		
		standards = standards.order(Standard.subject_title)
		standards = standards.order(Standard.subject_id)
		standards = standards.order(Standard.standard_no)
		results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
		return results, new_cursor, more


	@classmethod
	def default_order_by_critique(self,cursor):
		standards=Standard.query()
		standards = standards.order(Standard.critique_finished)
		standards = standards.order(Standard.subject_title)
		standards = standards.order(Standard.subject_id)	
		standards = standards.order(Standard.standard_no)
		results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
		return results, new_cursor, more


	@classmethod
	def default_order_by_sample(self,cursor):
		standards=Standard.query()
		standards = standards.order(Standard.sample_finished)
		standards = standards.order(Standard.subject_title)
		standards = standards.order(Standard.subject_id)	
		standards = standards.order(Standard.standard_no)
		results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
		return results, new_cursor, more

	@classmethod
	def default_order_by_verification_finished(self,cursor):
		standards=Standard.query()
		standards = standards.order(Standard.verification_finished)
		standards = standards.order(Standard.subject_title)
		standards = standards.order(Standard.subject_id)	
		standards = standards.order(Standard.standard_no)
		results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
		return results, new_cursor, more

	@classmethod
	def subject_order(self,var1,var2,cursor):
		standards = Standard.query()
		standards = standards.filter(Standard.subject_title==var1)
		if var2 == 'critique_finished':
			standards = standards.order(Standard.critique_finished)
			standards = standards.order(Standard.subject_title)
			standards = standards.order(Standard.subject_id)	
			standards = standards.order(Standard.standard_no)
			results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
			return results, new_cursor, more
		if var2 == 'sample_finished':
			standards = standards.order(Standard.sample_finished)
			standards = standards.order(Standard.subject_title)
			standards = standards.order(Standard.subject_id)	
			standards = standards.order(Standard.standard_no)
			results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
			return results, new_cursor, more
		if var2 == 'verification_finished':
			standards = standards.order(Standard.verification_finished)
			standards = standards.order(Standard.subject_title)
			standards = standards.order(Standard.subject_id)	
			standards = standards.order(Standard.standard_no)
			results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
			return results, new_cursor, more
		if var2 =="A":
			standards = standards.order(Standard.subject_title)	
			standards = standards.order(Standard.subject_id)
			standards = standards.order(Standard.standard_no)
			results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
			return results, new_cursor, more
		else:
			results, new_cursor, more = standards.fetch_page(100, start_cursor=cursor)
			return results, new_cursor, more


	@classmethod
	def subject_list(self):
		full= []
		standards = Standard.query()
		for result in standards:
			if result.subject_title not in full:
				full.append(result.subject_title)
		return sorted(full)


	@classmethod
	def get_subject_list(self):
		data = memcache.get('subject_list')
		if data is not None:
			return data
		else:
			data = self.subject_list()
			memcache.add('subject_list', data, 60)
			return data

	@classmethod
	def reset_subject_list(self):
		data = self.subject_list()
		memcache.set('subject_list', data, 60)
		return data


class Staff(ndb.Model):
	year = ndb.StringProperty()
	staff_id = ndb.StringProperty()
	last_name = ndb.StringProperty()
	first_name = ndb.StringProperty()
	title = ndb.StringProperty()
	subject = ndb.StringProperty()
	email = ndb.StringProperty()


	@classmethod
	def get_staff_list(self):
		staff = Staff.query()
		staff = staff.order(Staff.subject)
		staff = staff.order(Staff.last_name)
		return staff











