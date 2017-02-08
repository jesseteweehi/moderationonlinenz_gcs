import os
import re
import json
from models import models as m
import webapp2
from google.appengine.api import users
from basehandler import Handler
from data import parse as p
from formswt import AdminStandardCreate, StaffToUsersForm
from google.appengine.api import namespace_manager
import cloudstorage as gcs


"""
Things needed to be created: BULK upload.
1) COMPLETED - Standard Upload, also need to be able to identify if standard, subject, area, version combination has already be uploaded and if so: what to do. Total student entries update 
2) COMPLETED - Staff Upload, check staff_id for year if already in use then don't upload.
3) Users email upload - Upload email csv as users for website.

"""
def check_email(email):
	"""CHECK"""
	return re.match(r'[^@]+@[^@]+\.[^@]+', email)

def open_cloudstorage_file(filename):
	bucket ='/files-moderationonlinenz/'+filename
	gcs_file = gcs.open(bucket)
	return gcs_file


def create_select(l):
	"""
	Configure list from csv,
	"""
	full = list()
	for child in l:
		val = (child[0],child[0]+' - '+child[2]+' '+child[1])
		if val not in full:
			full.append(val)
	return full


def create_level(s):
	"""
	May throw up error as hasn't been checked
	"""
	if s[-1:] == '6' or '11' in s or s[-1:] == '1':
		return '1'
	if s[-1:] == '7' or '12' in s or s[-1:] == '2':
		return '2'
	if s[-1:] == '8' or '13' in s or s[-1:] == '3':
		return '3'
	else: 
		return 'Multi'


def check_digit(s):
	if s.isdigit():
		return s
	else:
		return '0'

def create_standards_model(l):
	"""
	standards_no
	version
	level
	credits
	title
	"""
	full=[]
	for child in l:
		if child[4] != 'External':
			standard_data = child[0].split(' ')

			if standard_data[0][0:1] == 'A':
				standard_type = 'Achievement Standard'
			else:
				standard_type = 'Unit Standard'

			standard = standard_data[1]
			version = standard_data[-1][1:]

			credits = child[1].split('.')[0]
			title = child[2]
			subject_title = child[-2]
			subject_id = child[-3]
			level = create_level(subject_id)
			student_totals = check_digit(child[-1])

			sub_list = [standard_type,subject_id,subject_title,standard,version,level,credits,title,student_totals]

			full.append(sub_list)
	return full

def update_standards_model(l,q,year):
	"""
	Create a list of current standard.

	Iterate through new list check versus current. if not in currrent list, add new var to current standard list.
	"""
	full = []
	current_standards = m.Standard.query(ancestor=q)
	current_standards = current_standards.filter(m.Standard.year == year)
	for current_standard in current_standards:
		current_standard_compare = (current_standard.subject_id,current_standard.standard_no,current_standard.version)
		full.append(current_standard_compare)

	for new_standard in l:
		new_standard_compare = (new_standard[1],new_standard[3],new_standard[4])
		if new_standard_compare not in full:
			standard = m.Standard(parent=q,
								year=year,
								standard_type = new_standard[0],
								subject_id = new_standard[1],
								subject_title=new_standard[2],
								standard_no = new_standard[3],
								version = new_standard[4],
								level = new_standard[5],
								credits = int(new_standard[6]),
								title = new_standard[7], 
								verification_total = int(new_standard[8]),
								
								critique_started=False,
								critique_finished=False,
								critique_email='',

								sample_started=False,
								sample_finished=False,
								sample_email='',	
								)
			standard.put()

def create_staff(l,year,q):
	full = []
	current_staff = m.Staff.query(ancestor=q)
	current_staff = current_staff.filter(m.Staff.year == year)
	for current_member in current_staff:
		full.append(current_member.staff_id)

	for new_member in l:
		if check_email(new_member[5]) and new_member[0] not in full:
			member = m.Staff(parent=q,
							year = year,
							staff_id = new_member[0],
							last_name = new_member[1],
							first_name = new_member[2],
							title = new_member[3],
							subject = new_member[4],
							email=new_member[5],
							)
			member.put()

def all_staff_users(users,year,ancestor):
	u = users
	full = []
	new_email = []

	staff = m.Staff.query(ancestor=ancestor)
	staff = staff.filter(m.Staff.year == year)
	for child in staff:
		full.append(child.email)
	for member in full:
		if member not in u.pleb:
			new_email.append(member)
	u.pleb.extend(new_email)
	return u

class CreateStaffFile(Handler):
	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/setup.html', form=AdminStandardCreate())

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = AdminStandardCreate(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				staff = p.open_file(school,year,form.filename.data)
				q = m.MetaSchool.get_key(school)
				create_staff(staff,year,q)
				self.render('admin/ouch.html')
			else:
				self.render('admin/setup.html', form=form)

class CreateStaffGCS(Handler):
	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/setup.html', form=AdminStandardCreate())

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = AdminStandardCreate(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				staff = p.open_file_gcs(open_cloudstorage_file(form.filename.data))
				q = m.MetaSchool.get_key(school)
				create_staff(staff,year,q)
				self.render('admin/ouch.html')
			else:
				self.render('admin/setup.html', form=form)

class StaffToUsers(Handler):
	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/stafftousers.html', form=StaffToUsersForm())

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = StaffToUsersForm(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				q = m.MetaSchool.get_key(school)
				u = all_staff_users(self.check_u(),year,q)
				u.put()
				self.redirect('/schooladmin/user')
			else:
				self.render('admin/stafftousers.html', form=form)

class StaffGCS(Handler):
	"""CHECK
	Seems to be some old code from standards may need to write up the staff code
	FROM First Round
	"""

	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/setup.html', form=AdminStandardCreate())

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = AdminStandardCreate(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				standardsfile = p.open_file_gcs(open_cloudstorage_file(form.filename.data))
				standards = create_standards_model(standardsfile)
				q = m.MetaSchool.get_key(school)
				standards = update_standards_model(standards,q,year)	
				self.render('admin/ouch.html')
			else:
				self.render('admin/setup.html', form=form)

class StandardsGCS(Handler):
	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/setup.html', form=AdminStandardCreate())

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = AdminStandardCreate(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				standardsfile = p.open_file_gcs(open_cloudstorage_file(form.filename.data))
				standards = create_standards_model(standardsfile)
				q = m.MetaSchool.get_key(school)
				standards = update_standards_model(standards,q,year)	
				self.render('admin/ouch.html')
			else:
				self.render('admin/setup.html', form=form)

class StandardsFile(Handler):
	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/setup.html', form=AdminStandardCreate())

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = AdminStandardCreate(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				standardsfile = p.open_file(school,year,form.filename.data)
				standards = create_standards_model(standardsfile)
				q = m.MetaSchool.get_key(school)
				standards = update_standards_model(standards,q,year)	
				self.render('admin/ouch.html')
			else:
				self.render('admin/setup.html', form=form)
		
		
class StandardsOld(Handler):
	def get(self):
		namespace_manager.set_namespace('')
		if users.is_current_user_admin():
			self.render('admin/setup.html', form=AdminStandardCreate())

	def post(self):
		"""
		Need to sort out students not needed
		"""
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			namespace_manager.set_namespace('')
			form = AdminStandardCreate(self.request.POST)
			namespace_manager.set_namespace(form.school.data[-4:])
			if form.validate():
				school = form.school.data[-4:]
				year = form.year.data
				standardsfile = p.open_file(open_cloudstorage_file(form.filename.data))
				standards = create_standards_model(standardsfile)

				q = m.MetaSchool.get_key(school)
		
				for child in standards:
					standard = m.Standard(parent=q,
											year=year,
											standard_type = child[0],
											subject_id = child[1],
											subject_title=child[2],
											standard_no = child[3],
											version = child[4],
											level = child[5],
											credits = int(child[6]),
											title = child[7], 
											verification_total = int(child[8]),
											
											critique_started=False,
											critique_finished=False,
											critique_email='',

											sample_started=False,
											sample_finished=False,
											sample_email='',	
											)
					standard.put()
			self.render('admin/ouch.html')
		

		
