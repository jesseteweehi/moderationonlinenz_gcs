import os
import json
from models import models as m
import webapp2
from google.appengine.api import users
from basehandler import Handler
from data import parse as p
from formswt import AdminStandardCreate
from google.appengine.api import namespace_manager
import cloudstorage as gcs

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
	if s[-1:] == '6':
		return '1'
	if s[-1:] == '7':
		return '2'
	if s[-1:] == '8':
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
			# full[standard] = {}
			# full[standard]['standard_type'] = standard_type
			# full[standard]['standard'] = standard
			# full[standard]['credits'] = credits
			# full[standard]['title'] = title
			# full[standard]['subject_title'] = subject_title
			# full[standard]['subject_id'] = subject_id
			# full[standard]['version'] = version
			# full[standard]['level'] = level
			# full[standard]['student_totals'] = student_totals
	return full

class Standards(Handler):
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
		
				# for child in staff:
				# 	member = m.Staff(parent=q,
				# 					year = year,
				# 					staff_id = child[0],
				# 					last_name = child[1],
				# 					first_name = child[2],
				# 					title = child[3],
				# 					subject = child[4],
				# 					email=child[5],
				# 					)
				# 	member.put()
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
		

		