#!/usr/bin/env python
# -*- coding: utf-8 -*-
import csv
from cStringIO import StringIO

import webapp2
from webapp2_extras import sessions
from google.appengine.api import users
from google.appengine.datastore import datastore_query
from google.appengine.api import namespace_manager
from google.appengine.ext import ndb
from google.appengine.ext.ndb import metadata
import cloudstorage as gcs

from basehandler import Handler
from models import models as m
from data import parse as p

from formswt import DeleteStaffForm, CreateStaffForm, UsersCreateForm, Crit, MetaCreateForm, LoginForm, SchoolAdminPasswordForm, SampleandReviewForm, StandardCreateForm, VerificationForm, OutsideVerificationForm, InsideVerificationForm, CodeForm, CodeCreateForm
from config import Standards
import transactions as t

from docx import Document
from docx.shared import Inches

import worddoc


def check_creds(user, check_u, admin=False):
	if not user or not check_u:
		return False  
	if user.email() in check_u.pleb and not admin:
		return True
	if user.email() in check_u.admin and admin:
		return True
	else:
		return False

class MainPage(Handler):
	def organise(self, user,check):
		if user and check:
			return self.redirect('/standards')
		if user and not check:
			return self.redirect('/login')
		if check and not user:
			return self.redirect(users.create_login_url('/'))
		if not check and not user:
			return self.redirect('/vlogin')

	def get(self):
		user = users.get_current_user()
		self.organise(user, self.check_u())
		
######## Standards #########

def create_subject_list(l):
	full=[]
	for child in l:
		if child.subject_title not in full:
			full.append(child.subject_title)
	return sorted(full)

class StandardDelete(Handler):
	def post(self, post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True):	
			standard = m.Standard.get_by_id(int(post_id), parent=self.ancestor())
			
			if not standard:
				self.error(404)
				return

			full = []
			if standard.critique_key:
				full.append(standard.critique_key)
			if standard.sample_key:
				full.append(standard.sample_key)
			if standard.verification_key:
				full.extend(standard.verification_key)
			if full:
				ndb.delete_multi(full)
		
			standard.key.delete()
			m.Standard.reset_standard_shuffle()
			m.Standard.reset_subject_list()
			self.redirect('/')
		else:
			self.redirect('/ouch')

class StandardCreate(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True):
			self.render('standards/create_standard.html', form=StandardCreateForm())
		else:
			self.redirect('/ouch')
	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=True):
			self.redirect('/ouch')
		else:
			form = StandardCreateForm(self.request.POST)
			if form.validate():
				standard = m.Standard(parent=self.ancestor(),
					year=form.year.data,

					standard_type=form.standard_type.data,

					subject_id=form.subject_id.data,
					subject_title=form.subject_title.data,

					standard_no=form.standard_no.data,
					version=form.version.data,
					level=form.level.data,
					credits=int(form.credits.data),
					title=form.title.data,
									
					critique_started=False,
					critique_finished=False,
					critique_email='',

					sample_started=False,
					sample_finished=False,
					sample_email='',

					verification_total=form.verification_total.data,

					tic=form.tic.data,
					)
				standard.put()
				m.Standard.reset_standard_shuffle()
				m.Standard.reset_subject_list()
				self.redirect('/standards/%s#standard' % str(standard.key.id()))
			else:
				self.render('blank.html', var=form.errors)
				# self.render('standards/create_standard.html', form=form)

class StandardEdit(Handler):
	def get(self,post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			standard = m.Standard.get_by_id(int(post_id), parent=self.ancestor())
			editstandardcreateform = StandardCreateForm(obj=standard)
			self.render('standards/edit_standard.html', form=editstandardcreateform)
		else:
			self.redirect('/ouch')

	def post(self,post_id):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		else:
			form = StandardCreateForm(self.request.POST)
			q = m.MetaSchool.get_key(self.session.get('school-id'))
			standard = m.Standard.get_by_id(int(post_id), parent=q)
			if form.validate():
				standard.year = form.year.data
				standard.standard_type = form.standard_type.data
				standard.subject_id = form.subject_id.data  
				standard.subject_title = form.subject_title.data
				standard.standard_no = form.standard_no.data
				standard.version = form.version.data
				standard.level = form.level.data
				standard.credits = int(form.credits.data)
				standard.title = form.title.data
				standard.tic = form.tic.data
				standard.verification_total=form.verification_total.data
				standard.put()
				self.redirect('/standards/%s#standard' % str(standard.key.id()))
			else:
				editstandardcreateform = StandardCreateForm(obj=standard)
				self.render('standards/edit_standard.html', form=editstandardcreateform)

class AllStandards(Handler):
	def organise(self,var1,var2,cursor):
		"""
		Filter by subject then order by completion
		"""
		if var1 == var2:
			return m.Standard.default_filter_page(cursor)
		if var1 == 'A':
			if var2 == 'critique_finished':
				return m.Standard.default_order_by_critique(cursor)
			if var2 == 'sample_finished':
				return m.Standard.default_order_by_sample(cursor)
			if var2 == 'verification_finished':
				return m.Standard.default_order_by_verification_finished(cursor)
			if var2 == 'A':
				return m.Standard.default_filter_page(cursor)
			else:
				return m.Standard.default_filter_page(cursor)
		else:
			return m.Standard.subject_order(var1,var2,cursor)


	order_list = [('A','Normal'),('critique_finished','Critique not completed'),('sample_finished','Samples not completed'),('verification_finished','No of Verifications')]
	
	def get(self):
		"""
		1) Filter by subject
		2) Filter by Completion
		"""
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			cursor_str = self.request.get('c', None)
			cursor = None
			if cursor_str:
				cursor = datastore_query.Cursor(urlsafe=cursor_str)


			var1 = self.request.get('q')
			var2 = self.request.get('o')
			subject_list = m.Standard.get_subject_list()
			results, new_cursor, more = self.organise(var1,var2,cursor)

			if more:
				urlcursor = new_cursor.urlsafe()
			else:
				urlcursor= None
			
			self.render('standards/all_standard_page.html',var=results,subject_list=subject_list, order_list=self.order_list, q=var1, o=var2, urlcursor=urlcursor)
		else:
			self.redirect('/ouch')

class StandardPage(Handler):
	def check_before_after(self, before, after):
		if before and after:
			return before.id(),after.id()
		if not before and not after:
			return before,after
		if before and not after:
			return before.id(),after
		if not before and after:
			return before,after.id()

	def get(self, post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):	
			standard = m.Standard.get_by_id(int(post_id), parent=self.ancestor())
			before, after = m.Standard.standard_shuffle(standard.key)
			before, after = self.check_before_after(before,after)
			critique=None
			sample=None
			verification_list =None
			if not standard:
				self.error(404)
				return

			if standard.critique_key:
				critique = standard.critique_key.get()

			if standard.sample_key:
				sample = standard.sample_key.get()

			if standard.verification_key:
				verification_list = ndb.get_multi(standard.verification_key)

			self.render('standards/standard_page.html',standard=standard, critique=critique, sample=sample, verification_list=verification_list, before=before, after=after)
		else:
			self.redirect('/ouch')

class StandardDownload(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True):
			standards = m.Standard.query()
			standards = standards.order(m.Standard.subject_title)
			standards = standards.order(m.Standard.subject_id)
			standards = standards.order(m.Standard.standard_no)

			self.response.headers['Content-Type'] = 'text/csv'
			self.response.headers['Content-Disposition'] = 'attachment; filename=standards.csv'
			writer = csv.writer(self.response.out)
			# writer.writerow(['Year','Subject_Title','Subject_ID','Standard_No'])
			for standard in standards:
				critique=None
				sample=None
				if standard.critique_key:
					critique = standard.critique_key.get()
				if standard.sample_key:
					sample = standard.sample_key.get()
				writer.writerow([standard.subject_title,
								 standard.subject_id,
								 standard.standard_no,
								 standard.version,
								 standard.level,
								 standard.credits,
								 standard.title,])
		else:
			self.redirect('/ouch')

class TrialXMLDownload(Handler):
	def get(self, post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True):
			standard = m.Standard.get_by_id(int(post_id), parent=self.ancestor())
			critique=None
			sample=None
			verification_list =None
			if not standard:
				self.error(404)
				return

			if standard.critique_key:
				critique = standard.critique_key.get()

			if standard.sample_key:
				sample = standard.sample_key.get()

			if standard.verification_key:
				verification_list = ndb.get_multi(standard.verification_key)

			if critique == None or sample == None or verification_list == None or len(verification_list) < 8:
				self.redirect('/downloadfail')

			else:
				filename = str(standard.subject_title +'-'+standard.subject_id+'|'+standard.standard_no)
				document = worddoc.create_document(standard, critique, sample, verification_list)

				f = StringIO()
				document.save(f)
			
				self.response.headers['Content-Type'] = 'text/xml'
				self.response.headers['Content-Disposition'] = 'attachment; filename=%s.docx' %filename 
				self.response.write(f.getvalue())
		else:
			self.redirect('/ouch')

######### Sample and Review ##########

class SampleandReviewCreate(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			standard_parent = self.request.get('standard_parent')
			if standard_parent:
				self.render('samples/sampleandreview.html', form=SampleandReviewForm(),standard_parent=standard_parent)
			else:
				self.redirect('/standards')
		else:
			self.redirect('/ouch')

	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		else:
			form = SampleandReviewForm(self.request.POST)
			if form.validate():
				key = t.create_sample(form,self.ancestor(), user.email())
				if key:
					self.redirect('/standards/%s#sample' % str(key))
				else:
					self.redirect('/')
			else:
				standard_parent = self.request.get('standard_parent')
				standard = m.Standard.get_by_id(int(standard_parent), parent=self.ancestor())
				self.render('samples/sampleandreview.html', form=form, standard_parent=standard_parent)

class SampleandReviewEdit(Handler):
	def get(self, post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			sample = m.SampleandReviewModel.get_by_id(int(post_id),parent=self.ancestor())
			editsampleandreviewform = SampleandReviewForm(obj=sample)
			self.render('samples/sampleandreview_edit.html', form=editsampleandreviewform)
		else:
			self.redirect('/ouch')
	
	def post(self, post_id):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		else:
			form = SampleandReviewForm(self.request.POST)
			if form.validate():
				key = t.update_sample(form,self.ancestor(), post_id, user.email())
				self.redirect('/standards/%s#sample' % str(key))
			else:
				self.render('samples/sampleandreview_edit.html', form=form)
				# self.render('blank.html', var=form.errors)
			
######### Critique ##########

class CritiqueCreate(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			standard_parent = self.request.get('standard_parent')
			if standard_parent:
				self.render('critique/critique.html', form=Crit(), standard_parent=standard_parent)
			else:
				self.redirect('/standards')
		else:
			self.redirect('/ouch')

	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		else:
			form = Crit(self.request.POST)
			if form.validate():
				key = t.create_critique(form,self.ancestor(),user.email())
				if key:
					self.redirect('/standards/%s#critique' % str(key))
				else:
					self.redirect('/')
			else:
				standard_parent = self.request.get('standard_parent')
				standard = m.Standard.get_by_id(int(standard_parent), parent=self.ancestor())
				self.render('critique/critique.html', form=form, standard_parent=standard_parent)

class CritiquePageEdit(Handler):
	def get(self,post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			critique = m.CritiqueModel.get_by_id(int(post_id),parent=self.ancestor())
			editcritiqueform = Crit(obj=critique)
			self.render('critique/critique_edit.html', form=editcritiqueform)
		else:
			self.redirect('/ouch')

	def post(self,post_id):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		else:
			form = Crit(self.request.POST)
			key = t.update_critique(form, self.ancestor(), post_id, user.email())
			if form.validate():
				
				self.redirect('/standards/%s#critique' % str(key))
			else:
				editcritiqueform = Crit(obj=critique)
				self.render('critique/critique_edit.html', form=editcritiqueform, id=str(critique.key.id()))

######### Verification ############

class VerificationOutsideCreate(Handler):
	"""
	Need to work out how to solve the ancestor problem
	"""
	def get(self,post_id):
		code = self.session.get('parent')
		if str(code) == post_id:
			self.render('verification/outside_verification.html', form=OutsideVerificationForm())
		else:
			self.redirect('ouch')
		
	def post(self,post_id):
		code = self.session.get('parent')
		if str(code) == post_id:
			ancestor=m.MetaSchool.get_by_id(int(post_id))
			form = OutsideVerificationForm(self.request.POST)	
			if form.validate():	
				key = t.create_verification_other(form,ancestor.key)
				if key:
					self.redirect('/thanks/%s' % str(post_id))
				else:
					self.render('verification/outside_verification.html', form=OutsideVerificationForm())
			else:
				self.render('verification/outside_verification.html', form=form)
		else:
			self.redirect('ouch')

			# self.render('blank.html', var=form.errors)

class VerificationEdit(Handler):
	def get(self,post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			verification=m.VerificationModel.get_by_id(int(post_id),parent=self.ancestor())
			editverificationform = VerificationForm(obj=verification)
			self.render('verification/verification.html', form=editverificationform)
		else:
			self.redirect('/ouch')

			
	def post(self,post_id):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		form = VerificationForm(self.request.POST)
		if form.validate():	
			verification = t.update_verification(form,post_id, self.ancestor())
			self.redirect('/standards/%s#verification' % str(verification))		
		else:
			self.render('blank.html', var=form.errors)
			# self.render('verification/verification.html', form=form)

class VerificationDelete(Handler):
	def post(self, post_id):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			verification = t.delete_verification(post_id,self.ancestor())
		
			if not verification:
				self.error(404)
				return
		
			self.redirect('/standards/%s#verification' % str(verification))
		else:
			self.redirect('/ouch')	

class VerificationInsideCreate(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=False):
			standard_parent = self.request.get('standard_parent')
			standard = m.Standard.get_by_id(int(standard_parent), parent=self.ancestor())
			if standard_parent:
				self.render('verification/inside_verification.html', form=InsideVerificationForm(), standard=standard, school=self.check_u().school)
			else:
				self.redirect('/')
		else:
			self.redirect('/ouch')	
	
	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=False):
			self.redirect('/ouch')
		else:
			form = InsideVerificationForm(self.request.POST)	
			if form.validate():	
				key = t.create_verification(form,self.ancestor())
				if key:
					self.redirect('/standards/%s#verification' % str(key))
				else:
					self.render('verification/inside_verification.html', form=InsideVerificationForm())
			else:
				# self.render('blank.html', var=form.errors)
				standard_parent = self.request.get('standard_parent')
				standard = m.Standard.get_by_id(int(standard_parent), parent=self.ancestor())
				self.render('verification/inside_verification.html', form=form, standard=standard, school=self.check_u().school)
		
######### Admin ############

class CreateStaff(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True):
			self.render('admin/createstaff.html', form=CreateStaffForm())
		else:
			self.redirect('/ouch')

	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=True) and not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			form = CreateStaffForm(self.request.POST)
			if form.validate():
				staff = m.Staff(parent=self.ancestor(),
								year=form.year.data,
								staff_id=form.staff_id.data,
								last_name=form.last_name.data,
								first_name=form.first_name.data,
								title=form.title.data,
								subject =form.subject.data,
								email=form.email.data,)
				staff.put()
				self.redirect('/staff/create')
			else:
				self.render('blank.html', var=form.errors)
				# self.render('admin/createstaff.html', form=form)

class DeleteStaff(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True):
			self.render('admin/deletestaff.html', form=DeleteStaffForm())
		else:
			self.redirect('/ouch')

	def post(self):
		form = DeleteStaffForm(self.request.POST)
		if form.validate():
			full = []
			for member in form.member.data:
				key = ndb.Key(urlsafe=member)
				full.append(key)
			if full:		
				ndb.delete_multi(full)
				self.redirect('/staff/delete')
		else:
			self.render('admin/deletestaff.html', form=form)




class CreateUsers(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True) or users.is_current_user_admin():
			self.render('admin/createusers.html', var=self.check_u(), form=UsersCreateForm())
		else:
			self.redirect('/ouch')

	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=True) and not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			u = self.check_u()
			form = UsersCreateForm(self.request.POST)
			if form.validate():
				if u:
					if form.all_delete.data:
						u.pleb = []
						u.admin = []
					if form.user.data and form.admin.data:
						if form.user.data not in u.pleb:
							u.pleb.append(form.user.data)
						if form.user.data not in u.admin:
							u.admin.append(form.user.data)
					if form.user.data and form.delete.data:
						if form.user.data in u.pleb:
							u.pleb.remove(form.user.data)
						if form.user.data in u.admin:
							u.admin.remove(form.user.data)
					if form.user.data and form.admin_delete.data:
						if form.user.data in u.admin:
							u.admin.remove(form.user.data)
						else:
							pass
					else:
						if form.user.data and form.user.data not in u.pleb:
							u.pleb.append(form.user.data)
					u.put()
					self.redirect('/schooladmin/user')
				else:
					self.redirect('/schooladmin/user')
			else:
				self.render('admin/createusers.html', var=u, form=form)
		

class VerificationLogin(Handler):
	def get(self):
		self.render('admin/verificationlogin.html', form=CodeForm())

	def post(self):
		form = CodeForm(self.request.POST)
		if form.validate():
			namespace_manager.set_namespace(form.school.data[-4:])
			check = m.User.check_code(form.school.data,form.code.data)
			if check:
				self.session['parent'] = check.key.parent().integer_id()
				self.session['school-id'] = form.school.data[-4:]
				self.redirect('/%s' % str(check.key.parent().integer_id()))
			else:
				self.redirect('/vlogin')
		else:
			self.render('admin/verificationlogin.html', form=form)

class VerificationLoginPassword(Handler):
	def get(self):
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True) or users.is_current_user_admin():
			self.render('admin/verificationloginpassword.html', form=CodeCreateForm(), school=self.check_u().school)
		else:
			self.redirect('/ouch')

	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=True) and not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			form = CodeCreateForm(self.request.POST)
			if form.validate():
				check=m.User.by_name(form.school.data)			
				update = m.User.update(form.school.data,form.code.data)
				check.outside_hash = update
				self.session['parent'] = check.key.parent().integer_id()
				check.put()
				self.redirect('/')
			else:
				self.render('admin/verificationloginpassword.html', form=form, school=self.check_u().school)

class Login(Handler):
	def get(self):
		self.render('admin/login.html', form=LoginForm())

	def post(self):
		form = LoginForm(self.request.POST)
		if form.validate():	
			namespace_manager.set_namespace(form.school.data[-4:])
			check = m.User.login(form.school.data,form.password.data)
			if check:
				self.session['school-id'] = form.school.data[-4:]
				self.session['user'] = check.key.integer_id()
				self.redirect('/')
			else:
				self.redirect('/login')
		else:
			self.redirect('/login')

class Logout(Handler):
	def get(self):
		self.checkout()
		self.render('admin/logout.html',url=users.create_logout_url('/'))

class SchoolCreate(Handler):
	def get(self):
		if users.is_current_user_admin():
			self.render('admin/metacreate.html', form=MetaCreateForm())
		else:
			self.redirect(users.create_login_url('/admin/meta'))
		

	def post(self):
		if not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			form = MetaCreateForm(self.request.POST)
			if form.validate():
				t.create_school(form)
				self.redirect('/')
			else:
				self.render('admin/metacreate.html', form=form)


class SchoolAdminPassword(Handler):
	def get(self):
		"""
		If Admin get Schooladminpassword which allows user to change all passwords
		else, user must be in admin side of members and gains access to only their school bu using the shchool-id session.		
		"""
		user = users.get_current_user()
		if check_creds(user, self.check_u(), admin=True) or users.is_current_user_admin():
			if self.check_u():
				school = self.check_u().school
			else:
				school = None
			self.render('admin/schooladminpassword.html', form=SchoolAdminPasswordForm(), school=school)
		else:
			self.redirect('/ouch')
		
	def post(self):
		user = users.get_current_user()
		if not check_creds(user, self.check_u(), admin=True) and not users.is_current_user_admin():
			self.redirect('/ouch')
		else:
			form = SchoolAdminPasswordForm(self.request.POST)
			if form.validate():
				namespace_manager.set_namespace(form.school.data[-4:])
				check = m.User.by_name(form.school.data)
				if check:
					update = m.User.update(form.school.data,form.password.data)
					check.pw_hash = update
					check.put()
					self.redirect('/') 
				else:				
					create = m.User.register(form.school.data,form.password.data)
					create.put() 
					self.redirect('/')
			else:
				self.redirect('/schooladmin/pass')

class Ouch(Handler):
	def get(self):
		q=users.create_login_url('/') 
		self.render('admin/ouch.html',var=q)

class Thanks(Handler):
	def get(self,post_id):
		self.render('admin/thanks.html',var=post_id)

class DownloadFail(Handler):
	def get(self):
		self.render('admin/downloadfail.html')

class Other(Handler):
	def get(self):
		user = users.get_current_user()
		if users.is_current_user_admin():
			namespaces=metadata.get_namespaces()
			current_namespace = namespace_manager.namespace_manager.get_namespace()

			self.response.out.write((namespaces,current_namespace,self.session,self.check_u()))
		else:
			self.redirect('/ouch')


webapp2_config = {}
webapp2_config['webapp2_extras.sessions'] = {
		'secret_key': 'aldfnv;ladnfv:_+%^&!()HUTD<><><ndflsfnvl;dsfnvskdfnvfd',
	}

app = webapp2.WSGIApplication([
	('/', MainPage),
	('/([0-9]+)', VerificationOutsideCreate),

	('/standards/edit/([0-9]+)', StandardEdit),
	('/standards/delete/([0-9]+)', StandardDelete),
	('/standards/create', StandardCreate),
	('/standards/([0-9]+)', StandardPage),
	('/standards', AllStandards),

	('/verification/edit/([0-9]+)', VerificationEdit),
	('/verification/delete/([0-9]+)', VerificationDelete),
	('/verification/create', VerificationInsideCreate),
	
	('/critique/create', CritiqueCreate),
	('/critique/edit/([0-9]+)', CritiquePageEdit),

	('/sample/create', SampleandReviewCreate),
	('/sample/edit/([0-9]+)', SampleandReviewEdit),

	('/schooladmin/pass', SchoolAdminPassword),
	('/schooladmin/vpass', VerificationLoginPassword),
	('/schooladmin/user', CreateUsers),
	('/staff/create', CreateStaff),
	('/staff/delete', DeleteStaff),

	('/vlogin', VerificationLogin),
	('/login', Login),
	('/logout', Logout),

	('/ouch', Ouch),
	('/thanks/([0-9]+)', Thanks),
	('/downloadfail', DownloadFail),

	('/admin/meta', SchoolCreate),
	('/admin/setup', Standards),

	('/download', StandardDownload),
	('/xml/([0-9]+)', TrialXMLDownload),

	('/namespaces',Other)


], config=webapp2_config, debug=True)
