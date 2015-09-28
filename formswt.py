import datetime
from wtforms import Form, SelectMultipleField, SelectField, RadioField, BooleanField, StringField, DateField, PasswordField, IntegerField, validators
from wtforms.widgets import Select, CheckboxInput, TextInput, TextArea, PasswordInput, HiddenInput, TextArea, html_params
from data import parse as p
from models import models as m
from google.appengine.api import namespace_manager

MAX_LENGTH = 50
MAIN_ERROR = ''
NO_INPUT_ERROR = 'Please enter information'

YEARS = [('2015','2015'),('2016','2016'),('2017','2017')]
GRADES = [('No Grade','No Grade'),('Not Achieved','Not Achieved'),('Achieved','Achieved'),('Achieved with Merit','Achieved with Merit'),('Achieved with Excellence','Achieved with Excellence')]

############# Data #############

class AllSchoolsData(SelectField):

	def __init__(self, *args, **kwargs):
		super(AllSchoolsData, self).__init__(*args, **kwargs)
		self.choices = []
		namespace = namespace_manager.get_namespace()
		namespace_manager.set_namespace('')
		school_list = m.AllSchools.get_by_id('school_list')
		for child in school_list.schools:
			self.choices.append((child,child)) 
		namespace_manager.set_namespace(namespace)

class AllStandardsData(SelectField):

	def __init__(self, *args, **kwargs):
		super(AllStandardsData, self).__init__(*args, **kwargs)
		self.choices = []
		standards = m.Standard.query()
		standards = standards.order(m.Standard.subject_title)
		standards = standards.order(m.Standard.subject_id)
		standards = standards.order(m.Standard.standard_no)
		for child in standards:
			self.choices.append((str(child.key.id()),child.subject_id+" | "+child.standard_no+" | "+child.title)) 

class AllStaffData(SelectField):

	def __init__(self, *args, **kwargs):
		super(AllStaffData, self).__init__(*args, **kwargs)
		self.choices = []
		staff = m.Staff.query()
		staff = staff.order(m.Staff.subject)
		staff = staff.order(m.Staff.last_name)
		# staff = staff.order(m.Staff.standard_no)
		for child in staff:
			self.choices.append((child.subject+" - "+child.last_name+" "+child.first_name+" | "+child.staff_id,
				                 child.subject+" - "+child.last_name+" "+child.first_name+" | "+child.staff_id))

class AllStaffDataDelete(SelectMultipleField):
	"""
	Create URL Safe key
	"""

	def __init__(self, *args, **kwargs):
		super(AllStaffDataDelete, self).__init__(*args, **kwargs)
		self.choices = []
		staff = m.Staff.query()
		staff = staff.order(m.Staff.subject)
		staff = staff.order(m.Staff.last_name)
		# staff = staff.order(m.Staff.standard_no)
		for child in staff:
			self.choices.append((child.key.urlsafe(),
				                 child.subject+" - "+child.last_name+" "+child.first_name+" | "+child.staff_id))


############# Helper ################

class Hidden(Form):
	key = StringField(widget=HiddenInput())

############ Admin ###########

class SchoolAdminPasswordForm(Form):
	"""
	This changes the user password for the relative school
	"""
	school = StringField(u'School', widget=TextInput())
	password = PasswordField('New Password', validators=[validators.input_required(), validators.EqualTo('confirm', message='Passwords must match'), validators.password_check(min=8)])
	confirm  = PasswordField('Repeat Password')

class LoginForm(Form):
	"""General Login Form"""
	school = AllSchoolsData(u'Choose School', widget=Select())
	password = PasswordField(u'Password', widget=PasswordInput(), validators=[validators.input_required(message='Please input password')]) 

class MetaCreateForm(Form):
	"""Creates the school which becomes the parents for all school info"""
	name = StringField(u'School', widget=TextInput(), validators=[validators.input_required(message='Please input school'), validators.length(max=MAX_LENGTH)])
	idnumber = StringField(u'School Number', widget=TextInput(), validators=[validators.input_required(),validators.length(min=4,max=4)])

class AdminStandardCreate(Form):
	school  = AllSchoolsData(u'Choose School', widget=Select())
	year = SelectField(u'Year', widget=Select(), choices=YEARS)
	filename = StringField(u'Cloud Storage Filename', widget=TextInput())


############ EDIT OVERALL STANDARDS ###########

class StandardCreateForm(Form):
	year = SelectField(u'Year', widget=Select(), choices=YEARS)

	verification_total = IntegerField(u'No of Student Entries', widget=TextInput(), validators=[validators.optional()])
	subject_id = StringField(u'Subject ID e.g MUS1', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR),validators.length(max=MAX_LENGTH)])
	subject_title = StringField(u'Subject Title e.g Music', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR),validators.length(max=MAX_LENGTH)])

	standard_no = StringField(u'Standard Number', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR),validators.length(max=MAX_LENGTH)])
	version = StringField(u'Version of the Standard', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR),validators.length(max=MAX_LENGTH)])
	level = SelectField(u'NCEA level of Standard', widget=Select(), choices=[('Multi','Multi'),('1','1'),('2','2'),('3','3')])
	credits = IntegerField(u'Credits <br><small>How many credits the standard is worth</small>', widget=TextInput(),validators=[validators.input_required(message=NO_INPUT_ERROR),validators.NumberRange(min=1,max=50,message="Please enter a Number : Max 50")])
	title = StringField(u'Title of the standard', widget=TextArea(), validators=[validators.input_required(message=NO_INPUT_ERROR)])

	standard_type = SelectField(u'Standard Type <br><small>Achievement or Unit Standard</small>',widget=Select(),choices=(('Achievement Standard','Achievement Standard'),('Unit Standard','Unit Standard')))
	tic = AllStaffData(u'Teacher in Charge', widget=Select())

class Crit(Hidden):
	"""Critique for each of the standards
	STILL NEED TO CREATE
	Change radio fields to select and add inputtext other
	"""
	name = StringField(u'Name', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR), validators.length(max=MAX_LENGTH)])
	school = StringField(u'School', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR), validators.length(max=MAX_LENGTH)])
	materials = RadioField(u'Source of Materials', choices=[('Own','Own'),
														('Commercial','Commercial'),    
														('Subject','Subject Association'),
														('TKI','TKI / NZQA'),
														('Other','Other')])

	check1 = BooleanField(u'The assessment material has been reviewed against the current standard clarification and/or external moderation feedback. (Where the material has been previously critiqued and the standard is unchanged, no further critiquing is required)', widget=CheckboxInput())
	check2 = BooleanField(u'Student instructions contain registered standard number, version, title, level & credits', widget=CheckboxInput())
	check3 = BooleanField(u'Student instructions are clear and language is appropriate' ,widget=CheckboxInput())
	check4 = BooleanField(u'The assessment is consistent with learning/context/curriculum at the appropriate level',widget=CheckboxInput())
	check5 = BooleanField(u'The assessment allows students to achieve all requirements of the standard for all grades',widget=CheckboxInput())
	check6 = BooleanField(u'Instructions are consistent with explanatory notes/range statements in the standard',widget=CheckboxInput())
	check7 = BooleanField(u'Assessment schedule is consistent with the standard and clarifications documents',widget=CheckboxInput())
	check8 = BooleanField(u'Judgement/ sufficiency statement clearly describe performance levels for each grade, e.g. quality & length',widget=CheckboxInput())
	check9 = BooleanField(u'Evidence statements allow for a range of acceptable answers from students with specific examples for each grade (N/A/M/E)',widget=CheckboxInput())

	finished = BooleanField(u"""
		By clicking the button to the left you are signing that <b>you</b> have finished the <b><u>critique process</u></b>. 
		<br><small>If you are not finished, click submit process button below to save what you have entered so far. You can sign off the process at a later date</small>""",widget=CheckboxInput())



class SampleandReviewForm(Hidden):
	name = StringField(u'Name', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR), validators.length(max=MAX_LENGTH)])
	school = StringField(u'School', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR), validators.length(max=MAX_LENGTH)])
	check1 = BooleanField(u"The School's random selection procedure has been applied to select work for external moderation, if required.", widget=CheckboxInput())
	check2 = BooleanField(u'Assessment materials have been reviewed in response to the assessor and/or verifier feedback.', widget=CheckboxInput())
	check3 = BooleanField(u'New benchmark samples have been annotated and/or existing examples of grade boundary decisions have been updated.', widget=CheckboxInput())
	check4 = BooleanField(u'Assessment materials and student work are available for external moderation at (indicate file path or location):', widget=CheckboxInput())
	check5 = BooleanField(u'Reviewed assessment materials are ready for future use.', widget=CheckboxInput())

	samples_url = StringField(u'URL Location of Benchmark sample fsiles <br><small>Please enter a web page url</small>', widget=TextInput(), validators=[validators.URL(),validators.optional()])
	samples_other = StringField(u'Benchmark Sample files location <br><small>if applicable please indicate physical location of files</small>', widget=TextInput(), validators=[validators.length(max=MAX_LENGTH)])

	location_url = StringField(u'URL Location of external moderation files <br><small>Please enter a web page url</small>', widget=TextInput(), validators=[validators.URL(),validators.optional()])
	location_other = StringField(u'External Moderation files location <br><small>if applicable please indicate physical location of files</small>', widget=TextInput(), validators=[validators.length(max=MAX_LENGTH)])

	finished = BooleanField(u"""
		By clicking the button to the left you are signing that <b>you</b> have finished the <b><u>sample and review</u></b> process. 
		<br><small>If you are not finished, click submit process button below to save what you have entered so far. You can sign off the process at a later date</small>""",widget=CheckboxInput())

	


class OutsideVerificationForm(Form):
	standard = AllStandardsData('Choose Standard')
	student = StringField(u'Student Name (Full Name)', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR)])
	
	verifier_name = StringField(u'Teacher name (Verifier)', widget=TextInput(), validators=[validators.input_required(message=NO_INPUT_ERROR)])
	verifier_school = StringField(u'School of Verifier', widget=TextInput())

	verifiers_grade = SelectField(u'Assessment judgement', widget=Select(), choices=GRADES)

	discussion = StringField(u'Discussion', widget=TextArea())

	finished = BooleanField(u"<p id='finished_p'>", widget=CheckboxInput(),validators=[validators.required(message="The sign off box above must be checked to submit data")])


class VerificationForm(Form):
	student = StringField(u'Student Name (Full Name)', widget=TextInput(),validators=[validators.input_required(message=NO_INPUT_ERROR), validators.length(max=MAX_LENGTH)])
	
	verifier_name = StringField(u'Teacher name (Verifier)', widget=TextInput(),validators=[validators.input_required(message=NO_INPUT_ERROR), validators.length(max=MAX_LENGTH)])
	verifier_school = StringField(u'School of Verifier', widget=TextInput())
	verifier_school_other = StringField(u'Other - School of Verifier', widget=TextInput())
	verifiers_grade = StringField(u'Assessment judgement', widget=TextInput())

	markers_grade = SelectField(u'Markers assessment judgement', widget=Select(), choices=GRADES)
	reported_grade = SelectField(u'Reported assessment judegement', widget=Select(), choices=GRADES)

	# tic = AllStaffData(u'Teacher in Charge', widget=Select())

	discussion = StringField(u'Discussion', widget=TextArea())




class InsideVerificationForm(Form):
	standard = StringField(u'Standard', widget=HiddenInput())
	student = StringField(u'Student Name', widget=TextInput(),validators=[validators.input_required(message=NO_INPUT_ERROR)])
	
	verifier_name = StringField(u'Teacher name', widget=TextInput(),validators=[validators.input_required(message=NO_INPUT_ERROR)])
	verifier_school = StringField(u'School of Verifier', widget=TextInput())
	verifier_school_other = StringField(u'Other - School of Verifier', widget=TextInput())
	verifiers_grade = SelectField(u'Assessment judgement', widget=Select(), choices=GRADES, validators=[validators.NoneOf(values='No Grade',message='Please enter appropriate grade')])

	markers_grade = SelectField(u'Markers assessment judgement', widget=Select(), choices=GRADES,validators=[validators.optional()])
	reported_grade = SelectField(u'Reported assessment judegement', widget=Select(), choices=GRADES,validators=[validators.optional()])

	# tic = AllStaffData(u'Teacher in Charge', widget=Select(),validators=[validators.optional()])

	discussion = StringField(u'Discussion', widget=TextArea(),validators=[validators.optional()])

	finished = BooleanField(u"<p id='finished_p'>", widget=CheckboxInput(),validators=[validators.required(message="The sign off box above must be checked to submit data")])




class CodeForm(Form):
	school = AllSchoolsData(u'School', widget=Select())
	code = StringField(u'Code', widget=TextInput())

class CodeCreateForm(Form):
	"""
	This changes the user password for the relative school
	"""
	school = StringField(u'School', widget=TextInput())
	code = StringField('Code', validators=[validators.input_required(), validators.EqualTo('confirm', message='Code must match'), validators.password_check(min=5)])
	confirm  = StringField('Repeat Code')

class UsersCreateForm(Form):
	"""
	Organise users
	"""
	user = StringField('Add / Delete  User',widget=TextInput(), validators=[validators.Email(),validators.optional()])
	admin = BooleanField('Administrator',widget=CheckboxInput())
	delete = BooleanField('Check if you want to Delete User',widget=CheckboxInput())
	admin_delete = BooleanField('Remove Admin Rights',widget=CheckboxInput())
	all_delete = BooleanField('Start Again',widget=CheckboxInput())


class CreateStaffForm(Form):
	year = SelectField(u'Year', widget=Select(), choices=YEARS)
	staff_id = StringField(u'staff_id', widget=TextInput(), validators=[validators.input_required()])
	first_name = StringField(u'First Name', widget=TextInput(), validators=[validators.input_required()])
	last_name = StringField(u'Last Name', widget=TextInput(), validators=[validators.input_required()])
	title = SelectField(u'Title', widget=Select(), choices=(('Mr','Mr'),('Mrs','Mrs'),('Miss','Miss'),('Ms','Ms')))
	subject = StringField(u'Subject', widget=TextInput(),validators=[validators.input_required()])
	email = StringField(u'Email', widget=TextInput(), validators=[validators.Email()])

class DeleteStaffForm(Form):
	member = AllStaffDataDelete(u'Delete Staff')






