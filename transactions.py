from google.appengine.ext import ndb
from google.appengine.api import namespace_manager
from models import models as m
from basehandler import Handler

@ndb.transactional(xg=True)
def create_school(form, k='school_list'):
	namespace_manager.set_namespace('')
	school_list = m.AllSchools.get_by_id(k)
	if not school_list:
		var = [form.name.data+" - "+form.idnumber.data]
		school_list = m.AllSchools(schools=var,id='school_list')
	else:
		school_list.schools.append(form.name.data+" - "+form.idnumber.data)
	school_list.put()
	namespace_manager.set_namespace(form.idnumber.data)
	school = m.MetaSchool(name=form.name.data,
						  idnumber=form.idnumber.data)
	school.put()

@ndb.transactional(xg=True)
def create_critique(form, p, email=''):
	"""
	Steps
	1) Retrieve standard (from hidden id) using parent from school - session
	2) Create critique model
	3) add critique model key to standard.critiquekey --- KeyProperty.
	4) check form.data.finished if clicked, True for standard.critiquefinished ---  Boolean
	5) Return key property of standard so we can redirect page
	"""
	standard = m.Standard.get_by_id(int(form.key.data), parent=p)
	if standard:		
		critique = m.CritiqueModel(
					parent=p,
					name=form.name.data,
					school=form.school.data,
					materials=form.materials.data,
					check1=form.check1.data,
					check2=form.check2.data,
					check3=form.check3.data,
					check4=form.check4.data,
					check5=form.check5.data,
					check6=form.check6.data,
					check7=form.check7.data,
					check8=form.check8.data,
					check9=form.check9.data,
					critique_standard=standard.key,
					finished=form.finished.data,)
		critique_key = critique.put()
		standard.critique_key = critique_key
		standard.critique_started = True
		if form.finished.data:
			standard.critique_finished = True
			standard.critique_email = email
		standard.put()
		return standard.key.id()
	else:
		return None

@ndb.transactional(xg=True)
def update_critique(form, p, post_id, email=''):
	critique = m.CritiqueModel.get_by_id(int(post_id),parent=p)
	critique.name = form.name.data
	critique.school = form.school.data
	critique.materials = form.materials.data
	critique.check1 = form.check1.data
	critique.check2 = form.check2.data
	critique.check3 = form.check3.data
	critique.check4 = form.check4.data
	critique.check5 = form.check5.data
	critique.check6 = form.check6.data
	critique.check7 = form.check7.data
	critique.check8 = form.check8.data
	critique.check9 = form.check9.data
	critique.finished = form.finished.data
	critique.put()
	if form.finished.data:
		standard = m.Standard.get_by_id(critique.critique_standard.id(),parent=p)
		standard.critique_finished = True
		standard.critique_email = email
	else:
		standard = m.Standard.get_by_id(critique.critique_standard.id(),parent=p)
		standard.critique_finished = False
		standard.critique_email = ''
	standard.put()
	return critique.critique_standard.id()

@ndb.transactional(xg=True)
def create_sample(form, p, email=''):
	"""
	Steps
	1) Retrieve standard (from hidden id) using parent from school - session
	2) Create critique model
	3) add critique model key to standard.critiquekey --- KeyProperty.
	4) check form.data.finished if clicked, True for standard.critiquefinished ---  Boolean
	5) Return key property of standard so we can redirect page
	"""
	standard = m.Standard.get_by_id(int(form.key.data), parent=p)
	if standard:		
		sample = m.SampleandReviewModel(
				parent=p,
				name=form.name.data,
				school=form.school.data,
				check1=form.check1.data,
				check2=form.check2.data,
				check3=form.check3.data,
				check4=form.check4.data,
				check5=form.check5.data,
				location_url=form.location_url.data,
				location_other=form.location_other.data,
				samples_url=form.samples_url.data,
				samples_other=form.samples_other.data,
				sample_standard=standard.key,
				finished=form.finished.data,)
		sample_key = sample.put()
		standard.sample_key = sample_key
		standard.sample_started = True
		if form.finished.data:
			standard.sample_finished = True
			standard.sample_email = email
		standard.put()
		return standard.key.id()
	else:
		return None


@ndb.transactional(xg=True)
def update_sample(form, p, post_id, email=''):
	sample = m.SampleandReviewModel.get_by_id(int(post_id),parent=p)
	sample.name = form.name.data
	sample.school = form.school.data
	sample.check1 = form.check1.data
	sample.check2 = form.check2.data
	sample.check3 = form.check3.data
	sample.check4 = form.check4.data
	sample.check5 = form.check5.data
	sample.samples_url = form.samples_url.data
	sample.samples_other = form.samples_other.data
	sample.location_url = form.location_url.data
	sample.location_other = form.location_other.data
	sample.finished = form.finished.data
	sample.put()
	if form.finished.data:
		standard = m.Standard.get_by_id(sample.sample_standard.id(),parent=p)
		standard.sample_finished = True
		standard.sample_email = email
	else:
		standard = m.Standard.get_by_id(sample.sample_standard.id(),parent=p)
		standard.sample_finished = False
		standard.sample_email = ''
	standard.put()
	return sample.sample_standard.id()

@ndb.transactional(xg=True)
def create_verification_other(form,q):
	standard = m.Standard.get_by_id(int(form.standard.data), parent=q)
	if standard:	
		verification = m.VerificationModel(
									parent=q,
									student = form.student.data,
									verifier_name=form.verifier_name.data,
									verifier_school=form.verifier_school.data,
									verification_other_school=True,
									verifiers_grade=form.verifiers_grade.data,
									discussion=form.discussion.data,
									verification_standard=standard.key,
									finished=form.finished.data,
									)
		verification_key = verification.put()
		standard.verification_key.append(verification_key)
		standard.put()
		return standard.key.id()
	else:
		return None


@ndb.transactional(xg=True)
def create_verification(form,q):
	standard = m.Standard.get_by_id(int(form.standard.data), parent=q)
	if standard:
		if form.verifier_school_other.data:
			verification = m.VerificationModel(
										parent=q,
										student = form.student.data,
										verifier_name=form.verifier_name.data,
										verifier_school=form.verifier_school_other.data,
										verification_other_school=True,
										verifiers_grade=form.verifiers_grade.data,
										discussion=form.discussion.data,
										verification_standard=standard.key,
										finished=form.finished.data,
										)
		else:
			verification = m.VerificationModel(
										parent=q,
										student = form.student.data,
										verifier_name=form.verifier_name.data,
										verifier_school=form.verifier_school.data,
										verification_other_school=False,
										verifiers_grade=form.verifiers_grade.data,
										discussion=form.discussion.data,
										verification_standard=standard.key,
										finished=form.finished.data,
										)
		verification_key = verification.put()
		standard.verification_key.append(verification_key)
		standard.put()
		return standard.key.id()
	else:
		return None


@ndb.transactional(xg=True)
def update_verification(form,post_id,var):
	verification=m.VerificationModel.get_by_id(int(post_id),parent=var)
	verification.student = form.student.data
	verification.verifier_name = form.verifier_name.data
	verification.verifier_school = form.verifier_school.data
	verification.verifiers_grade= form.verifiers_grade.data
	verification.markers_grade=form.markers_grade.data
	verification.reported_grade=form.reported_grade.data
	verification.tic =form.tic.data
	verification.discussion =form.discussion.data
	standard = m.Standard.get_by_id(verification.verification_standard.id(), parent=var)
	standard.put()
	verification.put()
	return verification.verification_standard.id()

@ndb.transactional(xg=True)
def delete_verification(post_id,var):
	"""
	Firstly call up standard of the verification.
	Delete the verification key from standard
	Delete the standard
	"""
	verification = m.VerificationModel.get_by_id(int(post_id), parent=var)
	if verification:
		standard = verification.verification_standard.get()
		standard.verification_key.remove(verification.key)
		standard.put()
		verification.key.delete()
		return standard.key.id()
	else:
		return None
	


