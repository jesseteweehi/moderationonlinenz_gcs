import csv
import os

def pretty(d, indent=0):
    if type(d) is dict:
        for key, value in d.iteritems():
            print '\t' * indent + str(key)
            if isinstance(value, dict):
                pretty(value, indent+1)
            else:
                if type(value) is list:
                    print '\t' * (indent+1) + str(value)
                else:
                    print '\t' * (indent+1) + str(value.decode('utf-8'))
    if type(d) is list:
        for child in d:
            print str(child)
    if type(d) is str:
        print str(d.decode('utf-8'))

def open_file(filename):
    l = []
    # script_dir = os.path.dirname(__file__)
    # rel_path = school+"/"+year+"/"
    # abs_file_path = os.path.join(script_dir, rel_path) 
    spamreader = csv.reader(filename, delimiter=',',quotechar='"')
    for row in spamreader:
        l.append(row)
    filename.close()
    return l

def subject(string,csv_l):
    """from staff details categorise list according to string (subject)"""
    final = []
    for child in csv_l:
        for grandchild in child:
            if grandchild == string:
                final.append(child)
    return final

def create_select(l):
    full = []
    for child in l:
        val = (child[0],child[0]+' - '+child[2]+' '+child[1])
        if val not in full:
            full.append(val)
    return full

def create_standards(l):
    full=[]
    for child in l:
        standard = child[0].split(' ')[1]
        credits = child[1].split('.')[0]
        title = child[2]
        subject_title = child[-2]
        subject_id = child[-3]
        val =(standard,subject_title+' - '+standard+' - '+title)
        if val not in full:
            full.append(val)
    return full








