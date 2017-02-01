from flask import Flask, render_template, redirect, url_for, g, request, send_from_directory, session, Markup
from werkzeug import secure_filename
import mysql.connector
import os
import re
import subprocess
import hashlib, uuid

cnx = mysql.connector.connect(user='root', password='123456789',
                              host='secureprogramming.c69ljrsrgxen.us-west-2.rds.amazonaws.com',
                              database='SecureProgramming')

UPLOAD_FOLDER = '/home/ec2-user/SPProject/app/temp/'
UPLOAD_FOLDER1 = '/home/ec2-user/SPProject/app/FFUploads/'
ALLOWED_EXTENSIONS = set(['c','cpp','py','php','pl'])
ALLOWED_EXTENSIONS = set(['c','cpp'])

application = Flask(__name__)
application.secret_key = os.urandom(24)

application.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
application.config['UPLOAD_FOLDER1'] = UPLOAD_FOLDER1


# For a given file, return whether it's an allowed type or not
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in application.config['ALLOWED_EXTENSIONS']


@application.route('/upload', methods=['POST','GET'])
def upload():
    if (request.method == 'POST') and ('user in session'):
        file = request.files['file']
        filename = secure_filename(file.filename)
	FileExtension = filename.endswith((".py", ".cpp", ".c", ".C", ".pl"))
	if FileExtension :
        	file.save(os.path.join(application.config['UPLOAD_FOLDER'], filename))
        	filepath = os.path.join(application.config['UPLOAD_FOLDER'], filename)
        	strfilepath = str(filepath)
        	cmd = 'rats --quiet --html -w 2 ' + strfilepath
              	process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True)
               	value = process.communicate()
		session['output']=str(value[0])
       		return render_template('ratsOutput.html', output=Markup(session['output']))
	else:
		return "Invalid File extension"
    elif 'user' in session:
       	return render_template('loggedIn.html',user=session['user'])
    else:
        return render_template('login.html')

@application.route('/ratsOutput', methods=['POST'])
def ratsOutput():
	if 'user' in session:
		return render_template('ratsOutput.html', output=output)


@application.route('/uploadf', methods=['POST','GET'])
def uploadf():
    if (request.method == 'POST') and ('user in session'):
        file = request.files['ffile']
        filename = secure_filename(file.filename)
	FileExtension = filename.endswith((".cpp", ".c"))
	if FileExtension :
        	file.save(os.path.join(application.config['UPLOAD_FOLDER1'], filename))
        	filepath = os.path.join(application.config['UPLOAD_FOLDER1'], filename)
        	strfilepath = str(filepath)
        	cmd = 'flawfinder -m 2 --html --quiet --dataonly ' + strfilepath
		process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, shell=True)
               	value = process.communicate()
		session['output']=str(value[0])
		return render_template('ratsOutput.html', output=Markup(session['output']))
	else:
		return "Invalid File extension"
    elif 'user' in session:
       	return render_template('loggedIn.html')
	return render_template('loggedIn.html',user=session['user'])
    else:
        return render_template('login.html')


@application.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']


@application.route('/')
def index():
    return render_template('login.html')


@application.route('/signup', methods=['GET', 'POST'])
def signup():
    return render_template('signup.html')


@application.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('user', None)
    return render_template('login.html')

@application.route('/register', methods=['GET', 'POST'])
def register():
    username = request.form.get("un")
    password = request.form.get("pw")
    cpass = request.form.get("cpw")
    usernameRegex = '^[a-zA-Z0-9_.-]+$'
    validUname = re.match(usernameRegex, username)
    passRegex= '^(?=.*?\d)(?=.*?[A-Z])(?=.*?[a-z])[A-Za-z\d]{8,}$'
    validPass = re.match(passRegex, password)
    if validUname and validPass and (cpass==password):
        cursor = cnx.cursor()
	search_user = ("SELECT * from spLogin where uName='" + username + "'")
	cursor.execute(search_user)
        rows = cursor.fetchall()
	if cursor.rowcount==0:
		hashed_password = hashlib.sha512(password).hexdigest()
        	add_employee = ("INSERT INTO spLogin "
                    		"(uName, uPass) "
                    		"VALUES (%s, %s)")

        	data_employee = (username, hashed_password)
        	cursor.execute(add_employee, data_employee)
        	user_id = cursor.lastrowid
        	cnx.commit()
        	print('User added and id is....:', user_id)
        	return render_template('login.html')
	else:
		return "username is already registered"
    else:
        return render_template('error.html')

@application.route('/loggedIn', methods=['GET', 'POST'])
def loggedIn():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
	hashed_password = hashlib.sha512(password).hexdigest()
        cursor = cnx.cursor()
        query = ("SELECT * from spLogin where uName='" + username + "' and uPass='" + hashed_password + "'")
        cursor.execute(query)
        rows = cursor.fetchall()
        print('Total Row(s):', cursor.rowcount)
        if (cursor.rowcount>0) and ('user in session'):
	    print "andar ao..............................."
            session['user']=username
            return render_template('loggedIn.html',user=username)
        else:
            return redirect(url_for('index'))
    elif 'user' in  session:
        return render_template('loggedIn.html',user=session['user'])
    else:
        return render_template('login.html')


if __name__ == "__main__":
    application.run(host='0.0.0.0', debug=True)
