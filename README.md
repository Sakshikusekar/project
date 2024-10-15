from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
from flask_login import *
from werkzeug.security import generate_password_hash,check_password_hash
import json
import requests
import MySQLdb.cursors
import re
from flask_mail import Mail,Message
from random import randint
import stripe
import time

app = Flask(__name__)
mail=Mail(app)

app.config["MAIL_SERVER"]='smtp.gmail.com'
app.config["MAIL_PORT"]=465
app.config["MAIL_USERNAME"]='adityatanvoji@gmail.com'
app.config['MAIL_PASSWORD']='spxy vpdh mxav elyy'                    #you have to give your password of gmail account
app.config['MAIL_USE_TLS']=False
app.config['MAIL_USE_SSL']=True
mail=Mail(app)
otp=randint(000000,999999)

app.secret_key = 'xyzsdfg'
public_key = "pk_test_6pRNASCoBOKtIshFeQd4XMUh"
stripe.api_key = "sk_test_BQokikJOvBiI2HlWgH4olfQ2"
# Configure MySQL connection
dbd = MySQLdb.connect(host="localhost", user="root", passwd="", db="student_portal")

# Create a database cursor object
cursor = dbd.cursor()
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'student_portal'
app.config['SQLALCHEMY_DATABASE_URI']='mysql://root:@localhost/student_portal'
db=SQLAlchemy(app)
mysql = MySQL(app)

login_manager=LoginManager(app)
login_manager.login_view='login'

class User(UserMixin,db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50))
    contact=db.Column(db.Integer,unique=True)
    email=db.Column(db.String(50),unique=True)
    password=db.Column(db.String(500))

class personalinfo(UserMixin,db.Model):
    sid=db.Column(db.Integer,primary_key=True)
    sname=db.Column(db.String(100))
    semail=db.Column(db.String(100),unique=True)
    scon=db.Column(db.Integer,unique=True)
    sgender=db.Column(db.String(50))
    sdob=db.Column(db.String(80))
    sbirthp=db.Column(db.String(100))
    snationality=db.Column(db.String(150))
    shandicap=db.Column(db.String(30))
    sreligion=db.Column(db.String(50))
    scaste=db.Column(db.String(90))
    ssubcaste=db.Column(db.String(100))
    scategory=db.Column(db.String(30))
    saddre=db.Column(db.String(500))
    sstate=db.Column(db.String(100))
    spcode=db.Column(db.String(100))
    fname=db.Column(db.String(50))
    mname=db.Column(db.String(50))
    fnum=db.Column(db.String(50))
    focc=db.Column(db.String(50))
    mocc=db.Column(db.String(50))

class Acadinfo(UserMixin,db.Model):
    acid=db.Column(db.Integer,primary_key=True)
    icname=db.Column(db.String(100))
    lclass=db.Column(db.String(100))
    lqexam=db.Column(db.String(255))
    pmy=db.Column(db.String(100))
    tmark=db.Column(db.Integer())
    omark=db.Column(db.Integer())
    leper=db.Column(db.Integer())
    lexamr=db.Column(db.String(100))

class Courses(UserMixin,db.Model):
    cid=db.Column(db.Integer, primary_key=True)
    stream=db.Column(db.String(100))
    course=db.Column(db.String(100))
    classes=db.Column(db.String(100))

class upload_adhar(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    filename1=db.Column(db.String(100))
    filedata1=db.Column(db.LargeBinary)

class upload_caste_certificate(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    filename3=db.Column(db.String(100))
    filedata3=db.Column(db.LargeBinary)

class upload_domi(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    filename5=db.Column(db.String(100))
    filedata5=db.Column(db.LargeBinary)

class upload_last_exam(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    filename2=db.Column(db.String(100))
    filedata2=db.Column(db.LargeBinary)

class upload_photo(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    filename=db.Column(db.String(100))
    filedata=db.Column(db.LargeBinary)

class upload_sign(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    filename4=db.Column(db.String(100))
    filedata4=db.Column(db.LargeBinary)

class fees(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    sname=db.Column(db.String(100))
    semail=db.Column(db.String(100))

class approval(UserMixin, db.Model):
    id=db.Column(db.Integer, primary_key=True)
    approved=db.Column(db.Boolean)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/alert')
def alert_popup():
    # Retrieve the flashed message
    message = get_flashed_messages()

    # Display the message in an alert pop-up
    return f'''
        <script>
            alert("{message}");
            window.history.back();
        </script>
    '''

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/admission')
def admission():
    return render_template("admission.html")

@app.route('/contact')
def contact():
    return render_template("contact.html")

@app.route('/sign')
def sign():
    return render_template("sign.html")



@app.route('/adminlogin', methods =['GET', 'POST'])
def adminlogin():
    message = ''
    if request.method == 'POST' and 'email' in request.form and 'password' in request.form:
        email = request.form['email']
        password = request.form['password']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM adminlog WHERE email = % s AND password = % s', (email, password, ))
        admin = cursor.fetchone()
        if admin:
            session['loggedin'] = True
            session['aid'] = admin['aid']
            session['adminname'] = admin['adminname']
            session['email'] = admin['email']
            message = 'Logged in successfully !'
            return render_template('adminuser.html', message = message)
        else:
            message = 'Please enter correct email / password !'
    return render_template('adminlogin.html', message = message)

@app.route('/adminlogout')
def logoutadmin():
    session.pop('loggedin', None)
    session.pop('aid', None)
    session.pop('email', None)
    return redirect(url_for('adminlogin'))

def is_human(captcha_response):
    """ Validating recaptcha response from google server
        Returns True captcha test passed for submitted form else returns False.
    """
    secret = "6Lclfa8kAAAAAE5SMf2HY1uiyrhuzaO3s38qKymU"
    payload = {'response':captcha_response, 'secret':secret}
    response = requests.post("https://www.google.com/recaptcha/api/siteverify", payload)
    response_text = json.loads(response.text)
    return response_text['success']

@app.route('/signup',methods=['POST','GET'])
def signup():
    sitekey = "6Lclfa8kAAAAADgvaNkYXlL6S_Q4w4zLGSHG4q-A"
    if request.method == "POST":
        username=request.form.get('username')
        contact=request.form.get('contact')
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()
        if user:
            flash("Email Already Exist","warning")
            return render_template('/register.html')
        encpassword=generate_password_hash(password)
        user=User.query.filter_by(contact=contact).first()
        if user:
            flash("contact Already Exist","warning")
            return render_template('/register.html')
        captcha_response = request.form['g-recaptcha-response']

        if is_human(captcha_response):
            # Process request here
            status = "Detail submitted successfully."
        else:
             # Log invalid attempts
            status = "Sorry ! Please Check Im not a robot."


        new_user=db.engine.execute(f"INSERT INTO `user` (`username`,`contact`,`email`,`password`) VALUES ('{username}','{contact}','{email}','{encpassword}')")

        # this is method 2 to save data in db
        # newuser=User(username=username,email=email,password=encpassword)
        # db.session.add(newuser)
        # db.session.commit()
        flash("Signup Succes Please Login","success")
        return render_template('login.html')
    return render_template('register.html',sitekey=sitekey)

@app.route('/login',methods=['POST','GET'])
def login():
    if request.method == "POST":
        email=request.form.get('email')
        password=request.form.get('password')
        user=User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password,password):
            login_user(user)
            flash("Login Success","primary")
            session['username']=username=user.username
            session['email']=email=user.email
            session['id']=id=user.id
            return render_template('user.html', username=username, email=email)
        else:
            flash("invalid credentials","danger")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/userstu')
def userstu():
    username=session.get('username')
    return render_template("user.html",username=username)

@app.route('/payment', methods=['POST'])
def payment():
    username=session.get('username')
    email=session.get('email')
    id=session.get('id')
    new_user=db.engine.execute(f"INSERT INTO `fees`(`id`,`sname`,`semail`)values('{id}', '{username}','{email}')")
    return render_template('thankyou.html')

@app.route('/thankyou')
def thankyou():
    username=session.get('username')
    email=session.get('email')
    id=session.get('id')

    return render_template("user.html", username=username)
    

@app.route('/feerec',methods=['POST','GET'])
def feer():
    id=session.get('id')
    query=db.engine.execute(f"SELECT id,sname,semail FROM `fees` where id=id")
    return render_template('feer.html',query=query)

@app.route('/forgot_password')
def forgot_password():
    return render_template("forgotpassword.html")

@app.route('/verify',methods=["POST"])
def verify():
    email=request.form['email']
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('user is not registered')
        return redirect(url_for('alert_popup'))
    msg=Message(subject='OTP',sender='adityatanvoji@gmail.com',recipients=[email])
    msg.body=str(otp)
    mail.send(msg)
    return render_template('verify.html', data=email)

@app.route('/validate',methods=['POST'])
def validate():
    user_otp=request.form['otp']
    email=request.form['email']
    if otp==int(user_otp):
        return render_template('resetpassword.html', data=email)
    return "<h3>Please Try Again</h3>"

@app.route('/reset_password', methods=['POST'])
def reset_password():
    email=request.form['email']
    password = request.form['password']
    confirm_password = request.form['confirm-password']
    if password == confirm_password:
        password=request.form.get('password')
        encpassword=generate_password_hash(password)
        query = "UPDATE `user` SET `password`=%s WHERE `email`=%s"
        db.engine.execute(query, (encpassword, email))
        return render_template('login.html')
    else:
        flash('Passwords does not match.')
        return render_template('resetpassword.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logout SuccessFul","warning")
    return redirect(url_for('login'))

@app.route("/user_pd", methods=['GET', 'POST'])
def user_pd():
    username=session.get('username')
    pid = User.query.filter_by(username=username).first().id
    pinfo = personalinfo.query.filter_by(sid=pid).first()
    if request.form.get('action2') == 'next':
        sname=request.form.get('stud')
        semail=request.form.get('email')
        scon=request.form.get('num')
        sgender=request.form.get('radio_option')
        sdob=request.form.get('DOB')
        sbirthp=request.form.get('POB')
        snationality=request.form.get('nation')
        shandicap=request.form.get('hand')
        sreligion=request.form.get('religion')
        scaste=request.form.get('caste')
        ssubcaste=request.form.get('scaste')
        scategory=request.form.get('cat')
        saddre=request.form.get('add')
        sstate=request.form.get('state')
        spcode=request.form.get('pin')
        fname=request.form.get('father')
        mname=request.form.get('mother')
        fnum=request.form.get('fnum')
        focc=request.form.get('focc')
        mocc=request.form.get('mocc')
        id=session.get('id')
        user_id = User.query.filter_by(email=semail).first().id

        new_user=db.engine.execute(f"INSERT INTO `personalinfo`(`sid`,`sname`,`semail`,`scon`,`sgender`,`sdob`,`sbirthp`,`snationality`,`shandicap`,`sreligion`,`scaste`,`ssubcaste`,`scategory`,`saddre`,`sstate`,`spcode`,`fname`,`mname`,`fnum`,`focc`,`mocc`)VALUES ('{user_id}', '{sname}','{semail}','{scon}','{sgender}','{sdob}','{sbirthp}','{snationality}','{shandicap}','{sreligion}','{scaste}','{ssubcaste}','{scategory}','{saddre}','{sstate}','{spcode}','{fname}','{mname}','{fnum}','{focc}','{mocc}')")


        return render_template('useracademics.html', data=user_id)
    elif  request.form.get('action1') == 'back':
        return render_template('user.html',username=username)
    else:
        pass # unknown
    # if user personal info exist redirect to view page
    if pinfo:
        id=session.get('id')
        user_info = User.query.filter_by(id=id).first()
        personal_info = personalinfo.query.filter_by(sid=id).first()
        acad_info = Acadinfo.query.filter_by(acid=id).first()
        course_info=Courses.query.filter_by(cid=id).first()
        #query=db.engine.execute(f"SELECT sid,sname,semail,scon,sgender,sdob,sbirthp,snationality,shandicap,sreligion,scaste,ssubcaste,scategory,saddre,sstate,spcode,fname,mname,fnum,focc,mocc FROM `personalinfo` where id=id")
        return render_template("userpdview.html", userinfo=user_info, personalinfo=personal_info, acadinfo=acad_info,couseinfo=course_info)
    return render_template("userpd.html")

@app.route("/user_academics", methods=['GET', 'POST'])
def user_academics():
    if request.form.get('action2') == 'next':
        acid=request.form.get('acid')
        icname=request.form.get('iname')
        lclass=request.form.get('cls')
        lqexam=request.form.get('qexam')
        pmy=request.form.get('my')
        tmark=request.form.get('TM')
        omark=request.form.get('OM')
        leper=request.form.get('percent')
        lexamr=request.form.get('result')
        user_id=request.form.get('user-id')
        new_user=db.engine.execute(f"INSERT INTO `acadinfo`(`acid`,`icname`,`lclass`,`lqexam`,`pmy`,`tmark`,`omark`,`leper`,`lexamr`)Values ('{user_id}','{icname}','{lqexam}','{lclass}','{pmy}','{tmark}','{omark}','{leper}','{lexamr}')")

        return render_template('courses.html',data=user_id)
    elif  request.form.get('action1') == 'back':
        username=session.get('username')
        return render_template('userpd.html',)
    else:
        pass # unknown
    return render_template("useracademics.html")

@app.route('/courses', methods=['GET', 'POST'])
def courses():
    if request.form.get('action2') == 'next':
        stream=request.form.get('Strems[]')
        course=request.form.get('courses[]')
        classes= request.form.get('class[]')
        user_id=session.get('id')
        new_user=db.engine.execute(f"INSERT INTO `courses`(`cid`,`stream`,`course`,`classes`)Values ('{user_id}','{stream}','{course}','{classes}')")

        return render_template('userdoc.html',data=user_id)
    elif  request.form.get('action1') == 'back':
        return render_template('useracademics.html')
    else:
        pass # unknown
    return render_template("courses.html")


@app.route("/upload_image", methods=['GET', 'POST'])
def upload_image():
    if request.form.get('action2') == 'next':
        user_id=request.form.get('user-id')
        image = request.files['imagename']
        filename=image.filename
        filedata = bytes(image.read())
        image1 = request.files['imagename1']
        filename1=image1.filename
        filedata1 = bytes(image1.read())
        image2 = request.files['imagename2']
        filename2=image2.filename
        filedata2 = bytes(image2.read())
        image3 = request.files['imagename3']
        filename3=image3.filename
        filedata3 = bytes(image3.read())
        image4 = request.files['imagename4']
        filename4=image4.filename
        filedata4 = bytes(image4.read())
        image5 = request.files['imagename5']
        filename5=image5.filename
        filedata5 = bytes(image5.read())
        username=request.form.get('username')
        cursor.execute("INSERT INTO upload_photo  (id,filename,filedata) VALUES (%s,%s,%s)", (user_id,filename,filedata))
        cursor.execute("INSERT INTO upload_adhar  (id,filename1,filedata1) VALUES (%s,%s,%s)", (user_id,filename1,filedata1))
        cursor.execute("INSERT INTO upload_last_exam  (id,filename2,filedata2) VALUES (%s,%s,%s)", (user_id,filename2,filedata2))
        cursor.execute("INSERT INTO upload_caste_certificate  (id,filename3,filedata3) VALUES (%s,%s,%s)", (user_id,filename3,filedata3))
        cursor.execute("INSERT INTO upload_sign  (id,filename4,filedata4) VALUES (%s,%s,%s)", (user_id,filename4,filedata4))
        cursor.execute("INSERT INTO upload_domi  (id,filename5,filedata5) VALUES (%s,%s,%s)", (user_id,filename5,filedata5))
        cursor.execute("INSERT INTO approval (id, approved) VALUES (%s, %s)", (user_id, 0))
        dbd.commit()
        return render_template('user.html',data=username)
    elif  request.form.get('action1') == 'back':
        return render_template('courses.html')
    else:
        pass # unknown
    return render_template("userdoc.html")

@app.route('/fee')
def ufee():
    return render_template('ufee.html', public_key=public_key)

@app.route('/a')
def indexa():
    return render_template("adminuser.html")


@app.route('/studentdetails')
def studentdetails():
    query=db.engine.execute(f"SELECT sid,sname,scon,fnum,saddre,sdob,shandicap,scaste,scategory FROM `personalinfo`")
    classess=Acadinfo.query.with_entities(Acadinfo.acid, Acadinfo.lclass).all()
    for classes in classess:
        print(classes.lclass)
    zipped = zip(query, classess)
    return render_template('studentdetails.html',zipped=zipped)

@app.route('/pending', methods=['POST', 'GET'])
def pending():
    acadinfo = db.session.query(Acadinfo).join(approval, approval.id == Acadinfo.acid).filter(approval.approved == False).all()
    students = db.session.query(personalinfo.sname).join(approval, approval.id == personalinfo.sid).filter(approval.approved == False).all()
    zipped = zip(acadinfo, students)
    return render_template("pending.html", zipped=zipped)

@app.route('/approve_form', methods=['POST'])
def approve_form():
    id = request.form.get('id')
    query=db.engine.execute(f"UPDATE approval set `approved`=1 WHERE id='{id}'")
    return redirect(url_for('pending'))

@app.route('/image/view/<string:image_of>/<int:image_id>')
def image_view(image_of, image_id):
    if image_of == "photo":
        image = upload_photo.query.get(image_id)
        response = make_response(image.filedata)
        response.headers.set('Content-Type', 'image/jpeg')
        response.headers.set('Content-Disposition', 'attachment', filename='image.jpeg')
        return response
    elif image_of == "sign":
        image = upload_sign.query.get(image_id)
        response = make_response(image.filedata4)
        response.headers.set('Content-Type', 'image/jpeg')
        response.headers.set('Content-Disposition', 'attachment', filename='image.jpeg')
        return response
    elif image_of == "adhar":
        image = upload_adhar.query.get(image_id)
        response = make_response(image.filedata1)
        response.headers.set('Content-Type', 'image/jpeg')
        response.headers.set('Content-Disposition', 'attachment', filename='image.jpeg')
        return response
    elif image_of == "result":
        image = upload_last_exam.query.get(image_id)
        response = make_response(image.filedata2)
        response.headers.set('Content-Type', 'image/jpeg')
        response.headers.set('Content-Disposition', 'attachment', filename='image.jpeg')
        return response
    elif image_of == "domecile":
        image = upload_domi.query.get(image_id)
        response = make_response(image.filedata5)
        response.headers.set('Content-Type', 'image/jpeg')
        response.headers.set('Content-Disposition', 'attachment', filename='image.jpeg')
        return response
    else:
        image = upload_caste_certificate.query.get(image_id)
        response = make_response(image.filedata3)
        response.headers.set('Content-Type', 'image/jpeg')
        response.headers.set('Content-Disposition', 'attachment', filename='image.jpeg')
        return response

@app.route('/approved')
def approved():
    acadinfo = db.session.query(Acadinfo).join(approval, approval.id == Acadinfo.acid).filter(approval.approved == True).all()
    students = db.session.query(personalinfo.sname).join(approval, approval.id == personalinfo.sid).filter(approval.approved == True).all()
    zipped = zip(acadinfo, students)
    return render_template("approved.html", zipped=zipped)


@app.route('/fee1')
def fee():
    id=session.get('id')
    query=db.engine.execute(f"SELECT id,sname,semail FROM `fees`")
    return render_template("fee.html",query=query)



if __name__ == '__main__':
    app.debug = True
app.run(host="0.0.0.0")
