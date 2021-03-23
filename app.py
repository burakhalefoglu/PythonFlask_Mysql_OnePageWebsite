from flask import Flask, render_template, flash, redirect, url_for, session, logging, request, jsonify, make_response
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth

from flask_restful import Api
from flask_jwt_extended import (JWTManager, jwt_required,
                                jwt_refresh_token_required,
                                jwt_optional, fresh_jwt_required,
                                get_raw_jwt, get_jwt_identity,
                                create_access_token, create_refresh_token,
                                set_access_cookies, set_refresh_cookies,
                                unset_jwt_cookies, unset_access_cookies)

from datetime import timedelta
import string
import random
import math
import uuid
import os

LETTERS = string.ascii_letters
NUMBERS = string.digits
PUNCTUATION = string.punctuation


#os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__, static_url_path='/static')

# Secret key Config
app.config['SECRET_KEY'] = "mysupersecretkeymysupersecretkeymysupersecretkey"
app.config['BASE_URL'] = 'http://127.0.0.1:5000'  # Running on localhost
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
app.config['JWT_ACCESS_COOKIE_PATH'] = ['/dashboard', '/']
app.config['PROPAGATE_EXCEPTIONS'] = True


# MySql Config
app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = ""
app.config["MYSQL_DB"] = "dbname"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"
app.config["FLASK_HTPASSWD_PATH"] = '/secret/.htpasswd'


# Mail Config
app.config["MAIL_SERVER"] = "xxx.xxx.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USE_TLS"] = False
app.config["MAIL_USERNAME"] = "xxx@xxx.com"
app.config["MAIL_PASSWORD"] = 'xxxxxxxx'

# Sing in With Config
app.config['GOOGLE_CLIENT_ID'] = "xxx"
app.config['GOOGLE_CLIENT_SECRET'] = "xxx"
app.config['GITHUB_CLIENT_ID'] = "xxx"
app.config['GITHUB_CLIENT_SECRET'] = "xxx"


mysql = MySQL(app)
mail = Mail(app)
oauth = OAuth(app)
jwt = JWTManager(app)


Global_HaveToLogin = False
Check_Login_page = False
PostFail = False
SeccionLog = False
Resetfail = False
ResetHavetoBool = False


@jwt.unauthorized_loader
def unauthorized_callback(callback):
    # No auth header
    flash(message="You must be logged in.", category="danger")
    global Check_Login_page
    global ResetHavetoBool
    Check_Login_page = True
    ResetHavetoBool = True
    return redirect(url_for('index', HaveToLogin=Check_Login_page))


@jwt.invalid_token_loader
def invalid_token_callback(callback):
    # Invalid Fresh/Non-Fresh Access token in auth header
    flash(message="You must be logged in.", category="danger")
    global Check_Login_page
    global ResetHavetoBool
    Check_Login_page = True
    ResetHavetoBool = True
    resp = make_response(
        redirect(url_for('index', HaveToLogin=Check_Login_page)))
    unset_jwt_cookies(resp)
    return resp, 302


@jwt.expired_token_loader
def expired_token_callback(callback):
    # Expired auth header
    resp = make_response(redirect(app.config['BASE_URL'] + '/token/refresh'))
    unset_access_cookies(resp)
    return resp, 302


@app.route('/token/refresh', methods=['GET'])
@jwt_refresh_token_required
def refresh():
    # Refreshing expired Access token
    user_id = get_jwt_identity()
    access_token = create_access_token(identity=str(user_id))
    resp = make_response(redirect(app.config['BASE_URL'] + '/', 302))
    set_access_cookies(resp, access_token)
    return resp


def assign_access_refresh_tokens(user_id, url):
    access_token = create_access_token(identity=str(user_id), fresh=True)
    refresh_token = create_refresh_token(identity=str(user_id))
    resp = make_response(redirect(url, 302))
    set_access_cookies(resp, access_token)
    set_refresh_cookies(resp, refresh_token)
    return resp


def unset_jwt():
    resp = make_response(redirect(app.config['BASE_URL'] + '/', 302))
    unset_jwt_cookies(resp)
    return resp


@app.route("/", methods=['GET', 'POST'])
@jwt_optional
def index():
    username = get_jwt_identity()
    if username != None:
        return redirect(url_for('dashboard'))

    if(request.method == "POST"):
        return PostMessage()
    else:
        return GetMessage()


def PostMessage():
    if(request.form['LoginId'] == "1"):
        return logindef()
    elif(request.form['LoginId'] == "2"):
        return registerdef()
    else:
        return Forgetdef()


def GetMessage():
    global Global_HaveToLogin
    global Check_Login_page
    global PostFail
    global Resetfail
    global ResetHavetoBool
    title = "From data to game experience"
    Check_Login_page = False
    PostFail = False
    Resetfail = False
    if(ResetHavetoBool):
        ResetHavetoBool = False
        Global_HaveToLogin = True
    else:
        Global_HaveToLogin = False

    return render_template("index.html", title=title, Resetfail=Resetfail, HaveToLogin=Global_HaveToLogin, PostFail=PostFail)


def registerdef():
    global PostFail
    global SeccionLog

    companyname = request.form['CompanyName']
    email = request.form['Email']
    password = sha256_crypt.encrypt(request.form['Password'])

    cursor = mysql.connection.cursor()
    Fsorgu = " SELECT * FROM users WHERE email = %s"
    result = cursor.execute(Fsorgu, (email,))

    if(result > 0):
        flash(message="This user already exists!", category="warning")
        PostFail = True
        return render_template("index.html", PostFail=PostFail)

    else:
        Rsorgu = "INSERT INTO users (companyname,email,password,customerid,token) VALUES(%s,%s,%s,%s,%s)"
        customerid = RandomNumber(64)
        forgetPassToken = RandomNumber(64)
        # ,createcustomerid(),createtoken()))
        cursor.execute(Rsorgu, (companyname, email, password,
                                customerid, forgetPassToken))
        mysql.connection.commit()
        cursor.close()
        flash(message="The registration was successful ...", category="success")
        PostFail = False
        return assign_access_refresh_tokens(customerid, app.config['BASE_URL'] + '/dashboard')


def logindef():
    global Check_Login_page
    global SeccionLog
    global ResetHavetoBool
    email = request.form['Email']
    entered_password = request.form['Password']
    cursor = mysql.connection.cursor()
    Lsorgu = " SELECT * FROM users WHERE email = %s "
    result = cursor.execute(Lsorgu, (email,))
    if(result > 0):
        data = cursor.fetchone()
        ınDbPasw = data["password"]
        if sha256_crypt.verify(entered_password, ınDbPasw):
            flash(message="The login was successful...", category="success")
            return assign_access_refresh_tokens(data["customerid"], app.config['BASE_URL'] + '/dashboard')

        else:
            ResetHavetoBool = True
            flash(message="Username or password is wrong.", category="danger")
            Check_Login_page = True
            return render_template("index.html", HaveToLogin=Check_Login_page)

    else:
        flash(message="There is no such user.", category="danger")
        Check_Login_page = True
        return render_template("index.html", HaveToLogin=Check_Login_page)


def Forgetdef():
    global Resetfail
    global Check_Login_page
    global ResetHavetoBool
    email = request.form['Email']
    token = str(uuid.uuid4())
    cursor = mysql.connection.cursor()
    Fsorgu = " SELECT * FROM users WHERE email = %s"
    result = cursor.execute(Fsorgu, (email,))
    if(result > 0):
        data = cursor.fetchone()
        msg = Message(subject="Forgot password request ",
                      sender="resetmail@appneuron.com", recipients=[email])
        msg.html = render_template("MailTemplate.html", token=token, data=data)
        mail.send(msg)
        cursor = mysql.connection.cursor()
        Fsorgu = "UPDATE users SET token =%s WHERE email=%s"
        result = cursor.execute(Fsorgu, (token, email))
        mysql.connection.commit()
        cursor.close()
        flash(message="The password reset link has been sent to your e-mail.",
              category="success")
        ResetHavetoBool = True
        Check_Login_page = True
        return render_template("index.html", HaveToLogin=Check_Login_page)
    else:
        Resetfail = True
        flash(message="The e-mail not exist", category="danger")
        return render_template("index.html", Resetfail=Resetfail)


@app.route("/reset/<token>", methods=['GET', 'POST'])
def reset(token):
    global Check_Login_page
    global ResetHavetoBool
    if(request.method == "POST"):
        password = sha256_crypt.encrypt(request.form['password'])
        token1 = str(uuid.uuid4())
        cursor = mysql.connection.cursor()
        ResetSorgu = "SELECT * FROM users WHERE token =%s"
        cursor.execute(ResetSorgu, (token,))
        user = cursor.fetchone()
        if user:
            cursor = mysql.connection.cursor()
            Fsorgu = "UPDATE users SET token=%s, password=%s Where token=%s"
            cursor.execute(Fsorgu, (token1, password, token))
            mysql.connection.commit()
            cursor.close()
            flash(message="Your password successfuly updated", category="success")
            Check_Login_page = True
            ResetHavetoBool = True
            return redirect(url_for('index', HaveToLogin=Check_Login_page))

        else:
            flash(message="Your token is invalid", category="danger")
            Check_Login_page = True
            ResetHavetoBool = True
            return redirect(url_for('index', HaveToLogin=Check_Login_page))
    else:
        return render_template("reset.html")


############################# Sing in With #######################################
google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    # This is only needed if using openId to fetch user info
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)


# Google login route
@app.route('/login/google')
def google_login():
    google = oauth.create_client('google')
    redirect_uri = url_for('google_authorize', _external=True)
    return google.authorize_redirect(redirect_uri)


# Google authorize route
@app.route('/login/google/authorize')
def google_authorize():
    global Check_Login_page
    global SeccionLog
    global ResetHavetoBool
    global PostFail
    google = oauth.create_client('google')
    googletoken = google.authorize_access_token()
    print(googletoken)
    resp = google.get('userinfo').json()
    if resp["id"] != "":
        cursor = mysql.connection.cursor()
        Fsorgu = " SELECT * FROM users WHERE email = %s"
        result = cursor.execute(Fsorgu, (resp["email"],))

        if(result > 0):
            data = cursor.fetchone()
            PostFail = False
            return assign_access_refresh_tokens(data["customerid"], app.config['BASE_URL'] + '/dashboard')

        else:
            Rsorgu = "INSERT INTO users (companyname,email,password,customerid,token) VALUES(%s,%s,%s,%s,%s)"
            customerid = RandomNumber(64)
            forgetPassToken = RandomNumber(64)
            password = sha256_crypt.encrypt(RandomNumber(64))
            cursor.execute(Rsorgu, (resp["name"].replace(
                " ", ""), resp["email"], password, customerid, forgetPassToken))
            mysql.connection.commit()
            cursor.close()
            flash(message="The registration was successful ...", category="success")
            PostFail = False
            return assign_access_refresh_tokens(customerid, app.config['BASE_URL'] + '/dashboard')

    else:
        flash(message="something went wrong. Please try again later!",
              category="danger")
        Check_Login_page = True
        ResetHavetoBool = True
        return redirect(url_for('index', HaveToLogin=Check_Login_page))

###########################################################################


@app.route('/logout')
@jwt_required
def logout():
    return unset_jwt(), 302


@app.route("/dashboard", methods=['GET', 'POST'])
@fresh_jwt_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/terms")
def TermAndCondition():
    return render_template("TermAndCondition.html")


def RandomNumber(length):

    printable = f'{LETTERS}{NUMBERS}{PUNCTUATION}'

    # convert printable from string to list and shuffle
    printable = list(printable)
    random.shuffle(printable)

    # generate random password and convert to string
    random_password = random.choices(printable, k=length)
    random_password = ''.join(random_password)
    return random_password


if __name__ == "__main__":
    app.run(debug=True)
