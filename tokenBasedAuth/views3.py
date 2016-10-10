
from models import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
import os
import json
import requests
from flask_httpauth import HTTPBasicAuth
auth = HTTPBasicAuth()


engine = create_engine('sqlite:///usersWithTokens.db')

#Google Imports

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
from flask import make_response


Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)


CLIENT_ID = os.environ['google_client_id']

@auth.verify_password
def verify_password(username_or_token,password):
    #Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id = user_id).one()
    else:
        user = session.query(User).filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True

@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')

@app.route('/oauth/<provider>',methods=['POST'])
def login(provider):
    print '----------'
    print 'login part'
    #STEP1 - Parse the auth Code
    #auth_code = request.json.get('auth_code')
    #auth_code = request.args.get('auth_code')
    auth_code = request.data

    print 'Step 1 Complete, received auth code %s' %auth_code
    if provider == 'google':
        #STEP2 exchange for a token
        try:
            #Upgrade the auth code into a credentials object
            oauth_flow = flow_from_clientsecrets('client_secret.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except:
            response = make_response(json.dumps('Failed to upgrade the authotization code'),401)
            response.headers['Content-Type'] = 'application/json'
            return response

        #Check that the access token is valid
        access_token = credentials.access_token
        print 'access Token: %s' %access_token
        url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
        h = httplib2.Http()
        result = json.loads(h.request(url,'GET')[1])
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        print "Step 2 Complete! Access Token : %s " % credentials.access_token

        #STEP 3 - Find User or make a new one

        h = httplib2.Http()
        userinfo_url =  "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt':'json'}
        answer = requests.get(userinfo_url, params=params)

        data = answer.json()

        name = data['name']
        picture = data['picture']
        email = data['email']

        #see if user exists, if it doesn't make a new one

        user = session.query(User).filter_by(email=email).first()
        if not user:
            user = User(username=name,picture=picture,email=email)
            session.add(user)
            session.commit()


       #STEP 4 - Make our token
        token = user.generate_auth_token(600)

       #STEP 5 - Send back token to the client
        print '---------'
        print 'MY-APP Access Token %s' %token
        return jsonify({'token':token.decode('ascii')})

    else:
       return 'Unrecoginized provider'

@app.route('/show')
def show_users():
    users = session.query(User).all()
    for i in users:
        print i.email,i.id,i.password_hash
    return 'ok'

@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token':token.decode('ascii')})


@app.route('/users', methods = ['POST'])
def new_user():
    username = request.args.get('username')
    password = request.args.get('password')
    if username is None or password is None:
        print "missing arguments"
        abort(400)

    if session.query(User).filter_by(username = username).first() is not None:
        print "existing user"
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message':'user already exists'}), 200#, {'Location': url_for('get_user', id = user.id, _external = True)}

    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201#, {'Location': url_for('get_user', id = user.id, _external = True)}


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({ 'data': 'Hello, %s!' % g.user.username })



if '__main__' == __name__:
    app.debug = True
    app.run(host = '0.0.0.0', port = 5000)
