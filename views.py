from findARestaurant import findARestaurant
from models import Base, Restaurant, User
from flask import Flask, jsonify, request, abort,url_for,g
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine
import os
import sys
import codecs
#from flask.ext.httpauth import HTTPBasicAuth
from flask_httpauth import HTTPBasicAuth


sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)

foursquare_client_id = os.environ['sqClientId']

foursquare_client_secret = os.environ['sqClientSecret']

google_api_key = os.environ['google_api_key']

engine = create_engine('sqlite:///restaurantWithUser.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

app = Flask(__name__)
auth = HTTPBasicAuth()



@auth.verify_password
def verify_password(username, password):
    user = session.query(User).filter_by(username=username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True


@app.route('/users', methods = ['POST'])
def new_user():
    # username = request.get_json('username')
    # password = request.get_json('password')
    username = request.args.get('username','')
    password = request.args.get('password','')
    if username is None or password is None:
        abort(400) # missing arguments
    if session.query(User).filter_by(username = username).first() is not None:
        print "User already exists"
        return jsonify({"message","user already exits"}), 200 # existing user
    user = User(username = username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({ 'username': user.username }), 201, {'Location': url_for('get_user', id = user.id, _external = True)}

@app.route('/api/users/<int:id>')
def get_user(id):
    user = session.query(User).filter_by(id=id).one()
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@app.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data':"Hello, %s!" %g.user.username})

@app.route('/show', methods=['GET'])
def show(): #just show users
    users = session.query(User).all()
    for i in users:
        print i.username, i.password_hash
    return 'ok'

@app.route('/restaurants', methods = ['GET', 'POST'])
def all_restaurants_handler():
  if request.method == 'GET':
  	# RETURN ALL RESTAURANTS IN DATABASE
  	restaurants = session.query(Restaurant).all()
  	return jsonify(restaurants = [i.serialize for i in restaurants])

  elif request.method == 'POST':
  	# MAKE A NEW RESTAURANT AND STORE IT IN DATABASE
    location = request.args.get('location', '')
    mealType = request.args.get('mealType', '')
    restaurant_info = findARestaurant(mealType, location)
    if restaurant_info != "No Restaurants Found":
      restaurant = Restaurant(restaurant_name = unicode(restaurant_info['name']), restaurant_address = unicode(restaurant_info['address']), restaurant_image = restaurant_info['image'])
      session.add(restaurant)
      session.commit()
      return jsonify(restaurant = restaurant.serialize)
    else:
      return jsonify({"error":"No Restaurants Found for %s in %s" % (mealType, location)})

@app.route('/restaurants/<int:id>', methods = ['GET','PUT', 'DELETE'])
def restaurant_handler(id):
  restaurant = session.query(Restaurant).filter_by(id = id).one()
  if request.method == 'GET':
  	#RETURN A SPECIFIC RESTAURANT
  	return jsonify(restaurant = restaurant.serialize)
  elif request.method == 'PUT':
  	#UPDATE A SPECIFIC RESTAURANT
  	address = request.args.get('address')
  	image = request.args.get('image')
  	name = request.args.get('name')
  	if address:
  		restaurant.restaurant_address = address
  	if image:
  		restaurant.restaurant_image = image
  	if name:
  		restaurant.restaurant_name = name
  	session.commit()
  	return jsonify(restaurant = restaurant.serialize)

  elif request.method == 'DELETE':
  	#DELETE A SPECFIC RESTAURANT
  	session.delete(restaurant)
  	session.commit()
  	return "Restaurant Deleted"

if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
