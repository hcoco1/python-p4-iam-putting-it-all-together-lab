#!/usr/bin/env python3

# Import necessary modules from the Flask and Flask-RESTful libraries
from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

# Import application configurations, database object, and API object 
# from the config module
from config import app, db, api

# Import the User and Recipe models from the models module
from models import User, Recipe

# Define a Signup resource for registering new users
class Signup(Resource):
    def post(self):
        # Get the JSON payload from the request
        json = request.get_json()
        
        # Check if username is provided in the JSON payload
        try:
            json['username']
        except KeyError:    
            return {"Message":"Unprocessable Entity" }, 422

        # Check if image_url is provided; if not, create a user without an image
        try:
            json['image_url']
        except KeyError:    
            user = User(username=json['username'])
        else:
            user = User(
                username=json['username'],
                image_url=json['image_url'],
                bio=json['bio']
            )
        
        # Set the password hash for the user and add the user to the database
        user.password_hash = json['password']
        db.session.add(user)
        db.session.commit()

        # Set the user ID in the session to indicate the user is logged in
        session['user_id'] = user.id

        # Return the newly created user's details with a 201 Created status
        return {
            "id" : user.id,
            "username" : user.username,
            "image_url" : user.image_url,
            "bio" : user.bio
        }, 201

# Define a resource to check the session for the logged-in user's details
class CheckSession(Resource):
    def get(self):
        # Get the user from the database using the user ID in the session
        user = User.query.filter(User.id == session.get('user_id')).first()
        
        if user:
            # If user is found, return the user's details with a 200 OK status
            return {
                "id" : user.id,
                "username" : user.username,
                "image_url" : user.image_url,
                "bio" : user.bio
            }, 200
        else:
            # If no user is found, return an unauthorized message with a 401 status
            return {"Message": "Unauthorized"}, 401

# Define a Login resource for user authentication
class Login(Resource):
    def post(self):
        # Get the username from the JSON payload and fetch the user from the database
        username = request.get_json()['username']
        user = User.query.filter(User.username == username).first()

        # If user is found and the password is correct, log the user in
        if user:
            password = request.get_json()['password']
            if user.authenticate(password):
                session['user_id'] = user.id
                return {
                    "id" : user.id,
                    "username" : user.username,
                    "image_url" : user.image_url,
                    "bio" : user.bio
                }, 201

        # If authentication fails, return an error message with a 401 Unauthorized status
        return {'error': 'Invalid username or password'}, 401

# Define a Logout resource to clear the session and log out the user
class Logout(Resource):
    def delete(self):
        # Check if a user is logged in and then log them out
        if session.get("user_id"):
            session['user_id'] = None
            return {}, 204

        # If no user is logged in, return an unauthorized message with a 401 status
        return {"message": "unauthorized"}, 401

# Define a RecipeIndex resource for managing recipes
class RecipeIndex(Resource):
    def get(self):
        # Fetch the logged-in user from the database
        user = User.query.filter(User.id == session.get('user_id')).first()

        # If user is found, return all recipes with a 200 OK status
        if user:
            recipes = [recipe.to_dict() for recipe in Recipe.query.all()]
            return (recipes), 200
        else:
            # If no user is found, return an unauthorized message with a 401 status
            return {"message": "unauthorized"}, 401

    def post(self):
        # Fetch the logged-in user from the database
        user = User.query.filter(User.id == session.get('user_id')).first()
        
        # If user is found, try to create a new recipe
        if user:
            json = request.get_json()

            try:
                recipe = Recipe(
                    title = json['title'],
                    instructions = json['instructions'],
                    minutes_to_complete = json['minutes_to_complete'],
                    user_id = session['user_id']
                )
                db.session.add(recipe)
                db.session.commit()
            except IntegrityError:
                # If there's a database error, return an error message with a 422 status
                return {"message": "Unprocessable Entity"}, 422  

            # Return the newly created recipe's details with a 201 Created status
            return {
                "title" : recipe.title,
                "instructions" : recipe.instructions,
                "minutes_to_complete" : recipe.minutes_to_complete,
                "user_id" : recipe.user_id       
            }, 201
        else:
            # If no user is found, return an unauthorized message with a 401 status
            return {"message": "unauthorized"}, 401

# Add each resource to the API with its corresponding endpoint
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

# Run the Flask application when the script is executed directly
if __name__ == '__main__':
    app.run(port=5555, debug=True)
