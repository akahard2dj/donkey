from flask import g, jsonify, abort, request
from flask_restful import Resource
from app import db

from app.models.user import EncryptedUser as User
from app.api_1_0.authentication import auth

import random
import string


class UsersApi(Resource):
    def post(self):
        useremail = request.json.get('useremail')
        password = request.json.get('password')
        username = request.json.get('username')

        if useremail is None or password is None:
            abort(400)
        if User.query.filter_by(user_email=useremail).first() is not None:
            abort(401)

        random_user_name = ''.join(random.SystemRandom()
                                   .choice(string.ascii_uppercase + string.digits + string.ascii_lowercase)
                                   for _ in range(7))
        user = User(user_email=useremail)
        if not username:
            user.user_name = random_user_name
        else:
            user.user_name = username
        user.hash_password(password)
        db.session.add(user)
        db.session.commit()
        return (jsonify({'username': user.user_email}, 201))


class UserApi(Resource):
    decorators = [auth.login_required]
    def get(self):
        return jsonify(({'useremail':g.user.user_email, 'username': g.user.user_name, 'user_id': g.user.user_id}, 200))

    def put(self):
        method = request.args.get('type')
        value = request.args.get('data')
        if method == 'username':
            g.user.reset_user_name(value)
        elif method == 'password':
            g.user.reset_password(value)
        else:
            abort(401)
        return {'message': 'success'}

    def delete(self):
        user = User.query.filter_by(user_id=g.user.user_id)
        user.delete()
        return {'message': 'ok'}
