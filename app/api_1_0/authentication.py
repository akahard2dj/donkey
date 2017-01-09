from flask import g, jsonify
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth
from flask_restful import Resource

import datetime

from app.models.user import EncryptedUser as User

auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(useremail_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(useremail_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(user_email=useremail_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


class BasicHTTPAuthApi(Resource):
    decorators = [auth.login_required]

    def get(self):
        token = g.user.generate_auth_token(7200)
        g.user.set_token_issued_datetime(datetime.datetime.utcnow())
        return jsonify({'token': token.decode(), 'duration': 7200})

