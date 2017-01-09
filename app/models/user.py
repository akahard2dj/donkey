from flask import current_app
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

from app import db
from app.models.aes_cipher import AESCipher
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql.expression import func, cast


cipher = AESCipher(current_app.config['AES_KEY'])


class EncryptedUser(db.Model):
    __tablename__ = 'encrypted_user'
    enc_user_email = db.Column(db.String(64), unique=True, index=True)
    user_id = db.Column(db.Integer, primary_key=True)
    enc_user_name = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(128))
    token_issued = db.Column(db.DateTime)

    @hybrid_property
    def user_email(self):
        return cipher.decrypt(self.enc_user_email)

    @user_email.expression
    def user_email(cls):
        decrypted = func.aes_decrypt(
            func.unhex(cls.enc_user_email), current_app.config['AES_KEY']
        )
        return cast(decrypted, db.String(64))

    @user_email.setter
    def user_email(self, email):
        self.enc_user_email = cipher.encrypt(email)

    @hybrid_property
    def user_name(self):
        return str(aes_decrypt(self.enc_user_name))

    @user_name.expression
    def user_name(cls):
        decrypted = func.aes_decrypt(
            func.unhex(cls.enc_user_name), current_app.config['AES_KEY']
        )
        return cast(decrypted, db.String(64))

    @user_name.setter
    def user_name(self, name):
        self.enc_user_name = aes_encrypt(name)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=7200):
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'user_id': self.user_id})

    def reset_password(self, new_password):
        self.password_hash = pwd_context.encrypt(new_password)
        db.session.add(self)

    def reset_user_name(self, new_user_name):
        self.user_name = new_user_name
        db.session.add(self)

    def set_token_issued_datetime(self, issued_datetime):
        self.token_issued = issued_datetime
        db.session.add(self)

    def to_json(self):
        json_data = {
            'username': self.user_name,
            'useremail': self.user_email,
            'userid': self.user_id
        }
        return json_data

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = EncryptedUser.query.get(data['user_id'])
        return user
