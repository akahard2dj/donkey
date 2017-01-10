from flask import current_app
from passlib.apps import custom_app_context as pwd_context
from passlib.hash import pbkdf2_sha256
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

from app import db
from app.models.role import Role
from app.models.aes_cipher import AESCipher
from sqlalchemy.ext.hybrid import hybrid_property, hybrid_method
from sqlalchemy.sql.expression import func, cast


class EncryptedUser(db.Model):
    __tablename__ = 'encrypted_users'
    enc_user_email = db.Column(db.String(64), unique=True, index=True)
    user_id = db.Column(db.Integer, primary_key=True)
    enc_user_name = db.Column(db.String(64), index=True)
    password_hash = db.Column(db.String(256))
    token_issued = db.Column(db.DateTime)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'))
    posts = db.relationship('EncryptedPost', backref='author', lazy='dynamic')

    def __init__(self, **kwargs):
        super(EncryptedUser, self).__init__(**kwargs)
        if self.role is None:
            if self.user_email == 'master@bora.com':
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()

    @hybrid_property
    def user_email(self):
        cipher = AESCipher(current_app.config['AES_KEY'])
        return cipher.decrypt(self.enc_user_email)

    @user_email.expression
    def user_email(cls):
        decrypted = func.aes_decrypt(
            func.unhex(cls.enc_user_email), current_app.config['AES_KEY']
        )
        return cast(decrypted, db.String(64))

    @user_email.setter
    def user_email(self, email):
        cipher = AESCipher(current_app.config['AES_KEY'])
        self.enc_user_email = cipher.encrypt(email)

    @hybrid_property
    def user_name(self):
        cipher = AESCipher(current_app.config['AES_KEY'])
        return cipher.decrypt(self.enc_user_name)

    @user_name.expression
    def user_name(cls):
        decrypted = func.aes_decrypt(
            func.unhex(cls.enc_user_name), current_app.config['AES_KEY']
        )
        return cast(decrypted, db.String(64))

    @user_name.setter
    def user_name(self, name):
        cipher = AESCipher(current_app.config['AES_KEY'])
        self.enc_user_name = cipher.encrypt(name)

    def hash_password(self, password):
        #self.password_hash = pwd_context.encrypt(password)
        custom_pbkdf2 = pbkdf2_sha256.using(rounds=100000)
        self.password_hash = custom_pbkdf2.hash(password)

    def verify_password(self, password):
        #return pwd_context.verify(password, self.password_hash)
        return pbkdf2_sha256.verify(password, self.password_hash)

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
        print(issued_datetime)
        self.token_issued = issued_datetime
        db.session.add(self)

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


