from datetime import datetime
from flask import current_app
from app import db

from app.models.aes_cipher import AESCipher
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.sql.expression import func, cast


class EncryptedPost(db.Model):
    __tablename__ = 'encrypted_post'
    post_id = db.Column(db.Integer, primary_key=True)
    enc_post_title = db.Column(db.Text)
    enc_post_body = db.Column(db.Text)
    post_timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow())
    user_id = db.Column(db.Integer, db.ForeignKey('encrypted_users.user_id'))
    read_counts = db.Column(db.Integer, default=0)

    def increase_read_count(self):
        updated_counts = self.read_counts + 1
        self.read_counts = updated_counts
        db.session.add(self)

    def edit_post(self, new_post_title, new_post_body):
        self.post_title = new_post_title
        self.post_body = new_post_body
        db.session.add(self)

    @hybrid_property
    def post_title(self):
        cipher = AESCipher(current_app.config['AES_KEY'])
        return cipher.decrypt(self.enc_post_title)

    @post_title.expression
    def post_title(cls):
        decrypted = func.aes_decrypt(
            func.unhex(cls.enc_post_title), current_app.config['AES_KEY']
        )
        return cast(decrypted, db.String(64))

    @post_title.setter
    def post_title(self, title):
        cipher = AESCipher(current_app.config['AES_KEY'])
        self.enc_post_title = cipher.encrypt(title)

    @hybrid_property
    def post_body(self):
        cipher = AESCipher(current_app.config['AES_KEY'])
        return cipher.decrypt(self.enc_post_body)

    @post_body.expression
    def post_body(cls):
        decrypted = func.aes_decrypt(
            func.unhex(cls.enc_post_body), current_app.config['AES_KEY']
        )
        return cast(decrypted, db.String(64))

    @post_body.setter
    def post_body(self, body):
        cipher = AESCipher(current_app.config['AES_KEY'])
        self.enc_post_body = cipher.encrypt(body)
