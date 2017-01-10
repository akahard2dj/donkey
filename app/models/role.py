from app import db
from app.models.permission import Permission as p


class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permission = db.Column(db.Integer)
    user = db.relationship('EncryptedUser', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (p.WRITE_ARTICLE | p.WRITE_COMMENT, True),
            'Admin': (0xFF, False)
        }
        for r in roles:
            role = Role.query.filter_by(role_name=r).first()
            if role is None:
                role = Role(role_name=r)
            role.permission = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()
