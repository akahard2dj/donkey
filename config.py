import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    CACHE_TYPE = 'null'
    SECRET_KEY = 'secret_key'
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    FLASKY_ADMIN = 'master@bora.com'
    SQLALCHEMY_TRACK_MODIFICATIONS = True
    FLASKY_POSTS_PER_PAGE = 30
    AES_KEY = '1234567890123456'

    @staticmethod
    def init_app(app):
        pass


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/test_restful'


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:@localhost/test_restful'
    WTF_CSRF_ENABLED = False


config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
