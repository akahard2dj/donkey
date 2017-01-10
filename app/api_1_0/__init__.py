from flask import Blueprint
from flask_restful import Api

from app.api_1_0.authentication import BasicHTTPAuthApi

from app.api_1_0.users import UserApi
from app.api_1_0.users import UsersApi

from app.api_1_0.posts import PostsApi
from app.api_1_0.posts import PostApi

auth_blueprint = Blueprint('auth_api', __name__)
api = Api()
api.init_app(auth_blueprint)

api.add_resource(BasicHTTPAuthApi, '/users/token')

api.add_resource(UsersApi, '/users/create')
api.add_resource(UserApi, '/users')

api.add_resource(PostsApi, '/posts/create')
api.add_resource(PostApi, '/posts/<int:post_id>')
