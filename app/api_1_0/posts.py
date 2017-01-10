from flask import g, jsonify, abort, request
from flask_restful import Resource
from sqlalchemy import exc

from datetime import datetime

from app import db
from app.api_1_0.authentication import auth
from app.models.post import EncryptedPost as Post


class PostsApi(Resource):
    decorators = [auth.login_required]

    def post(self):
        post_title = request.json.get('post_title')
        post_body = request.json.get('post_body')

        if post_title is None or post_body is None:
            abort(400)

        p = Post(post_title=post_title,
                 post_body=post_body,
                 post_timestamp=datetime.utcnow(),
                 user_id=g.user.user_id)
        db.session.add(p)
        db.session.commit()

        return jsonify({'message': 'success'}, 200)


class PostApi(Resource):
    decorators = [auth.login_required]

    def get(self, post_id):
        try:
            p = Post.query.get(post_id)
        except exc.SQLAlchemyError:
            return jsonify({'message': 'failure'}, 404)

        p.increase_read_count()
        print(p.post_id, p.post_timestamp, p.post_title, p.post_body, p.read_counts)
        return jsonify({'message': 'success'}, 200)

    def put(self, post_id):
        post_title = request.json.get('post_title')
        post_body = request.json.get('post_body')
        p = Post.query.get_or_404(post_id)
        p.edit_post(post_title, post_body)
        return jsonify({'message': 'success'}, 200)

    def delete(self, post_id):
        p = Post.query.filter_by(post_id=post_id)
        p.delete()
        return jsonify({'message': 'success'}, 200)
