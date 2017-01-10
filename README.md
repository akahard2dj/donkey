# donkey

donkey api

/users/token 
 - 사용자의 토큰 생성
 - [GET] input: basic auth(user_email, password), output: token
 
/users/create
 - 사용자 등록
 - [POST] input: basic auth, json data({useremail,password, username}), output: none
 
/users/<int:user_id>
 - 사용자 조회/수정/삭제
 - [GET] input: basic auth, userid, output: json_data({username,...})
 - [PUT] input: basic auth, user_id, url_args(type{username:password}, data{content})
 - [DELETE] input: basic auth, user_id
 
/posts/create
 - 게시물 등록
 - [POST] input: basic auth, json_data({post_title,post_body})

/posts/<int:post_id>
 - 게시물 조회/수정/삭제
 - [GET] input: basic auth, post_id, output: json_data({post_id, post_timestamp, post_title, post_body, post_read_counts})
 - [PUT] input: basic auth, post_id, json_data({post_title,post_body})
 - [DELETE] input: basic auth, post_id
