from app import db


class DeptCategory(db.Model):
    __tablename__ = 'dept_category'
    dept_category_id = db.Column(db.Integer, primary_key=True)
    dept_category_name = db.Column(db.String(64), index=True)
    dept_category_code = db.Column(db.Integer, index=True)
    #dept_division = db.relationship('DeptDivision', backref='dept_devision', lazy='dynamic')

    @staticmethod
    def insert_dept_category():
        categories = {
            '인문사회계열': 1,
            '자연과학계열': 2,
            '공학계열': 3,
            '의학계열': 4,
            '예체능계열': 5
        }
        for c in categories:
            category = DeptCategory.query.filter_by(dept_category_name=c).first()
            if category is None:
                category = DeptCategory(dept_category_name=c)
            category.dept_category_code = categories[c]
            db.session.add(category)
        db.session.commit()


class DeptDivision():
    __tablename__ = 'dept_division'
    dept_division_id = db.Column(db.Integer, primary_key=True)
    dept_division_name = db.Column(db.String(64), index=True)
    dept_division_code = db.Column(db.Integer, index=True)

    @staticmethod
    def insert_dept_division():
        divisions = {
            '언어문학': 11,
            '인문학': 12,
            '법학': 13,
            '사회과학': 14,
            '경영,경재': 15,
            '인문사회,교육': 16,
            '인문사회,N.C.E': 17,
            '수학,물리,천문,지구': 20,
            '화학생명,과학,환경': 21,
            '농림,수산': 22,
            '생활과학': 23,
            '의료예과': 24,
            '약학': 25,
            '간호': 26,
            '보건': 27,
            '자연과학,교육': 28,
            '자연과학,N.C.E': 29,
            '건설': 31,
            '기계': 32,
            '전기,전자,컴퓨터': 33,
            '재료': 34,
            '화공,고분자,에너지': 35,
            '산업,안전': 36,
            '공학계열,교육': 37,
            '공학계열,N.C.E': 38,
            '의료': 41,
            '의학계열,N.C.E': 42,
            '무용,체육': 51,
            '연극,영화': 52,
            '미술': 53,
            '음악': 54,
            '응용예술': 55,
            '예체능계열,교육': 56,
            '예체능계열,N.C.E': 57
        }

class DeptSection():
    pass
