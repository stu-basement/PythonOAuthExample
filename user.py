from flask_login import UserMixin

from db import get_db

class User(UserMixin):
    def __init__(self, id_, provider, name, email, profile_pic):
        self.id = id_
        self.provider = provider
        self.name = name
        self.email = email
        self.profile_pic = profile_pic

    @staticmethod
    def get(user_id):
        db = get_db()
        user = db.execute(
            "SELECT * FROM user WHERE id = ?", (user_id,)
        ).fetchone()
        if not user:
            return None

        user = User(
            id_=user[0], provider=user[1], name=user[2], email=user[3], profile_pic=user[4]
        )
        return user

    @staticmethod
    def create(id_, provider, name, email, profile_pic):
        db = get_db()
        db.execute(
            "INSERT INTO user (id, provider, name, email, profile_pic) "
            "VALUES (?, ?, ?, ?, ?)",
            (id_, provider, name, email, profile_pic),
        )
        db.commit()
