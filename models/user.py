from config import Config
import logging
import sys
from dataclasses import dataclass
import argon2
from models.token import Token

ph = argon2.PasswordHasher()
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


@dataclass
class User:
    id: int
    first_name: str
    last_name: str
    email: str
    password_hash: str
    token: Token = None

    @staticmethod
    def get_by_id(id):
        cursor = Config.conn.cursor()
        query = "SELECT id, first_name, last_name, email, password_hash from users where id = %s"
        cursor.execute(query, (id,))
        product_result = cursor.fetchone()

        if product_result is None:
            return None

        return User(
            product_result[0],
            product_result[1],
            product_result[2],
            product_result[3],
            product_result[4],
        )

    @staticmethod
    def get_by_email(email):
        cursor = Config.conn.cursor()
        query = "SELECT id, first_name, last_name, email, password_hash from users where email = %s"
        cursor.execute(query, (email,))
        product_result = cursor.fetchone()

        if product_result is None:
            return None

        return User(
            product_result[0],
            product_result[1],
            product_result[2],
            product_result[3],
            product_result[4],
        )

    @staticmethod
    def create(first_name, last_name, email, password):
        logging.info(f"Creating user {first_name} { last_name} [{email}]")

        password_hash = ph.hash(password)

        cursor = Config.conn.cursor()
        query = "INSERT INTO users (first_name, last_name, email, password_hash) VALUES (%s, %s, %s, %s) RETURNING id"

        try:
            cursor.execute(query, (first_name, last_name, email, password_hash))
        except Exception as e:
            logging.error(e)
            return None

        user_id = cursor.fetchone()[0]

        Config.conn.commit()

        return User.get_by_id(user_id)

    def update_user_password(self, password_hash):
        logging.info(f"Updating password for user {self.id}")

        cursor = Config.conn.cursor()
        query = "UPDATE users SET password_hash = %s WHERE id = %s"
        cursor.execute(query, (password_hash, self.id))

        Config.conn.commit()

        return User.get_by_id(self.id)

    def verify_password(self, password) -> bool:
        logging.info(f"Verifying password for user {self.id}")

        cursor = Config.conn.cursor()
        query = "SELECT password_hash from users where id = %s"
        cursor.execute(query, (self.id,))
        password_hash = cursor.fetchone()[0]

        try:
            ph.verify(password_hash, password)
        except argon2.exceptions.VerifyMismatchError:
            return False
        return True

    def create_token(self) -> Token:
        return Token.create(self.id)

    def toJSON(self):
        user = {
            "id": self.id,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "email": self.email,
        }

        if self.token is not None:
            user["token"] = {
                "token_id": self.token.id,
                "token": self.token.token,
                "created_at": self.token.created_at,
                "expires_at": self.token.expires_at,
            }

        return user
