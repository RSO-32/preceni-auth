from config import Config
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
import random
import string
import pytz

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)


@dataclass
class Token:
    id: int
    token: str
    expires_at: datetime
    created_at: datetime

    @staticmethod
    def get_by_id(id):
        cursor = Config.conn.cursor()
        query = (
            "SELECT id, token, expires_at, created_at from user_tokens where id = %s"
        )

        cursor.execute(query, (id,))
        token_result = cursor.fetchone()

        if token_result is None:
            return None

        return Token(
            token_result[0],
            token_result[1],
            token_result[2],
            token_result[3],
        )

    @staticmethod
    def get_by_str(user_id, token_str):
        cursor = Config.conn.cursor()
        query = "SELECT id, token, expires_at, created_at from user_tokens where user_id = %s AND token = %s"

        cursor.execute(query, (user_id, token_str))
        token_result = cursor.fetchone()

        if token_result is None:
            return None

        return Token(
            token_result[0],
            token_result[1],
            token_result[2],
            token_result[3],
        )

    @staticmethod
    def create(user_id):
        logging.info(f"Creating token for user {user_id}")

        token_length = 64

        token = "".join(
            random.SystemRandom().choice(string.ascii_uppercase + string.digits)
            for _ in range(token_length)
        )

        expires_at = datetime.now() + timedelta(days=30)

        cursor = Config.conn.cursor()
        query = "INSERT INTO user_tokens (user_id, token, expires_at) VALUES (%s, %s, %s) RETURNING id"
        cursor.execute(query, (user_id, token, expires_at))
        token_id = cursor.fetchone()[0]

        Config.conn.commit()

        return Token.get_by_id(token_id)

    def is_valid(self):
        return self.expires_at > datetime.now(tz=pytz.UTC)
