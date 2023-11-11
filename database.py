from config import Config
from os import environ
import psycopg2
import logging


class Database:
    @staticmethod
    def connect():
        Config.conn = psycopg2.connect(
            database=environ.get("DB_NAME"),
            host=environ.get("DB_HOST"),
            user=environ.get("DB_USER"),
            password=environ.get("DB_PASSWORD"),
            port=environ.get("DB_PORT"),
        )

    logging.info("Initialized database connection")

    @staticmethod
    def create_tables():
        cursor = Config.conn.cursor()

        logging.info("Creating tables")

        cursor.execute(
            """create table if not exists users (
            id serial primary key,
            first_name text,
            last_name text,
            email text unique,
            password_hash text)"""
        )

        cursor.execute(
            """create table if not exists user_tokens (
            id serial primary key,
            user_id integer,
            token text,
            expires_at timestamptz,
            created_at timestamptz default now(),
            foreign key (user_id) references users (id))"""
        )

        Config.conn.commit()

    @staticmethod
    def drop_tables():
        cursor = Config.conn.cursor()

        logging.info("Dropping tables")

        cursor.execute("DROP TABLE IF EXISTS users")
        cursor.execute("DROP TABLE IF EXISTS user_tokens")

        Config.conn.commit()
