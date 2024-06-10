import sqlite3
import re
import os

from hashing import get_hash

DB_PATH = "users.db"

def validate_username(username):
    assert type(username) is str, "Username is not str"

    # Only allow usernames with letters, numbers, hyphens and underscores
    disallowed_char = re.search(r'[^a-zA-Z0-9-_]', username)

    assert not disallowed_char, f"Invalid character in username: '{disallowed_char.group()}'"

    if len(username) > 50:
        raise AssertionError("Username cannot be more than 50 characters")
    elif len(username) < 3:
        raise AssertionError("Username cannot be less than 3 characters")

    return True

def validate_password(password):
    assert type(password) is str, "Password is not str"

    # Only allow passwords with letters, numbers, various other characters
    disallowed_char = re.search(r'[^a-zA-Z0-9!@#$%^&*()-_+=]', password)

    assert not disallowed_char, f"Invalid character in password: '{disallowed_char.group()}'"

    if len(password) > 50:
        raise AssertionError("Password cannot be more than 50 characters")
    elif len(password) < 3:
        raise AssertionError("Password cannot be less than 3 characters")

    return True

def get_users():
    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        result = cursor.execute("SELECT username FROM users")
        result = [row[0] for row in result.fetchall()]

    return result

def get_user(username):
    if username is None:
        return None

    assert validate_username(username), "Username failed validation"

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        result = cursor.execute("SELECT * FROM users WHERE username=?", [username])
        result = result.fetchone()

        if result:
            result = {
                "id": result[0],
                "created": result[1],
                "username": result[2],
                "password": result[3],
                "admin": bool(result[4])
            }

    return result

def create_user(username, password, admin=False):
    assert validate_username(username), "Username failed validation"
    assert validate_password(password), "Password failed validation"

    assert not get_user(username), f"User {username!r} already exists"

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute(
            "INSERT INTO users (username, password, admin) VALUES (?, ?, ?)",
            [username, get_hash(password), admin]
        )

def update_user(username, new_password=None, admin=None):
    assert new_password is None or validate_password(new_password), "Password failed validation"

    assert get_user(username), f"User {username!r} doesn't exist"

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()

        if new_password is not None and type(new_password) is str:
            cursor.execute("UPDATE users SET password=? WHERE username=?", [get_hash(new_password), username])

        if admin is not None and type(admin) is bool:
            cursor.execute("UPDATE users SET admin=? WHERE username=?", [admin, username])

def delete_user(username):
    assert get_user(username), f"User {username!r} doesn't exist"

    with sqlite3.connect(DB_PATH) as connection:
        cursor = connection.cursor()
        cursor.execute("DELETE FROM users WHERE username=?", [username])

def init():
    with sqlite3.connect(DB_PATH) as connection:
        with open("schema.sql") as f:
            connection.executescript(f.read())

    create_user("admin", "123", admin=True) # Default 'admin' user created

if not os.path.isfile(DB_PATH):
    init()

if __name__ == "__main__":
    print(get_users())
    print(get_user("admin"))
    print(create_user("test", "123", admin=False))
    print(update_user("test", new_password="1234", admin=True))
    print(delete_user("test"))
