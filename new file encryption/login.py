import hashlib

def login_user(username, password):
    """Authenticate a user with a username and password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    try:
        with open("users.txt", "r") as f:
            for line in f:
                stored_username, stored_password = line.strip().split(",")
                if stored_username == username and stored_password == hashed_password:
                    return True
    except FileNotFoundError:
        return False
    return False