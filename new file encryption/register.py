import hashlib

def register_user(username, password):
    """Register a new user with a username and password."""
    hashed_password = hashlib.sha256(password.encode()).hexdigest()  # Hash the password
    with open("users.txt", "a") as f:
        f.write(f"{username},{hashed_password}\n")  # Store username and hashed password