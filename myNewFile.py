import hashlib

password = '63526327kdiekwnUJNJDUE'


def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password   # return the hashed password


def check_password(expected_hash):  # check the password
    input_password = input('Enter password: ')
    if hash_password(input_password) == expected_hash:
        print('Correct password')
    else:
        print('Incorrect password')
        check_password(expected_hash)


check_password(hash_password(password))  # check the password
