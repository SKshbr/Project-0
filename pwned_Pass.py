import requests
import hashlib
import sys


def request_api_data(query_char):
    url = "https://api.pwnedpasswords.com/range/" + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error status: {res.status_code}')
    else:
        return res


def get_password_leaks_count(hashes, hash_to_check):
    index = (line.split(':') for line in hashes.text.splitlines())
    # print(hashes)
    for h, count in index:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1Password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    # print(sha1Password)
    first5_char, tail = sha1Password[:5], sha1Password[5:]
    response = request_api_data(first5_char)
    return get_password_leaks_count(response, tail)


def main(argv):
    for password in argv:
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} has been Pwned {count} times... You should change your Password')
        else:
            print(f'{password} has never been Pawned. You are good to go!')
    return '-'*35


if __name__ == "__main__":
    main(sys.argv[1:])
