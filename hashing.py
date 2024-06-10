import hashlib

def get_hash(string, salt=None):
    if type(string) is not str:
        raise TypeError(f"{type(string).__name__!r} object is not valid string")

    if salt is None:
        salt = "wh8wf3hff3fj3f383hf3fhf3332553" # Gibberish
    elif type(salt) is not str:
        raise TypeError(f"{type(salt).__name__!r} object is not valid salt")

    hash_value = hashlib.sha256(bytes(string + salt, encoding="utf-8")).hexdigest()

    return hash_value

if __name__ == "__main__":
    example_hash = get_hash("123")
    print(example_hash)
