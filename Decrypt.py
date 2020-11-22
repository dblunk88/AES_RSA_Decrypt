import base64
import hashlib
import os
import webbrowser
from base64 import b64decode
from time import sleep

from Cryptodome.Cipher import AES,PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from tqdm import tqdm
import re


progress_bar_format = '{l_bar}{bar:25}{r_bar}{bar:-10b}'
datasets = []
messages = {}
rsa_keys = {}
hash = {}
aes_session_keys = {}
keyPair = {}

def alphanum_key(s):
    # https://nedbatchelder.com/blog/200712/human_sorting.html
    # To help sort the datasets if you are running multiple ones
    """ Turn a string into a list of string and number chunks.
        "z23a" -> ["z", 23, "a"]
    """
    return [ tryint(c) for c in re.split('([0-9]+)', s) ]

def tryint(s):
    # https://nedbatchelder.com/blog/200712/human_sorting.html
    # To help sort the datasets if you are running multiple ones
    try:
        return int(s)
    except ValueError:
        return s

def Setup():
    rsa_path = []
    hashes_path = []
    aes_session_keys_path = []
    messages_path = []

    for dir in os.listdir("."):
        if "dataset" in dir:
            datasets.append(dir)
    # To help sort the datasets if you are running multiple ones
    datasets.sort(key=alphanum_key)
    for dataset in datasets:
        directory = dataset

        if os.name == 'nt':
            dir_dividor = "\\"
        else:
            dir_dividor = "/"
        hashes_path.append([dataset,directory + dir_dividor + "hashes" + dir_dividor])
        aes_session_keys_path.append([dataset,directory + dir_dividor + "aes" + dir_dividor])
        messages_path.append([dataset,directory + dir_dividor + "messages" + dir_dividor])
        rsa_path.append([dataset,directory + dir_dividor + "rsa" + dir_dividor])

    # Going through the directories and adding the file values to a dict
    for name,path in hashes_path:
        for fileName in tqdm(os.listdir(path),desc=("Loading Hashes from " + name + " into memory").ljust(50),
                             bar_format=progress_bar_format):
            with open(path + fileName) as file:
                hash[f"{name}-{fileName}"] = [name,fileName,file.read()]
        sleep(0.1)
    for name,path in aes_session_keys_path:
        for fileName in tqdm(os.listdir(path),desc=("Loading Session Keys from " + name + " into memory").ljust(50),
                             bar_format=progress_bar_format):
            with open(path + fileName,"rb") as file:
                key = fileName.split(".eaes")[0].split("_")[1]
                aes_session_keys[f"{name}-{key}"] = [name,fileName,file.read()]
        sleep(0.1)
    for name,path in messages_path:
        for fileName in tqdm(os.listdir(path),desc=("Loading Messages from " + name + " into memory").ljust(50),
                             bar_format=progress_bar_format):
            with open(path + fileName,"rb") as file:
                message_number = fileName.split("message")[1].split(".emsg")[0]
                message = base64.b64encode(file.read())
                messages[f"{name}-{message_number}"] = [name,fileName,path + fileName,message]
        sleep(0.1)
    for name,path in rsa_path:
        for fileName in tqdm(os.listdir(path),desc=("Loading RSA Keys from " + name + " into memory").ljust(50),
                             bar_format=progress_bar_format):
            if 'private' in fileName:
                key = fileName.split(".pem")[0].split("_")[1]
                with open(path + fileName,"rb") as file:
                    private_key = file.read()
                with open(f"{path}public_{key}.pem") as file:
                    public_key = file.read()
                rsa_keys[f"{name}-{key}"] = [private_key,public_key,fileName]
        sleep(0.1)


def Decrypt_session_keys():
    # https://stackoverflow.com/questions/46132222/pycryptodome-official-example-unclear
    for file in tqdm(rsa_keys,desc=("Searching...").ljust(50),bar_format=progress_bar_format):
        dataset = file.split("-")[0]
        if dataset in keyPair:
            continue
        private_key = RSA.importKey(rsa_keys[file][0])
        cipher_rsa = PKCS1_OAEP.new(private_key)
        # TODO: Implement multithreading here
        for counter2 in range(0,199):
            try:
                session_index = f"{dataset}-key{str(counter2)}"
                cipher_data = aes_session_keys[session_index][2]
                aes_decrypted = cipher_rsa.decrypt(cipher_data)
                hashhex = hashlib.md5(aes_decrypted).hexdigest()
                if hash[dataset + "-plain_aes_hash.md5"][2] in hashhex:
                    keyPair[dataset] = [rsa_keys[file][2],aes_session_keys[session_index][1],aes_decrypted]
                    break
            except ValueError:
                continue
    return keyPair


def Bruteforce_Message_Key(keyPair):
    # all_aes_modes = [AES.MODE_CBC, AES.MODE_CFB, AES.MODE_CCM, AES.MODE_OPENPGP, AES.MODE_OFB, AES.MODE_OCB,
    #              AES.MODE_GCM, AES.MODE_ECB, AES.MODE_EAX, AES.MODE_CTR]
    aes_modes = [AES.MODE_CBC,AES.MODE_CFB,AES.MODE_OPENPGP,AES.MODE_OFB,AES.MODE_OCB,
                 AES.MODE_GCM,AES.MODE_ECB,AES.MODE_EAX,AES.MODE_CTR]
    found_messages = []
    for message_list in tqdm(messages,desc=("Searching...").ljust(50),bar_format=progress_bar_format):
        dataset = message_list.split("-")[0]
        message = messages[message_list][3]
        fileName = messages[message_list][1]
        session_key = keyPair[dataset][2]
        iv = 16 * b"\x00"
        for mode in aes_modes:
            # https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
            # Key is 32 characters --> AES 128-bit key
            try:
                plaintext = AES.new(key=session_key,mode=mode,iv=iv)
            except TypeError:
                plaintext = AES.new(key=session_key,mode=mode)
            found = decode_message(plaintext,dataset,message)
            if found is not None:
                found_messages.append([found, dataset, fileName])
    return found_messages


def decode_message(plaintext,dataset,message):
    file_hash = hash[dataset + "-plain_master_message_hash.md5"][2]
    try:
        plaintext = plaintext.decrypt(b64decode(message))
    except TypeError:
        plaintext = ""
    hashhex = hashlib.md5(plaintext).hexdigest()
    if hashhex == file_hash or plaintext.hex() == file_hash:
        return plaintext


def Cthulhu():
    print("\n\n\nSummoning the great one to celebrate the triumph!")
    webbrowser.open_new("https://www.youtube.com/watch?v=-OFkMzo7-n0")


if __name__ == "__main__":
    print("\n\n############################################\n"
          "##     Loading Everything into memory     ##\n"
          "############################################\n")
    Setup()
    # manager = multiprocessing.Manager()
    # rsa_shared_dict = manager.dict(rsa_keys)
    # session_shared_dict = manager.dict(aes_session_keys)
    # pool = multiprocessing.Pool(None)
    # processed = pool.map(Decrypt_session_keys,rsa_shared_dict.values())
    print("\n\n############################################\n"
          "##  Finding RSA and AES Session Keypairs  ##\n"
          "############################################\n")
    keyPair = Decrypt_session_keys()
    print("Found Keypairs:")
    for key in keyPair:
        print(f"Dataset: {key}, Private Key: {keyPair[key][0]}, Session Key: {keyPair[key][1]}, "
              f"Value: {keyPair[key][2]}")
    print("\n\n############################################\n"
          "## Decrypting Messages using Session Key  ##\n"
          "############################################\n")
    found = Bruteforce_Message_Key(keyPair)
    if found:
        print("Decrypted Messages:")
        for message, dataset, fileName in found:
            print(f"Dataset: {dataset}, Message Filename: {fileName}\nMessage: {message.decode('utf-8')}")
        Cthulhu()
