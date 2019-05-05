import os
import json
import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding as aspadding
from cryptography.exceptions import InvalidSignature
from json.decoder import JSONDecodeError

"""
Inputs: message, EncKey, HMACKey
outputs: dictionary[C, IV, tag]; C - Ciphertetxt, IV - Initial Vector, tag - HMAC of Enc file

(C, IV, tag)= MyencryptMAC(message, EncKey, HMACKey)
Function:
Encrypts messages and then produce HMAC digest of Encrypted Message.
The digest is tag.
Throws exceptions when Key is below 32 bytes.
IV is always 16 bytes long.
"""
def MyencryptMAC(message, EncKey, HMACKey):
    if len(EncKey) < 32 :
        raise ValueError("EncKey is below 32 bytes.")
    
    backend = default_backend()
    dic = dict()
    dic['IV'] = os.urandom(16) # IV is 16 Bytes

    #checking if it is binary or not
    if not (isinstance(message, bytes)): # If not bytes run commands to make it bytes
        message = bytes(message, 'ascii') #Turning ascii into bytes readable data
    
    """
    Padding:
    update() can apply algorithm as much as user wants but it just moves the message based on amount
    of extra character and in turn gives it to the finalize. Each iteration of update adds extra char to
    finalize(), which would produce ugly output of extra
    character.
    So only do update() once.
    finalize() returns the extra char plus padding
    """
    padder = padding.PKCS7(128).padder() # 128 bits or 16 bytes
    #padding message
    message = padder.update(message)
    message += padder.finalize()
    
    """
    Encryptor:
    update() can apply algorithm as much as user wants though once it reaches the
        decryption stage it would produce gibberish. Only do it once.
    finalize() closes the object, returns empty bytes and doesn't do anything else; Don't need to even add it.
        With the cipher setting that is being used.
    """
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(dic['IV']), backend=backend) # Setting Cipher Type
    encryptor = cipher.encryptor() # cipher is set to encrypt
    
    
    dic['C'] = encryptor.update(message)
    h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    h.update(dic['C']) # What it does is it apply MAC Algorithm and can do it as many times you want
                       # Make sure when verifying, that it updates the same amount.
    
    # Used with premade key input and hmac update once
    dic['tag'] = h.finalize() # When you are done with the iterations of MAC Algorithm finalize it to produce digest
    return dic

"""********************************************************"""
"""
Inputs: filepath
outputs: dictionary[C, IV, tag, EncKey, HMACKey, ext]; C - Ciphertetxt, IV - Initial Vector, ext - file extension, tag - HMAC of Enc file

(C, IV, tag, Enckey, HMACKey, ext)= MyfileEncryptMAC (filepath)
Function:
Encrypts file contents by calling MyencryptMAC function.
"""
def MyfileEncryptMAC (filePath):
    file_ext = os.path.splitext(filePath)[1] # [0]: File name, [1]: File Extension
    #Reading original file
    with open(filePath, 'rb') as content_file:
        message = content_file.read()
    
    # Dictionary of stuff
    stuff = dict()
    stuff['EncKey'] = os.urandom(32)
    stuff['ext'] = file_ext.encode() # Easier to make all data in dictionary binary or bytes type
    stuff['HMACKey'] = os.urandom(32)
    stuff.update(MyencryptMAC(message, stuff['EncKey'], stuff['HMACKey']))
    
    return stuff

"""********************************************************"""
"""
Inputs: messageC, tag, EncKey, HMACKey, IV;
        messageC - Ciphertetxt, IV - Initial Vector, ext - file extension, tag - HMAC of Enc file
outputs: original message

(message)= MydecryptMAC(messageC, tag, EncKey, HMACKey, IV)
Function:
Decrypts messages when used and verify tag. To verify, must HMAC the ciphertext and have tag.
If the tag does not match it raises an exception of InvalidSignature.
"""
def MydecryptMAC(messageC, tag, EncKey, HMACKey, IV):
    backend = default_backend()
    hc = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    hc.update(messageC)
    """
    HMAC:
    When verifying make sure the update is equal to the update in encryption stage.
    Otherwise would give invalid signature.
    """
    hc = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
    hc.update(messageC)
    hc.verify(tag) # verify also finalize HMAC
    
    unpadder = padding.PKCS7(128).unpadder()
    
    """
    Decryptor:
    update() can apply algorithm as much as user wants though it would produce gibberish. Only do it once.
    finalize() closes the object, returns empty bytes and doesn't do anything else; Don't need to even add it.
        With the cipher setting that is being used.
    """
    cipher = Cipher(algorithms.AES(EncKey), modes.CBC(IV), backend = backend)
    decryptor = cipher.decryptor()
    
    messageC = decryptor.update(messageC) + decryptor.finalize()
    messageC = unpadder.update(messageC) + unpadder.finalize()
    
    return messageC

"""********************************************************"""
"""
Inputs:  C, tag, Enckey, HMACKey, IV, ext, filepath
        C - Ciphertetxt, tag - HMAC of Enc file, IV - Initial Vector, ext - file extension
outputs: decrypted file and decrypted message

(message)= MyfileEncrypt (filepath):
Function:
Decrypts file contents by calling MydecryptMAC function. Then writing it
back into files with the original extension.
"""
def MyfileDecryptMAC (C, tag, EncKey, HMACKey, IV, ext, filepath):
    fileName= os.path.splitext(filepath)[0] # [0]: File name, [1]: File Extension
    ext = ext.decode() # Decode binary or bytes into string
    message = MydecryptMAC(C, tag, EncKey, HMACKey, IV,)
    
    #Writing to new decrypted file
    with open(fileName + ext, "wb") as decrypt_file:
        decrypt_file.write(message)
        
    return message

"""********************************************************"""
"""
Inputs:  directoryPath
outputs: Generates Public and Private keys files

void WriteRSAKey(directoryPath)
Function:
Creates pem files for private and public key at filePath.
The private key is 2048 bits, public exponent 65537.
Private Key:Encoding = PEM, Format = PKCS8, encryption_algorithm = no encrypt key (no password)
"""
def WriteRSAKey(directoryPath):
    if not os.path.isdir(directoryPath):
        raise FileNotFoundError("Directory: %s to write RSA keys does not exist." %directoryPath)
    
    filePathPRK = os.path.join(directoryPath, 'PRK.pem')
    filePathPUK = os.path.join(directoryPath, 'PUK.pem')
    
    # If one of them are missing then write both.
    if not(os.path.isfile(filePathPRK) and os.path.isfile(filePathPUK)):
        print("Write RSAKey in directory: %s" %directoryPath)
        #Write Private Key
        private_key = rsa.generate_private_key(public_exponent = 65537, key_size = 2048, backend = default_backend())
        with open(filePathPRK, 'wb') as key_file:
            key_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption()))
        #Write Public Key
        public_key = private_key.public_key()
        with open(filePathPUK, 'wb') as key_file:
            key_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
        
    return


"""********************************************************"""

"""
Inputs: filepath, RSA_Publickey_dirpath
outputs: RSACipher, C, IV, tag, ext; RSACipher - Encrypted EncKey + HMACKey, C - ciphertext, IV - Initial Vector, tag - HMAC digest 

(RSACipher, C, IV, tag, ext)= MyRSAEncrypt(filepath, RSA_Publickey_dirpath):
Function:
Calls MyfileEncryptMAC on file.
Concatenate EncKey and HMACKey from MyfileEncryptMAC. Then encrypts with the public key to make RSACipher.
The padding uses OAEP(Optimal Asymmetric Encryption Padding) padding mode. It gives probabilistic encryption.
Before it returns it delete EncKey and HMACKey.
If public key does not exist then it throws exception.
"""

def MyRSAEncrypt(filepath, RSA_Publickey_dirpath):
    filePathPUK = os.path.join(RSA_Publickey_dirpath, 'PUK.pem')
    if os.path.isfile(filePathPUK):
        with open(filePathPUK, 'rb') as key_file:
            publicKey = load_pem_public_key(key_file.read(), backend=default_backend())
    else:
        raise FileNotFoundError("Public Key file does not exist.")
    
    stuff = MyfileEncryptMAC(filepath)
    
    concatEHKeys = stuff['EncKey'] + stuff['HMACKey']
    #mgf - mask generation fuction: accepts any input length, then output desired length
    stuff['RSACipher'] = publicKey.encrypt(concatEHKeys, aspadding.OAEP(mgf = aspadding.MGF1(algorithm=hashes.SHA256()), algorithm = hashes.SHA256(), label = None))

    del stuff['EncKey']
    del stuff['HMACKey']
    return stuff

"""********************************************************"""

"""
Inputs: RSACipher, C, tag, IV, ext, filepath, RSA_Privatekey_dirpath
            RSACipher - Encrypted EncKey + HMACKey, C - ciphertext, IV - Initial Vector, tag - HMAC digest
outputs: message

message= MyRSADecrypt(RSACipher, C, tag, IV, ext, filepath, RSA_Privatekey_dirpath)
Function:
Uses private key to decrypt RSACipher to get the EncKey + HMACKey or EncKey||HMACKey = (64 bytes long). Then it splits EncKey + HMACKey
to individual key(32 bytes).
Call MyfileDecryptMAC to get unencrypted file back.
If key does not exist throw exception.
"""
def MyRSADecrypt(RSACipher, C, tag, IV, ext, filepath, RSA_Privatekey_dirpath):
    filePathPRK = os.path.join(RSA_Privatekey_dirpath, 'PRK.pem')
    if os.path.isfile(filePathPRK):
        with open(filePathPRK, 'rb') as key_file:
            privateKey = load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    else:
        raise FileNotFoundError("Private Key file does not exist.")
    
    concatEHKeys = privateKey.decrypt(RSACipher, aspadding.OAEP(mgf = aspadding.MGF1(algorithm=hashes.SHA256()), algorithm = hashes.SHA256(), label = None))
    EncKey, HMACKey = concatEHKeys[0:32], concatEHKeys[32:64]

    message = MyfileDecryptMAC(C, tag, EncKey, HMACKey, IV, ext, filepath)
    return message

"""********************************************************"""
"""
Inputs: binary dictionary
outputs: string dictionary

(str)dictionary BintoStrDic((bin)dictionary)
Function:
Converts each binary value in dictionary to a string value.
"""
def BintoStrDic(dictionary):
    stringDic = dict()
    for x in dictionary:
        stringDic[x] = binascii.hexlify(dictionary[x]).decode()
    return stringDic
#decode: binary -> string
#encode: string -> binary
#hexlify: bytes object only; makes binary data into hex value string; If it is already hex (/x0A) translate into string (0A)
#unhexlify: string hex value only; 
"""********************************************************"""
"""
Inputs: string dictionary
outputs: binary dictionary

(bin)dictionary BintoStrDic((str)dictionary)
Function:
Converts each string value in dictionary to a binary value.
"""
def StrtoBinDic(dictionary):
    binDic = dict()
    for x in dictionary:
        binDic[x] = binascii.unhexlify(dictionary[x])
    return binDic

"""********************************************************"""
"""
Inputs: directoryPath, RSA_Publickey_dirpath, (str)signature
outputs: Unencrypted files

void ScanDirEnc(directoryPath, RSA_Publickey_dirpath, (str)signature)
Function:
Starts at root directory or filepath then it encrypts each file in directory
and subdirectory. Calls EncryptFiletoMyRSAFile to replace file with RSAEncryptFile.
"""
def ScanDirEnc(directoryPath, RSA_Publickey_dirpath, signature):
    if os.path.isdir(directoryPath):
        print("SDE: Scanning directory: %s" %directoryPath)
    else:
        print("Directory: \"%s\" does not exist." %directoryPath)
        return

    for root, dirs, files in os.walk(directoryPath):
        for filename in files:
            filePath = os.path.join(root, filename)
            EncryptFiletoMyRSAFile(filePath, RSA_Publickey_dirpath, signature)
    return

"""********************************************************"""
"""
Inputs: directoryPath, RSA_Privatekey_dirpath, (str)signature
outputs: decrypted files

void ScanDirDec(directoryPath, RSA_Privatekey_dirpath, (str)signature)
Function:
Starts at root directory or filepath then it decrypts each file in directory
and subdirectory. Calls DecryptMyRSAFiletoFile to replace RSAEncryptFile with original file.
"""
def ScanDirDec(directoryPath, RSA_Privatekey_dirpath, signature):
    if os.path.isdir(directoryPath):
        print("SDD: Scanning directory: %s" %directoryPath)
    else:
        print("Directory: \"%s\" does not exist." %directoryPath)
        return
    
    for root, dirs, files in os.walk(directoryPath):
        for filename in files:
            filePath = os.path.join(root, filename)
            DecryptMyRSAFiletoFile(filePath, RSA_Privatekey_dirpath, signature)
    return

"""********************************************************"""
"""
Inputs: filepath, RSA_Publickey_dirpath, (str)signature
outputs: encrypted file

void EncryptFiletoMyRSAFile(filePath, RSA_Publickey_dirpath, (str)signature)
Function:
It encrypts files and delete the original file.
First it removes file then writes encrypted file.
It adds signature to the encrypted file so that it isn't encrypted again.
Skips files that are pem.
"""
def EncryptFiletoMyRSAFile(filePath, RSA_Publickey_dirpath, signature):
    
    if not isinstance(signature, str): # Really don't want to delete a file and then couldn't write file because of json dump exception.
        raise TypeError("signature must be a string.")
    
    encDic = dict()
    fileName, fileExt = os.path.splitext(filePath)
    if ".pem" != fileExt: # Skip pem that is needed to encrypt and decrypt files
        if(".json" == fileExt): # Check to see if json file is encrypted by our RSA
            try:
                with open(filePath) as json_file:
                    encDic = json.load(json_file)
                    if('sig' in encDic and encDic['sig'] == "1"): #If it has our signature, return
                        return
                    else: #If it is not our file then clear dictionary contents 
                        encDic.clear()
                    
            except JSONDecodeError as e:
                print(repr(e))
                print("  ", filePath)
                return
                
        encDic['sig'] = signature
        encDic.update( BintoStrDic(MyRSAEncrypt(filePath, RSA_Publickey_dirpath)) )
        try: # Assuming that the dictionary to be json dumped is all strings. Otherwise delete file then get exception that prevents writing json file.
            os.remove(filePath) # Remove first to see that it is allowed before writing json file
            with open(fileName + ".json", 'w') as json_file:
                json.dump(encDic, json_file, indent = 0)
        except PermissionError:
            print(filePath + " is in use.")
    return

"""********************************************************"""
"""
Inputs: filepath, RSA_Publickey_dirpath, (str)signature
outputs: Unencrypted files

void DecryptMyRSAFiletoFile(directoryPath, RSA_Publickey_dirpath, (str)signature)
Function:
It decrypts files and delete the json file. If original file is json,
it overwrites old json.
Signature is used to check that encrypted file is ours then decrypts file.
"""
def DecryptMyRSAFiletoFile(filePath, RSA_Privatekey_dirpath, signature):
    
    if not isinstance(signature, str): # If not string then wouldn't decrypt anything.
        raise TypeError("signature must be a string.")
    decDic = dict()
    
    if ".json" == os.path.splitext(filePath)[1]: #If file is json then decrypt
        try:
            with open(filePath) as json_file:
                decDic = json.load(json_file)
            if(decDic['sig'] == signature):
                del decDic['sig'] #del before calling StrtoBinDic since it is not binary
                decDic = StrtoBinDic(decDic)
                MyRSADecrypt(decDic['RSACipher'], decDic['C'], decDic['tag'], decDic['IV'], decDic['ext'], filePath, RSA_Privatekey_dirpath)
            else:
                return
        except InvalidSignature as e: # The tag verification failed
            print("Why you make hash fail?")
            print(repr(e))
            print("  ", filePath)
        except binascii.Error as e: # converting from string to binary failed
            print("binascii.%s" %repr(e)) # When Error is a member, repr(e) doesn't show binascii
            print("  ", filePath)
        except KeyError as e: # When Key doesn't match
            print("json is not encrypted by MyRSAEncrypt.")
            print(repr(e))
            print("  ", filePath)
        except JSONDecodeError as e:
            print(repr(e))
            print("  ", filePath)
        except ValueError as e: # When get bad value like RSA decryption error
            print(repr(e))
            print("  ", filePath)
        else:
            if(b".json" != decDic['ext']): # Checks that the original file is json so that the json file doesn't get deleted; Also 'ext' is in binary.
                os.remove(filePath)
    return

"""****------------------------------------------------****"""
"""********************************************************"""
"""
Start of program
"""
"""********************************************************"""
"""****------------------------------------------------****"""
RSAKeyLoc = '.'
pp = "cave of the poo poo pee pee master"
sig = "1"

WriteRSAKey(RSAKeyLoc)
# Ask user whether they want to change directory
print("Default directory is in executable with directory target:", pp)
print("Use \".\" to encrypt the directory that the executable file is in.")
print("Enter 1 to use default directory.")
print("Enter 2 to change directory path.")
value = ''
while(value != '1' and value != '2'):
    value = input("Enter number: ")
    if(value == '2'):
        pp = input("Enter the directory path: ") 
print()

# Ask user to Encrypt, Decrypt or exit
while(value != '3'):
    print("Enter number 1 to Enc files")
    print("Enter number 2 to Dec files")
    print("Enter number 3 to exit")
    value = input("Enter number: ")
    if(value == '1'): # Encrypt
        print("\nEncryption Started.")
        ScanDirEnc(pp, RSAKeyLoc, sig)
        print("Encryption Done.\n")
        
    elif value == '2': # Decrypt
        print("\nDecryption Started.")
        ScanDirDec(pp, RSAKeyLoc, sig)
        print("Decryption Done.\n")
        
print("Goodbye")

