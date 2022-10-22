import json
import time
from hashlib import md5
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Hash import MD5, SHA1, SHA256
from Crypto.Cipher import AES
import base64
import string
import random


def toSortedString(map):
    d = sorted(map.items(), key=lambda x: x[0])
    res = ""
    for k, v in d:
        res += f"{k}={v}&"
    res = res[:-1]
    return res


def sign(data, privateKey):
    """
    签名
    """
    # from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
    rsa_key = RSA.importKey(privateKey)
    signer = PKCS1_signature.new(rsa_key)

    # #1. SIGNATURE_ALGORITHM: "MD5withRSA"
    # hash_obj = MD5.new(data.encode('utf-8'))

    #2. SIGNATURE_ALGORITHM: "SHA1withRSA"
    hash_obj = SHA1.new(data.encode('utf-8'))

    # #3. SIGNATURE_ALGORITHM: "SHA256withRSA"
    # hash_obj = SHA256.new(data.encode('utf-8'))

    signature = base64.b64encode(signer.sign(hash_obj))
    return signature.decode("utf-8")

    


def verify(data, signature, publicKey):
    """
    验签
    """
    # from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
    rsa_key = RSA.importKey(publicKey)
    verifier = PKCS1_signature.new(rsa_key)
    h = SHA1.new(data.encode('utf-8'))
    if verifier.verify(h, base64.b64decode(signature.encode("utf-8"))):
        return True
    return False



def parse(value):
    """
    补足 16 位
    """
    while len(value) % 16 != 0:
        value += '\0'
    return str.encode(value)


def encrypt(content, key):
    """
    AES 加密
    """
    # print(content, key)
    aes = AES.new(parse(key), AES.MODE_ECB)
    encrypt_aes = aes.encrypt(parse(content))
    # print(encrypt_aes)
    encrypted_text = str(base64.encodebytes(encrypt_aes), encoding='utf-8')
    # print(encrypted_text)
    return encrypted_text


def decrypt(content, key):
    """
    AES 解密
    """
    aes = AES.new(parse(key), AES.MODE_ECB)
    base64_decrypted = base64.decodebytes(content.encode(encoding='utf-8'))
    decrypted_text = str(aes.decrypt(base64_decrypted), encoding='utf-8').replace('\0', '')
    return decrypted_text


def generateAesKey():
    """
    生成 AES 密钥: 16 位随机字符(字母大小写 + 数字)
    """
    return ''.join(random.sample(string.ascii_letters + string.digits, 16))


def encryptRSA(content, publicKey):
    """
    RSA 加密
    """
    # from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
    rsa_key = RSA.importKey(publicKey)
    cipher = PKCS1_cipher.new(rsa_key)
    encrypted_text = base64.b64encode(cipher.encrypt(content.encode("utf-8")))
    return encrypted_text.decode('utf-8')


def decryptRSA(content, privateKey):
    """
    RSA 解密
    """
    # from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
    rsa_key = RSA.importKey(privateKey)
    cipher = PKCS1_cipher.new(rsa_key)
    decrypted_text = cipher.decrypt(base64.b64decode(content), 0)
    return decrypted_text.decode("utf-8")



def buildParams(params, publicKey, privateKey):
    print(f"原始 params: {params}\n")
    map = {}
    timestamp = time.time()

    map["params"] = params
    map["timestamp"] = timestamp

    plain = toSortedString(map)
    md5_data = md5(plain.encode("utf-8")).hexdigest()
    print(f"签名前的 md5_data: {md5_data}\n")

    signature = sign(md5_data, privateKey)
    print(f"签名: {signature}\n")

    map["sign"] = signature

    # 对params进行AES加密
    aesKey = generateAesKey()
    print(f"原始 aesKey: {aesKey}\n")

    map["params"] = encrypt(params, aesKey)

    # #对AES密钥进行RSA加密
    aesKey = encryptRSA(aesKey, publicKey)
    print(f"RSA 加密后的 aesKey: {aesKey}\n")

    map["key"] = aesKey
    return map


def verifyParams(data, publicKey, privateKey):
    asekey = decryptRSA(data["key"], privateKey)
    print(f"RSA 解密后的 asekey: {asekey}\n")

    decrypted_params = decrypt(data["params"], asekey)
    print(f"AES 解密后的 params: {decrypted_params}\n")

    plain = toSortedString({"params": decrypted_params, "timestamp": data["timestamp"]})
    md5_data = md5(plain.encode("utf-8")).hexdigest()
    print(f"验签入参 md5_data: {md5_data}\n")
    print(f"验签入参 sign: {data['sign']}\n")

    return verify(md5_data, data["sign"], publicKey)



if __name__ == "__main__":
    # A 和 B分别持有自己的密钥对以及对方的公钥
    # 私钥签名, 公钥验签 
    # 公钥加密, 私钥解密

    # A:
    publicKey1 = open("public1.pem", "r").read()
    privateKey1 = open("private1.pem", "r").read()

    # B:
    publicKey2 = open("public2.pem", "r").read()
    privateKey2 = open("private2.pem", "r").read()

    params = json.dumps({'a': 1, 'b': 2})

    # B: 构造参数, 发起请求
    data = buildParams(params, publicKey1, privateKey2)  # publicKey1 加密 aesKey, privateKey2 对参数签名
    print(f"构造的参数: {data}\n")

    # A: 收到请求, 验正参数
    ok = verifyParams(data, publicKey2, privateKey1) # publicKey2 验证签名, privateKey1 解密 aesKey
    print(f"验正参数: {ok}\n")



    

    



