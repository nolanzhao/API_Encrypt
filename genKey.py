import Crypto.PublicKey.RSA
import Crypto.Random

x = Crypto.PublicKey.RSA.generate(2048)
privateKey = x.exportKey("PEM")
publicKey = x.publickey().exportKey()

with open("private1.pem", "wb") as f:
    f.write(privateKey)

with open("public1.pem", "wb") as f:
    f.write(publicKey)
