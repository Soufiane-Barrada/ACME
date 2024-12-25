import requests
import cryptography
import base64
import json
import time
import sys
import Certificate_server
import Shutdown_server
import Challenge_server
import threading
import os
from cryptography.hazmat.primitives._serialization import Encoding
from dns import MyResolverw
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography import x509
from cryptography.x509.oid import NameOID


dirURI = 'https://localhost:14000/dir'
domains=[]
domain1 = 'netsec.ethz.ch'
domain2 = 'syssec.ethz.ch'
ipv4_address = '1.2.3.4'
challenge_type = "dns01"
revoke=False

count=1
for arg in sys.argv:
    if(count==1):
        count=2
    elif count==2:
        challenge_type=arg
        count=0
    elif arg=="--dir":
        count=3
    elif count==3:
        dirURI=arg
        count=0
    elif arg=="--record":
        count=4
    elif count==4:
        ipv4_address=arg
        count=0
    elif arg=="--domain":
        count=5
    elif count==5:
        domains.append(arg)
        count=0
    elif arg=="--revoke":
        revoke=True

if len(domains)==0:
    domains=[domain1]

#test
print("dirURI: ", dirURI)
print("domains: ",domains)
print("record: ",ipv4_address)
print("challenge_type: ",challenge_type)
print()



cert = 'pebble.minica.pem'
#START Shutdown server
shut_srv=Shutdown_server.start(ipv4_address)
shut_srv.start()
time.sleep(1)

##############################################################################################
def requestURIs(dirURL, cert):
    response = requests.get(dirURL, verify=cert)

    # Check the response
    if response.status_code == 200:
        file = response.json()
        newAccount = file.get('newAccount', 'PROBLEM')
        newNonce = file.get('newNonce', 'PROBLEM')
        newOrder = file.get('newOrder', 'PROBLEM')
        revokeCert = file.get('revokeCert', 'PROBLEM')

    return newAccount, newNonce, newOrder, revokeCert




def requestNonce(newNonce, cert):
    response = requests.head(newNonce, verify=cert)
    # Check the response
    if response.status_code == 200:
        print("requestNonce was successful.")
        content = response.headers.get('Replay-Nonce')
        print("Nonce:", content)
    else:
        print(f"requestNonce failed with status code {response.status_code}.")
        print("Failure:", response.text)

    return content





def generateES256Keys():
    privateKey = ec.generate_private_key(ec.SECP256R1(), default_backend())
    publicKey = privateKey.public_key()

    public_key_pem = publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo)

    publicKeybase64 = base64.urlsafe_b64encode(public_key_pem).decode('utf-8').rstrip("=")

    #print("Private key: ", privateKey)
    #print("Public key: ", publicKey)
    #print("Public Key PEM: ", public_key_pem)
    #print("Public Key base64: ", publicKeybase64)

    return privateKey, publicKey, publicKeybase64





def sign(message, privateKey, publicKey):
    signature = privateKey.sign(message,ec.ECDSA(hashes.SHA256()))

    return signature


def make_keyAuth(token,publicKey):
    public_key_x = base64.urlsafe_b64encode(publicKey.public_numbers().x.to_bytes(32, byteorder='big')).decode(
        'utf-8').rstrip("=")
    public_key_y = base64.urlsafe_b64encode(publicKey.public_numbers().y.to_bytes(32, byteorder='big')).decode(
        'utf-8').rstrip("=")
    jwk_ = {"crv": "P-256",
        "kty": "EC",
        "x": public_key_x,
        "y": public_key_y}

    jwk_json = json.dumps(jwk_, separators=(',', ':'), sort_keys=True).encode('utf-8')

    digest = hashes.Hash(hashes.SHA256())
    digest.update(jwk_json)
    hash_jwk_json = digest.finalize()

    thumbprint_base64 = base64.urlsafe_b64encode(hash_jwk_json).decode('utf-8').rstrip("=")
    key_authorization_org = f"{token}.{thumbprint_base64}"

    key_authorization = key_authorization_org.encode('ascii') #recheck
    digest2 = hashes.Hash(hashes.SHA256())
    digest2.update(key_authorization)
    key_authorization = digest2.finalize()
    print("type after hash: ",type(key_authorization))
    #key_authorization = key_authorization.encode('utf-8')

    key_authorization= base64.urlsafe_b64encode(key_authorization).decode('utf-8').rstrip("=")

    print("Key authorization Orginal is: ", key_authorization_org)
    print("Key authorization is: ", key_authorization)
    print()
    return key_authorization, key_authorization_org

def makeJWS(nonce, url, private_key, public_key, jwk=True, payload="", accountURL=""):
    protected_header = {}
    if (jwk):

        public_key_x = base64.urlsafe_b64encode(public_key.public_numbers().x.to_bytes(32, byteorder='big')).decode(
            'utf-8').rstrip("=")
        public_key_y = base64.urlsafe_b64encode(public_key.public_numbers().y.to_bytes(32, byteorder='big')).decode(
            'utf-8').rstrip("=")

        protected_header = {
            "alg": "ES256",
            "nonce": nonce,
            "jwk": {
                "kty": "EC",
                "crv": "P-256",
                "x": public_key_x,
                "y": public_key_y
            },
            "url": url
        }

    else:
        protected_header = {
            "alg": "ES256",
            "nonce": nonce,
            "kid": accountURL,
            "url": url
        }

    #print("protected_header: ", protected_header)

    json_protected_header = json.dumps(protected_header, separators=(',', ':'), sort_keys=True).encode('utf-8')

    if(payload!=""):
        if(payload=="{}"):
            json_payload= payload.encode('utf-8')
        else:
            json_payload= json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    else:
        json_payload= "".encode('utf-8')


    protected_header_base64 = base64.urlsafe_b64encode(json_protected_header).decode('utf-8').rstrip("=")
    payload_base64 = base64.urlsafe_b64encode(json_payload).decode('utf-8').rstrip("=")


    jws_message = f"{protected_header_base64}.{payload_base64}"
    #print("jws_message: ",jws_message)

    signature = private_key.sign(jws_message.encode('ascii'), ec.ECDSA(hashes.SHA256()))  # utf-8 or ascii?
    r, s = utils.decode_dss_signature(signature)
    # print()
    # print("R :", r)
    # print("S :", s)
    print()
    r_octet = r.to_bytes((r.bit_length() + 7) // 8, byteorder='big')
    s_octet = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big')
    # print("R (big-endian octet sequence):", r_octet)
    # print("S (big-endian octet sequence):", s_octet)
    # print()
    rs_concatenated = r_octet + s_octet
    #print("R||S (big-endian octet sequence):", rs_concatenated)
    # rs_concatenated_base64 = base64.urlsafe_b64encode(rs_concatenated).decode('utf-8').rstrip("=")

    signature_base64 = base64.urlsafe_b64encode(rs_concatenated).decode('utf-8').rstrip("=")

    jws_message = {
        "protected": protected_header_base64,
        "payload": payload_base64,
        "signature": signature_base64
    }
    jws_message = json.dumps(jws_message, separators=(',', ':'), sort_keys=True)

    #print("jws_message: ", jws_message)

    return jws_message

def send(uri,jws,accepted,mess):
    response = requests.post(uri, data=jws, headers={"Content-Type": "application/jose+json"}, verify=cert)
    print()
    if response.status_code == accepted:
        print(f"{mess} was successful.")
        print("Response content:", response.text)
    else:
        print(f"{mess} failed with status code {response.status_code}.")
        print("Failure:", response.text)
    print()

    return response

def poll( url, nonce, privateKey, publicKey,accountURL,expected=[],ord=False):
    """Polls url until it gets back an expected answer.

        Parameters
        ----------
        url : str
            url to poll
        nonce : str
            A nonce
        privateKey:  EllipticCurvePrivateKey

        publicKey: EllipticCurvePublicKey

        accountURL: str
            the AcmeClient account URL
        expected: list of strings
            list of wanted responses
        ord: bool
            Whether the polling is done on the Order URL.
        Returns
        -------
        obj,str,str
            Tuple of response object, new nonce, and certificate URL (if polling for an order).
        """
    cert_url=""
    while True:
        payload = ""
        jws = makeJWS(nonce, url, privateKey, publicKey, False, payload, accountURL)
        response = requests.post(url, data=jws, headers={"Content-Type": "application/jose+json"}, verify=cert)
        file = response.json()
        stat = file["status"]
        if response.status_code == 200 and stat in expected:
            print(f"Polling successful.")
            print("Response content:", response.text)
            print()
            nonce = response.headers.get('Replay-Nonce')
            if ord:
                cert_url = file["certificate"]
            return response, nonce,cert_url
        else:
            print("poll content:", response.text)

        nonce = response.headers.get('Replay-Nonce')

        time.sleep(1)
##################################################################################################

#START DNS
myresolver = MyResolverw(ipv4_address,domains)
mylogger = DNSLogger("request,reply,truncated,error", False)
myserver = DNSServer(myresolver, "0.0.0.0",10053,logger=mylogger)
myserver.start_thread()
time.sleep(2)

# GET the URIs from the /dir
newAccountURI, newNonceURI, newOrderURI, revokeCertuRI = requestURIs(dirURI, cert)
print()


# GET a Nonce for the first request
nonce = requestNonce(newNonceURI, cert)
print()


# GENERATE key pair
privateKey, publicKey, publicKeybase64 = generateES256Keys()
print()


# CREATE Account
payload = {"termsOfServiceAgreed": True}
jws = makeJWS(nonce, newAccountURI, privateKey, publicKey, True, payload,"")
response= send(newAccountURI,jws,201,"Account Creation")
nonce = response.headers.get('Replay-Nonce')
accountURL = response.headers.get('Location')
print()


# APPLY for certificate issuance
identifiers=[]
for dom in domains:
    identifiers.append({"type": "dns", "value": dom})

payload = {"identifiers": identifiers}
jws = makeJWS(nonce, newOrderURI, privateKey, publicKey, False, payload,accountURL)
response= send(newOrderURI,jws,201,"Application for certificate")
nonce = response.headers.get('Replay-Nonce')
file=response.json()
authorizations=file.get("authorizations","PROBLEM")
order= response.headers.get("Location")
print("authorizations:  ", authorizations)
finalize = file.get("finalize","PROBLEM")
print("finalize: ", finalize)
print()
time.sleep(2)


#DOWNLOADING authorization resources
number_of_domains= len(domains)
challenges_url=[]
tokens=[]
for authorization in authorizations:
    payload = ""
    jws = makeJWS(nonce, authorization, privateKey, publicKey, False, payload,accountURL)
    response = send(authorization,jws,200,"Download of authorization resources")
    nonce = response.headers.get('Replay-Nonce')
    file = response.json()
    file = file.get("challenges","PROBLEM")
    token=""
    challenge_url=""
    if challenge_type == "dns01":
        for jf in file:
            if(jf.get("type") == "dns-01"):
                token = jf.get("token","PROBLEM")
                challenge_url= jf.get("url","PROBLEM")
                #print("The token is: ", token)
                #print("The challenge URL is: ", challenge_url)
                break
    elif(challenge_type == "http01"):
        for jf in file:
            if(jf.get("type") == "http-01"):
                token = jf.get("token","PROBLEM")
                challenge_url= jf.get("url","PROBLEM")
                #print("The token is: ", token)
                #print("The challenge URL is: ", challenge_url)
                break

    challenges_url.append(challenge_url)
    tokens.append(token)
    time.sleep(2)
    print()

#START the https server
chal_srv=Challenge_server.start(ipv4_address)
chal_srv.start()
time.sleep(2)



#MAKE the Key Authorization
keyAuths=[]
for token in tokens:
    kaA,kaO = make_keyAuth(token,publicKey)
    keyAuths.append(kaA)
    if challenge_type == "dns01":
        myresolver.add_keyAuth(kaA)
    if challenge_type == "http01":
        Challenge_server.add_token_keyAuth(token,kaO)
print()


#CHALLENGES
# DNS challenge
if challenge_type == "dns01":
    for i in range(number_of_domains):
        payload = "{}"
        jws = makeJWS(nonce, challenges_url[i], privateKey, publicKey, False, payload, accountURL)
        response = send(challenges_url[i], jws,200, "DNS challenge")
        nonce = response.headers.get('Replay-Nonce')

#HTTP challenge
if challenge_type == "http01":
    for i in range(number_of_domains):
        payload = "{}"
        jws = makeJWS(nonce, challenges_url[i], privateKey, publicKey, False, payload, accountURL)
        response = send(challenges_url[i], jws,200, "HTTP challenge")
        nonce = response.headers.get('Replay-Nonce')



# CERTIFICATE + FINALIZE --
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
# Generate a CSR
x509_domains=[]
for dom in domains:
    x509_domains.append(x509.DNSName(dom))

csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "CH"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Zürich"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, u"Zürich"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ETHZ"),
    x509.NameAttribute(NameOID.COMMON_NAME, "acme")
])).add_extension(x509.SubjectAlternativeName(x509_domains),critical=False).sign(key, hashes.SHA256())
csr_der = csr.public_bytes(Encoding.DER)
csr_der = base64.urlsafe_b64encode(csr_der).decode('utf-8').rstrip("=")


#Poll
for authorization in authorizations:
    response,nonce,_=poll(authorization,nonce,privateKey,publicKey,accountURL,["valid"])
#END of Poll

payload = {"csr":csr_der}
jws = makeJWS(nonce, finalize, privateKey, publicKey, False, payload,accountURL)
response = send(finalize,jws,200,"CSR request")
nonce = response.headers.get('Replay-Nonce')
print()

#poll
response,nonce,certificate_url =poll(order,nonce,privateKey,publicKey,accountURL,["valid"],True)
#END of poll
#END OF CERTIFICATE + FINALIZE --


#Download certificate
payload =""
jws = makeJWS(nonce, certificate_url, privateKey, publicKey, False, payload,accountURL)
response = send(certificate_url,jws,200,"Download certificate")
certificate = response.content
nonce = response.headers.get('Replay-Nonce')

with open("mykeyw.pem", "wb") as f:
    f.write(key.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,
                              encryption_algorithm=serialization.NoEncryption()))

with open("mycertw.pem", "wb") as f:
    f.write(certificate)
time.sleep(2)


#START the certificate server
cert_serv=Certificate_server.start(ipv4_address,"mycertw.pem",'mykeyw.pem')
cert_serv.start()



#REVOKE certificate
if revoke:
    certificate = x509.load_pem_x509_certificate(certificate)
    certificate= certificate.public_bytes(serialization.Encoding.DER)
    certificate= base64.urlsafe_b64encode(certificate).decode('utf-8').rstrip("=")
    payload={"certificate": certificate}
    jws = makeJWS(nonce, revokeCertuRI, privateKey, publicKey, False, payload, accountURL)
    response = send(revokeCertuRI, jws, 200, "revoke certificate")
    nonce = response.headers.get('Replay-Nonce')
time.sleep(3)


# END
myserver.stop()
cert_serv.join()
shut_srv.join()
chal_srv.join()






