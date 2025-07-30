import grpc
import hashlib
import ca_pb2
import ca_pb2_grpc
import ca
from concurrent.futures import ThreadPoolExecutor
import threading
import time
from Crypto.Util import number

class Client(ca_pb2_grpc.CAService):
    def __init__(self, client_id):
        self.client_id = client_id
        self.public_key, self.private_key = ca.generate_rsa_keys(3072)

        self.publicKeyOfOtherClient = (-1, -1)

    def setPublicKeyOfOtherClient(self, publicKey):
        self.publicKeyOfOtherClient = publicKey

def verify(message, signature, public_key):
    n, e = public_key
    hash = int.from_bytes(hashlib.sha256(message).digest(), byteorder='big')
    decrypted_sign = pow(signature, e, n)
    return decrypted_sign == hash

def encrypt(message, public_key):
    n, e = public_key
    #Converting the message to an integer
    message_int = int.from_bytes(message.encode('utf-8'), byteorder='big')
    #Encrypting the message
    enc_message = pow(message_int, e, n)
    return enc_message

def decrypt(encrypted_message, private_key):
    n, d = private_key
    #Decrypting the message
    dec_message_int = pow(encrypted_message, d, n)
    #Converting the decrypted integer back to bytes, then decoding to a string
    dec_message_bytes = dec_message_int.to_bytes((dec_message_int.bit_length() + 7) // 8, byteorder='big')
    dec_message = dec_message_bytes.decode('utf-8')
    return dec_message

def check_certificates(certificate, check_interval=3):
    while True:
        if not is_certificate_valid(certificate):
            break
            #Handling expiration (e.g., notify, renew, etc.)
        time.sleep(check_interval)  #Wait before the next check

def is_certificate_valid(certificate):
    current_time = int(time.time())
    issue_time = certificate['timestamp']
    valid_duration = certificate['duration']
    expiration_time = issue_time + valid_duration
    return expiration_time >= current_time

def serve():

    client_a = Client("A")

    #Creating a gRPC channel and stub to communicate with the CA server
    channel = grpc.insecure_channel('localhost:50052')
    stub = ca_pb2_grpc.CAServiceStub(channel)

    #Ask public key from CA
    response = stub.RequestCAPublicKey(ca_pb2.CAPublicKeyRequest(clientId=client_a.client_id))
    if response:
        client_a.ca_public_key = (int(response.n), int(response.d))
    else:
        print("Failure in retrieving the CA Public Key")

    #Register client A with the CA server
    regResponse = stub.RegisterClient(ca_pb2.RegisterClientRequest(clientId=client_a.client_id, n=str(client_a.public_key[0]), e=str(client_a.public_key[1])))
    if regResponse:
        print("Client A has been registered successfully")
        print()
    else:
        print("Failure in registering client A")

    input("Register client B with the CA server and press Enter to continue")

    #Request certificate of B from the CA server
    message = "CA_B"
    client_id = message[3:]
    response = stub.RequestCertificate(ca_pb2.CertificateRequest(clientId=client_id))
    if response:
        print("Received certificate of Client B from CA server")
        print()
    else:
        print("Couldn't get certificate of Client B from CA server")

    #Verifying the certificate using CA's public key
    certificate_data = {
            'id': response.id,
            'n': response.n,
            'e': response.e,
            'timestamp': response.timestamp,
            'duration': response.duration,
            'caId': response.caId
        }
    
    message = str(certificate_data).encode('utf-8')
    receivedSignature = int(response.signature)
    thread = None
    if verify(message, int(receivedSignature), client_a.ca_public_key):
        print("Certificate has been verified")
        #Starting the background thread for monitoring certificates
        thread = threading.Thread(target=check_certificates, args=(certificate_data, certificate_data['duration']))
        thread.daemon = True  
        thread.start()
        client_a.setPublicKeyOfOtherClient((int(response.n), int(response.e)))
        print()
    else:
        print("Invalid certificate")

    input("Press Enter to send encrypted message from A to B")

    #sending encrypted message from A to B
    encrypted_messages = ["kuch kuch hota hai, tum nahi samjhoge", "main apni favourite hun", "25 din mein paisa double"]

    #Creating a gRPC channel and stub to communicate with the B
    channelB = grpc.insecure_channel('localhost:50051')
    stubB = ca_pb2_grpc.MessageExchangeServiceStub(channelB)
    for message in encrypted_messages:
        #Checking if thread is alive
        if thread.is_alive():
            print("Certificate of Client B is still active.")
        else:
            print("The Certificate of Client B has expired. Exiting...")
            break
        #encrypting message using B's public key
        enc_message = encrypt(message, client_a.publicKeyOfOtherClient)
        enc_response = stubB.ReceiveEncryptedMessage(ca_pb2.EncryptedMessage(message=str(enc_message)))
        if enc_response.response == "expiredCertificate":
            print("Sorry, cannot process request due to Certificate Expiration")
            break
        #decrypting the encrypted_response received from B
        dec_response = decrypt(int(enc_response.response), client_a.private_key)
        print(f"Decrypted Response: {dec_response}")


if __name__ == '__main__':
    serve()