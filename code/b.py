import grpc
import hashlib
import ca_pb2
import ca_pb2_grpc
import ca
import a
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

class MessageExchangeService(ca_pb2_grpc.MessageExchangeServiceServicer):
    def __init__(self, private_key, public_keyOfOtherClient, certificateA):
        self.private_key = private_key
        self.publicKeyOfOtherClient = public_keyOfOtherClient
        self.certificateA = certificateA
        self.duration = certificateA['duration']

        #Starting the background thread for monitoring certificates
        self.thread = threading.Thread(target=a.check_certificates, args=(self.certificateA, self.duration))
        self.thread.daemon = True  
        self.thread.start()

    def ReceiveEncryptedMessage(self, request, context):
        #Decrypting the message using B's private key
        dec_message = a.decrypt(int(request.message), self.private_key)
        print(f"Decrypted message received: {dec_message}")

        ack = ""
        if dec_message == "kuch kuch hota hai, tum nahi samjhoge":
            ack = "Acknowledged 1st message"
        elif dec_message == "main apni favourite hun":
            ack = "Acknowledged 2nd message"
        elif dec_message == "25 din mein paisa double":
            ack = "Acknowledged 3rd message"

        #encrypting the acknowledgment
        ack_encrypted = a.encrypt(ack, self.publicKeyOfOtherClient)
        
        #Checking if the thread is alive
        if self.thread.is_alive():
            print("Certificate of Client B is still active.")
        else:
            print("The Certificate of Client B has expired. Exiting...")
            return ca_pb2.Acknowledgement(response=str("expiredCertificate"))
        return ca_pb2.Acknowledgement(response=str(ack_encrypted))

def serve():

    client_b = Client("B")

    #Creating a gRPC channel and stub to communicate with the CA server
    channel = grpc.insecure_channel('localhost:50052')
    stub = ca_pb2_grpc.CAServiceStub(channel)

    response = stub.RequestCAPublicKey(ca_pb2.CAPublicKeyRequest(clientId=client_b.client_id))
    if response:
        client_b.ca_public_key = (int(response.n), int(response.d))
    else:
        print("Failure in retrieving the CA Public Key")

    #Registering client B with the CA server
    regResponse = stub.RegisterClient(ca_pb2.RegisterClientRequest(clientId=client_b.client_id, n=str(client_b.public_key[0]), e=str(client_b.public_key[1])))
    if regResponse:
        print("Client B has been registered successfully")
        print()
    else:
        print("Failure in registering client B")

    input("Register client A with the CA server and press Enter to continue")

    #Requesting certificate of A from the CA server
    message = "CA_A"
    client_id = message[3:]
    response = stub.RequestCertificate(ca_pb2.CertificateRequest(clientId=client_id))
    if response:
        print("Received certificate of Client A from CA server")
        print()
    else:
        print("Couldn't get certificate of Client A from CA server")

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
    if a.verify(message, int(receivedSignature), client_b.ca_public_key):
        print("Certificate ha been verified")
        client_b.setPublicKeyOfOtherClient((int(response.n), int(response.e)))
        print()
    else:
        print("Invalid certificate")
        return

    server = grpc.server(ThreadPoolExecutor(max_workers=10))
    b_private_key = client_b.private_key
    
    ca_pb2_grpc.add_MessageExchangeServiceServicer_to_server(MessageExchangeService(b_private_key, client_b.publicKeyOfOtherClient, certificate_data), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("Server B is listening on port 50051...")

    server.wait_for_termination()

if __name__ == '__main__':
    serve()