import ascon
from diffiehellman import DiffieHellman
from twisted.internet import task
from twisted.internet.defer import Deferred
from twisted.internet.protocol import ClientFactory
from twisted.protocols.basic import LineReceiver


class EchoClient(LineReceiver):
    end = b"Bye-bye!"
    keyMsg = "key"
    dh = DiffieHellman(group=14, key_bits=16)
    dh_public = dh.get_public_key()
    dh_shared = 0
    #print(len(dh_public))

    nonce = b'qc\xb3\x0bJ\x92\xaf{\xee\r\x1a\x94d\x04o\xf8'
    associatedData = b"SENSOR"
    dataTemperature= b"2,4,10,20,30,50,99"


    def connectionMade(self):
        # Cuando conecta cliente a server, le manda su llave publica
        print("SENDING CLIENT PUBLIC KEY TO SERVER")
        self.sendLine(self.dh_public)
        #self.sendLine(self.end)

    def lineReceived(self, line):
        #print("receive:", line)
        # Si recibe llave publica del server, procede a generar
        # llave compartida de DH y manda los datos encriptados por Ascon.
        if len(line) == 256:
            self.dh_shared = self.dh.generate_shared_key(line)
            #print("Received PUBLICK KEY:", line)
            print("Now I have shared key and will send data !!")
            encryptedTemp= ascon.ascon_encrypt(key=self.dh_shared[:16], nonce=self.nonce, associateddata=self.associatedData,
                                                plaintext= self.dataTemperature, variant="Ascon-128")
            print("Encrypted Data: ", encryptedTemp)
            #print(self.dh_shared[:16])
            self.sendLine(encryptedTemp)

        if line == self.end:
            self.transport.loseConnection()



class EchoClientFactory(ClientFactory):
    protocol = EchoClient

    def __init__(self):
        self.done = Deferred()

    def clientConnectionFailed(self, connector, reason):
        print("connection failed:", reason.getErrorMessage())
        self.done.errback(reason)

    def clientConnectionLost(self, connector, reason):
        print("connection lost:", reason.getErrorMessage())
        self.done.callback(None)


def main(reactor):
    factory = EchoClientFactory()
    reactor.connectTCP("localhost", 8000, factory)
    return factory.done


if __name__ == "__main__":
    task.react(main)
