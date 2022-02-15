import logging
import sys
import random

from stats.handler_size import *

from sss.sharing import *
from sss.sharing import secret_int_to_points, points_to_secret_int
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF



def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def mod_inverse(k, prime):
    k = k % prime
    if k < 0:
        r = egcd(prime, -k)[2]
    else:
        r = egcd(prime, k)[2]
    return (prime + r) % prime

class Client:



    def __init__(self, param):
        self.logger = logging.getLogger("fmlr." + __name__)
        self.parameters = param
        self.sk_KA = 0
        self.sk_PKE = 0
        self.pk_KA = 0
        self.pk_PKE = 0
        self.id = id(self)
        self.encrypted_shares = {}
        self.key_agreements = {}
        self.dictonary_of_pk_KAs = {}
        self.list_pk_PKEs = []
        self.encrypted_shares_secret_input = []
        self.shares_secret_input = []
        self.x = 0
        #self.bytes_in = 0
        #self.bytes_out = 0
        self.data_round_out = {}
        self.data_round_out = {1: 0, 2: 0, 3: 0, 4: 0}
        self.data_round_in = {1: 0, 2: 0, 3: 0, 4: 0}
        pass

    def generate_key_pair_KA(self):
        #self.logger.debug("client {} - generating KA".format(self.id))
        self.sk_KA = self.parameters.gen_key()#param.generate_private_key()
        self.pk_KA = self.sk_KA.public_key()
        #self.logger.debug("client : {} sk {}".format(id(self), self.sk_KA.private_numbers().private_value))




    def generate_key_pair_PKE(self):
        #self.logger.debug("client {} - generating PKE".format(self.id))
        self.sk_PKE = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.pk_PKE = self.sk_PKE.public_key()

    def return_public_keys(self):
        self.data_round_out[1] += total_size(self.pk_KA) #print("size pk_Ka {}".format(, verbose=True)))
        self.data_round_out[1] += total_size(self.pk_PKE) #sys.getsizeof(self.pk_PKE)
        #self.data_round_out[1] = self.bytes_out

        return self.pk_KA, self.pk_PKE

    def add_pk_KA(self, key, id_client):
        self.data_round_in[1] += total_size(key) #sys.getsizeof(key)
        self.dictonary_of_pk_KAs[id_client] = key

        self.data_round_in[1] += total_size(key)#sys.getsizeof(key)

    def add_pk_PKE(self, key):
        #self.bytes_in += total_size(key) #sys.getsizeof(key)
        self.list_pk_PKEs.append(key)
        self.data_round_in[1] += total_size(key)#sys.getsizeof(key)

    def generate_encrypted_secret_round_two(self):
        shares_key = self.__generate_secret_share__(self.sk_KA)
        encrypted_shares = {}
        position = 0
        for public_key in self.list_pk_PKEs:
            #print("shares_key[{}][1] = {}".format(position, shares_key[position]))
            str_i = "{}".format(shares_key[position])
            str_i_b = str_i.encode('utf-8')
            #print(str_i_b)
            encrypted = public_key.encrypt(str_i_b, padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
            position += 1
            encrypted_shares[public_key] = encrypted
            #self.bytes_out += total_size(encrypted) #sys.getsizeof(encrypted)
            self.data_round_out[2] += total_size(encrypted)#sys.getsizeof(encrypted)

        return encrypted_shares

    def __generate_secret_share__(self, secret_input):
        #self.logger.debug("client : {} breaking {}".format(id(self), self.sk_KA.private_numbers().private_value))
        shares_b = secret_int_to_points(self.sk_KA.private_numbers().private_value, self.parameters.THREASHOLD_KEY, self.parameters.SIZE_OF_DISJOINT, self.parameters.Q)
        #self.logger.debug("client {} shares {}".format(id(self), shares_b[0:4]))
        recovered = points_to_secret_int(shares_b[0:4])
        #self.logger.debug("client : {} recovered {}".format(id(self), recovered))
        return shares_b

    def __decrypt_KA_share__(self, share):
        plaintext = self.sk_PKE.decrypt(share,
                                        padding.OAEP(mgf = padding.MGF1(algorithm=hashes.SHA256()), algorithm = hashes.SHA256(),label = None ))
        #print("client {} decrpted: {} ".format(id(self), plaintext))
        return plaintext

    def decrypt_KA_shares(self):
        decrypted = {}
        for client_id in self.encrypted_shares.keys():
            share = self.encrypted_shares[client_id]
            plain = self.__decrypt_KA_share__(share)
            decrypted[client_id] = plain
        #self.bytes_out += total_size(decrypted)#sys.getsizeof(decrypted)
        self.data_round_out[4] += total_size(decrypted)#sys.getsizeof(decrypted)
        return decrypted

    def get_bytes_out(self):
        return self.bytes_out

    def get_bytes_in(self):
        return self.bytes_in

    def receive_encrypted_KA_share(self, share, id_client):
        self.encrypted_shares[id_client] = share
        #self.bytes_in += total_size(id_client) #sys.getsizeof(id_client)
        #self.bytes_in += total_size(share) #sys.getsizeof(share)
        self.data_round_in[2] += total_size(id_client)#sys.getsizeof(id_client)
        self.data_round_in[2] += total_size(share)#sys.getsizeof(share)


    def __compute_key_agreement__(self, pk_KA):
        shared_key = self.sk_KA.exchange(ec.ECDH(), pk_KA)
        return shared_key

    def compute_key_agreements(self):
        client_ids = self.dictonary_of_pk_KAs.keys()
        for client_id in client_ids:
            if client_id != id(self):
                pk_KA = self.dictonary_of_pk_KAs[client_id]
                key_agreement = self.__compute_key_agreement__(pk_KA)
                #self.logger.debug("client {} computed shared key {} with client {}".format(id(self),int.from_bytes(key_agreement, byteorder='big'), client_id))
                self.key_agreements[client_id] = int.from_bytes(key_agreement, byteorder='big')

    def compute_ss_of_secret_input(self, secret_input):
        self.x = secret_input
        self.data_round_in[3] += total_size(secret_input)
        self.shares_secret_input = secret_int_to_points(secret_input, self.parameters.THREASHOLD, self.parameters.NR_SERVER, self.parameters.Q)

    def compute_tau_rho_secret_input(self):
        r_prime = random.randint(2, self.parameters.Q-1)
        r_two_prime = self.parameters.Q - r_prime - 1
        assert r_prime + r_two_prime == self.parameters.Q - 1
        #self.logger.debug("client {} - r_prime {}".format(id(self), r_prime))
        #self.logger.debug("client {} - r_two_prime {}".format(id(self), r_two_prime))
        tau = (pow(self.parameters.GENERATOR, self.x,  self.parameters.Q) * pow(self.parameters.GENERATOR, r_prime,  self.parameters.Q)) % self.parameters.Q
        #self.logger.debug("client {} computed tau {}".format(id(self), tau))
        tmp_rho = pow(self.parameters.GENERATOR, r_two_prime,  self.parameters.Q)
        #self.logger.debug("client {} computed tmp_rho {}".format(id(self), tmp_rho))
        prod_1 = 1
        prod_2 = 1
        client_ids = self.key_agreements.keys()
        for client_id in client_ids:
            inverse = mod_inverse(self.key_agreements[client_id], self.parameters.Q)
            #self.logger.debug("client {} computed inverse {}".format(id(self), inverse))
            if id(self) < client_id:
                prod_1 = (prod_1 * self.key_agreements[client_id]) % self.parameters.Q
            elif id(self) > client_id:
                prod_2 = (prod_2 * inverse) % self.parameters.Q

        #self.logger.debug("client {} computed prod_1 {}".format(id(self), prod_1))
        #self.logger.debug("client {} computed prod_2 {}".format(id(self), prod_2))

        rho = (tmp_rho * prod_1 * prod_2) % self.parameters.Q

        #self.logger.debug("client {} computed rho {}".format(id(self), rho))

        #self.bytes_out += total_size(tau) #sys.getsizeof(tau)
        #self.bytes_out += total_size(rho)#sys.getsizeof(rho)
        #self.bytes_out += total_size(self.shares_secret_input)#sys.getsizeof(self.shares_secret_input)
        self.data_round_out[3] += total_size(tau)
        self.data_round_out[3] += total_size(self.shares_secret_input)#sys.getsizeof(self.shares_secret_input)
        self.data_round_out[3] += total_size(rho)#sys.getsizeof(rho)
        return tau, rho, self.shares_secret_input







