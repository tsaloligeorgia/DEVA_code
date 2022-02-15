import logging, sys, hashlib, random

from sss.sharing import secret_int_to_points, points_to_secret_int

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from stats.handler_size import *

def concat_number(numbers):
    #print("bytes = {} ".format(numbers[0].to_bytes(sys.getsizeof(numbers[0]), 'big')))
    a = bytearray()

    for number in numbers:
        tmp = number.to_bytes(sys.getsizeof(number), 'big')
        a += tmp
    return a

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


class Server:

    def __init__(self, params, id):
        self.id = id
        self.logger = logging.getLogger("fmlr." + __name__)
        self.param = params
        self.clients_list = []
        self.public_keys_KA = {}
        self.public_keys_PKE = {}
        self.encrypted_keys = {}
        self.rho_clients = {}
        self.tau_clients = {}
        self.shares_from_clients = {}
        self.decrypted_shares = {}
        #self.bytes_in = 0
        #self.bytes_out = 0
        self.data_round_out = {1: 0, 2: 0, 3: 0, 4: 0}
        self.data_round_in = {1: 0, 2: 0, 3: 0, 4: 0}
        pass

    def add_client(self, client):
        self.logger.debug("server:{} - adding client: {} to list".format(id(self), id(client)))
        self.clients_list.append(client)

    def collect_pks(self):
        for client in self.clients_list:
            #self.bytes_in += sys.getsizeof()
            pk_KA, pk_PKE = client.return_public_keys()
            self.data_round_in[1] += total_size(pk_KA) #sys.getsizeof(pk_KA)
            self.data_round_in[1] += total_size(pk_PKE) #sys.getsizeof(pk_PKE)
            self.public_keys_KA[id(client)] = pk_KA
            self.public_keys_PKE[id(client)] = pk_PKE

    def share_keys(self):
        for client in self.clients_list:
            for id_client in self.public_keys_KA.keys():
                if id(client) != id_client:
                    self.data_round_out[1] += total_size(self.public_keys_KA[id_client]) #sys.getsizeof(self.public_keys_KA[id_client])
                    self.data_round_out[1] += total_size(self.public_keys_PKE[id_client])#sys.getsizeof(self.public_keys_PKE[id_client])
                    client.add_pk_KA(self.public_keys_KA[id_client], id_client)
                    client.add_pk_PKE(self.public_keys_PKE[id_client])
        #self.data_round_out[1] = self.bytes_out

    def receive_encrypted_shares(self, client, encrypted_shares):
        #self.logger.debug("Receiving encrypted shares from client {}: shares:{}".format(id(client), encrypted_shares))
        #bytes_in += total_size(encrypted_shares) #sys.getsizeof(encrypted_shares)
        self.encrypted_keys[client] = encrypted_shares
        self.data_round_in[2] += total_size(encrypted_shares)

    def send_encrypted_shares(self):
        #self.logger.debug("server: {} sending shares".format(id(self)))
        clients = self.encrypted_keys.keys()
        for client in clients:
           # self.logger.debug("client {} sending shares".format(id(client)))
            shares = self.encrypted_keys[client]
            for client_receiver in clients:
                if id(client) != id(client_receiver):
                    #self.logger.debug("sending shares to: {}".format(id(client_receiver)))
                    client_receiver.receive_encrypted_KA_share(shares[self.public_keys_PKE[id(client_receiver)]], id(client))
                    self.data_round_out[2] += total_size(shares[self.public_keys_PKE[id(client_receiver)]])#sys.getsizeof(shares[self.public_keys_PKE[id(client_receiver)]])
                    self.data_round_out[2] += total_size(id(client))#sys.getsizeof(id(client))
        #self.data_round_out[2] = self.bytes_out

    def receive_tau_rho(self, client, rho, tau):
        #self.logger.debug("server {} receiving {} {} from {}".format(id(self), rho, tau, id(client)))
        self.rho_clients[client] = rho
        self.tau_clients[client] = tau
        #self.bytes_in += total_size(rho)#sys.getsizeof(rho)
        #self.bytes_in += total_size(tau) #sys.getsizeof(tau)
        self.data_round_in[3] += total_size(rho) #sys.getsizeof(rho)
        self.data_round_in[3] += total_size(tau) #sys.getsizeof(tau)


    def return_rho_is(self):
        #self.bytes_out += total_size(self.rho_clients)#sys.getsizeof(self.rho_clients)
        return self.rho_clients

    def return_tau_is(self):
        #self.bytes_out += total_size(self.tau_clients) #sys.getsizeof(self.tau_clients)
        return self.tau_clients

    def receive_share_from_client(self, share, client):
        #self.logger.debug("server {} receiving share {} from {}".format(id(self), share, id(client)))
        self.shares_from_clients[client] = share
        #self.bytes_in += total_size(share) #sys.getsizeof(share)
        #self.bytes_in += total_size(client) #sys.getsizeof(client)
        self.data_round_in[3] += total_size(share) #sys.getsizeof(share)
        #self.data_round_in[3] += total_size(client) #sys.getsizeof(client)

    def add_decrypted_shares(self, client, decrypted_shares):
        self.decrypted_shares[client] = decrypted_shares
        #self.bytes_in += total_size(decrypted_shares) #sys.getsizeof(decrypted_shares)
        for share in decrypted_shares:
            self.data_round_in[4] += total_size(share) #sys.getsizeof(decrypted_shares)

    def get_bytes_out(self):
        return self.bytes_out

    def get_bytes_in(self):
        return self.bytes_in

    def __find_fault_clients__(self):

        clients_set_3 = list(self.rho_clients.keys())
        clients_set_2 = self.encrypted_keys.keys()
        fault_clients = []
        for client in clients_set_2:
            if client not in clients_set_3:
                fault_clients.append(client)
        self.clients_list = clients_set_3

        return fault_clients


    def __evaluate_shared_keys__(self, fault_clients):
        clients_set_4 = self.decrypted_shares.keys()
        shares_to_recover = {}
        for f_client in fault_clients:
            shares_to_recover[f_client] = []
            self.logger.debug("Server {} fault client : {} ".format(id(self), id(f_client)))

        for client in clients_set_4:
            decrypted_key = self.decrypted_shares[client]
            self.logger.debug("Server {} client : {}  decrypted_key: {} ".format(id(self), id(client), decrypted_key))
            pos = 0
            for f_client in fault_clients:
                if id(f_client) != id(client):
                    f_decrypted_key = decrypted_key[id(f_client)]
                    #print("f_decrypted_key  {}".format(f_decrypted_key.decode()))
                    my_str = f_decrypted_key.decode().replace("(", "")
                    my_str = my_str.replace(")", "")
                    my_str = my_str.split(",")
                    shares_to_recover[f_client].append((int(my_str[0]), int(my_str[1])))
                    pos += 1
        self.logger.debug("Server : {} recovering {}".format(id(self), shares_to_recover))
        recovered_key = {}
        for f_client in fault_clients:
            shares = shares_to_recover[f_client]
            sk_KA = points_to_secret_int(shares, self.param.Q)
            recovered_key[f_client] = sk_KA
        self.logger.debug("Server : {} recovered {}".format(id(self), recovered_key))
        return recovered_key



    def __compute_zis__(self, sk_KA_keys):
        z_is = {}
        clients_set_3 = self.rho_clients.keys()
        for f_client in sk_KA_keys.keys():
            zi = 1
            for client in clients_set_3:
                if id(f_client) != id(client):
                    #print(type(self.public_keys_KA[id(client)]))
                    self.logger.debug("server {}  sk_KA_keys[f_client] {} self.public_keys_KA[id(client)].public_numbers().y {}".format(id(self), sk_KA_keys[f_client], self.public_keys_KA[id(client)].public_numbers().y ))
                    #pn = dh.DHParameterNumbers(self.param.Q, self.param.param.parameter_numbers().g)
                    public_k = self.public_keys_KA[id(f_client)]
                    peer_private_key = ec.EllipticCurvePrivateNumbers(sk_KA_keys[f_client], public_k.public_numbers())
                    shared_key = peer_private_key.private_key().exchange(ec.ECDH(), self.public_keys_KA[id(client)])
                    #key_agreement = pow(self.public_keys_KA[id(client)].public_numbers().y, , self.param.Q)
                    self.logger.debug("key agreement: {}".format(shared_key))
                    #
                    key_agreement = int.from_bytes(shared_key, byteorder='big')
                    self.logger.debug("key agreement: {}".format(key_agreement))
                    if id(client) < id(f_client):
                        inverse = mod_inverse(key_agreement, self.param.Q)
                        zi = (zi*inverse) % self.param.Q
                    else:
                        zi = (zi*key_agreement) % self.param.Q
                #print("zi: {}".format(zi))
            z_is[f_client] = zi
        return z_is

    def __compute_omegas__(self, fault_clients):
        clients_set_3 = self.rho_clients.keys()
        omega_is = {}
        for f_client in fault_clients:
            omega_i = 1
            for client in clients_set_3:
                public_key = self.public_keys_KA[id(client)].public_numbers().y
                if id(client) < id(f_client):
                    inverse = mod_inverse(public_key, self.param.Q)
                    omega_i = (omega_i * inverse) % self.param.Q
                else:
                    omega_i = (omega_i * public_key) % self.param.Q
            omega_is[f_client] = omega_i
        return omega_is

    def DLEQ_verif(self, proof,  parameters):
        g = proof[0]
        h = proof[1]
        A = proof[2]
        B = proof[3]
        s1 = proof[4]
        s2 = proof[5]
        r = proof[6]
        print("DLEQ_verif")
        l = [g, h, A, B, s1, s2]
        bytes_to_hash = concat_number(l)
        g_r = pow(g, r, parameters.Q)
        h_r = pow(h, r, parameters.Q)
        m = hashlib.sha3_512()
        m.update(bytes_to_hash)
        hashed_bytes = m.digest()
        # print(hashed_bytes)
        c = int.from_bytes(hashed_bytes, byteorder='big')
        tmp_cmp_1 = (s1 * pow(A, c, parameters.Q)) % parameters.Q
        tmp_cmp_2 = (s2 * pow(B, c, parameters.Q)) % parameters.Q
        print("{} ?= {}".format(g_r, tmp_cmp_1))
        print("{} ?= {}".format(h_r, tmp_cmp_2))
        assert g_r == tmp_cmp_1  # verify 2
        assert h_r == tmp_cmp_2  # verify 3
        #print("DLEQ valid")

    def DLEQ(self, G, H, A, B, al, parameters):  # al = witness (alpha)
        #print("DLEQ")
        s = random.randint(0, parameters.Q - 1)  # generate random s
        #print("witness: {} A: {} \nB: {} s:{}".format(al, A, B, s))
        s1 = pow(G, s, parameters.Q)  # computation of s_1 and s_2
        s2 = pow(H, s, parameters.Q)
        l = [G, H, A, B, s1, s2]
        bytes_to_hash = concat_number(l)  # transforme every input n a
        m = hashlib.sha3_512()
        m.update(bytes_to_hash)
        hashed_bytes = m.digest()  # compute hash sha3_512
        # print(hashed_bytes)
        c = int.from_bytes(hashed_bytes, byteorder='big')  # generate an integer from hash
        r = (s + (c * al))  # compute r
        #print("r: {}".format(r))
        return (G, H, A, B, s1, s2, r)

    def __compute_dleq__(self, omegas_is, zis, sk_KA_keys, parameters):
        proofs = {}
        for f_client in sk_KA_keys.keys():
            omega_i = omegas_is[f_client]
            zi = zis[f_client]
            proof = self.DLEQ(self.param.GENERATOR, omega_i, pow(self.param.GENERATOR, sk_KA_keys[f_client], parameters.Q), pow(omega_i, sk_KA_keys[f_client], parameters.Q), sk_KA_keys[f_client], parameters)
            proofs[f_client]= proof
        return proofs

    def __compute_partial_value__(self):
        y = 0
        for client in self.shares_from_clients.keys():
            share = self.shares_from_clients[client]
            y = (y+int(share[1])) % self.param.Q
        return y

    def aggregate(self):
        fault_clients = self.__find_fault_clients__()
        #self.logger.debug("server {} has fault clients as {}".format(id(self), fault_clients))
        sk_KA_keys = self.__evaluate_shared_keys__(fault_clients)
        #self.logger.debug("server {} has sk_KA_keys as {}".format(id(self), sk_KA_keys))
        zis = self.__compute_zis__(sk_KA_keys)
        #self.logger.debug("server {} has zis as {}".format(id(self), zis))
        omega_is = self.__compute_omegas__(fault_clients)
        #self.logger.debug("server {} has omega_is as {}".format(id(self), omega_is))
        proofs = self.__compute_dleq__(omega_is, zis, sk_KA_keys, self.param)


        y = self.__compute_partial_value__()
        #self.logger.debug("server {} has y as {}".format(id(self), y))
        #self.bytes_out += total_size(zis) #sys.getsizeof(zis)
        #self.bytes_out += total_size(omega_is) #sys.getsizeof(omega_is)
        #self.bytes_out += total_size(proofs) #sys.getsizeof(proofs)
        #self.bytes_out += total_size(y) #sys.getsizeof(y)

        self.data_round_out[4] += total_size(zis) #sys.getsizeof(zis)
        self.data_round_out[4] += total_size(omega_is) #sys.getsizeof(omega_is)
        self.data_round_out[4] += total_size(proofs) #sys.getsizeof(proofs)
        self.data_round_out[4] += total_size(y) #sys.getsizeof(y)

        return zis, omega_is, proofs, y








