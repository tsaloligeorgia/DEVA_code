from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric import ec

import math

class Parameters(object):

    LAMBDA = 512
    THREASHOLD = 2
    THREASHOLD_KEY = 2
    NR_SERVER = 3
    NR_CLIENTS = 30
    #Q = 26036531759180155747046591158890124517313280480467928349371568030077193686951199155845942270333431782183122598412525621439506515600483667373341885536575742716343941672780662634756460355183211063679135104837181077398493078506592909714620355912316073904877669568012714788247742774087410686248375215755532909746577616287884179045959650005772333915892724409060329505380759372398663965006347008653902652258731665450435012868537265519523961688162018870080998003556350057667567092669917797244907787914735997620538041810147270537621266807574824679504249352223006242908155246565365668410898102751450372011416793866473479457019
    GENERATOR = 2
    FAULT = 0.0


    def __init__(self):
        self.param = ec.SECP256K1()#dh.generate_parameters(generator=self.GENERATOR, key_size=self.LAMBDA, backend=default_backend())
        private_key = ec.generate_private_key(ec.SECP256K1(),default_backend())
        self.Q = 2**256 - 2**32 - 977
        self.SIZE_OF_DISJOINT = math.ceil(self.NR_CLIENTS/self.NR_SERVER)

    def return_Q(self):
        return self.param.parameter_numbers().p

    def gen_key(self):
        private_key = ec.generate_private_key(ec.SECP256K1(),default_backend())
        # public_key = private_key.public_key()
        return private_key

    def return_param(self):
        return self.param

    def print_parameters_nice(self):
        self.SIZE_OF_DISJOINT = math.ceil(self.NR_CLIENTS / self.NR_SERVER)
        print("--------------Parameters-----------------")
        print("LAMBDA: {}".format(self.LAMBDA))
        print("GENERATOR: {}".format(self.GENERATOR))
        print("NR_CLIENTS: {}".format(self.NR_CLIENTS))
        print("NR_SERVERS: {}".format(self.NR_SERVER))
        print("PRIME: {}".format(self.Q))
        print("THREASHOLD_KEY: {}".format(self.THREASHOLD_KEY))
        print("THREASHOLD: {}".format(self.THREASHOLD))
        print("SIZE_OF_DISJOINT: {}".format(self.SIZE_OF_DISJOINT))
        print("FAULT CLIENT: {}%".format((self.FAULT*100)))
        print("------------------------------------------")