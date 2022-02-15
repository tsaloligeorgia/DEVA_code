import logging, math, getopt, sys, hashlib
from datetime import datetime
import time
from codetiming import Timer

from stats.handler_size import *

from sss.sharing import *

from parameters.param import Parameters
from client import Client
from server import Server

from tqdm import tqdm

logger = logging.getLogger("fmlr")
logger_t = logging.getLogger("timer")
logger.setLevel(logging.DEBUG)
#formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#ch = logging.StreamHandler()
#ch.setLevel(logging.DEBUG)
#ch.setFormatter(formatter)
#logger.addHandler(ch)

def concat_number(numbers):
    #print("bytes = {} ".format(numbers[0].to_bytes(sys.getsizeof(numbers[0]), 'big')))
    a = bytearray()

    for number in numbers:
        tmp = number.to_bytes(sys.getsizeof(number), 'big')
        a += tmp
    return a#

def DLEQ_verif(proof, parameters):
    g = proof[0]
    h = proof[1]
    A = proof[2]
    B = proof[3]
    s1 = proof[4]
    s2 = proof[5]
    r = proof[6]
    #print("DLEQ_verif")
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
    #print("{} ?= {}".format(g_r, tmp_cmp_1))
    #print("{} ?= {}".format(h_r, tmp_cmp_2))
    assert g_r == tmp_cmp_1  # verify 2
    assert h_r == tmp_cmp_2  # verify 3

timers_client = {}
timers = {}
def round_one(server, param):
    tt = Timer(text="", logger=None)
    for i in tqdm(range(0, param.SIZE_OF_DISJOINT), leave=False, desc="R1:"):

        c = Client(param)
        timers_client[id(c)] = []
        tt.start()
        c.generate_key_pair_KA()
        c.generate_key_pair_PKE()
        res = tt.stop()
        timers_client[id(c)].append((1, res))
        server.add_client(c)

    tt.start()
    server.collect_pks()
    server.share_keys()
    res = tt.stop()
    timers[id(server)].append((1, res))


def round_two(server, param):
    tt = Timer(text="", logger=None)
    res = 0

    for client in tqdm(server.clients_list, leave=False, desc="Round2:"):
        tt.start()
        encrypted_shares = client.generate_encrypted_secret_round_two()
        res_c = tt.stop()
        timers_client[id(client)].append((2, res_c))
        tt.start()
        server.receive_encrypted_shares(client, encrypted_shares)
        res = res + tt.stop()
    tt.start()
    server.send_encrypted_shares()
    res = res + tt.stop()
    timers[id(server)].append((2, res))


def round_three_server_side(server, tau_i, rho_i, shares, param):
    secret_input = 1  # random.randint(2,100) #TEST
    nr_fault_clients = math.ceil(len(server.clients_list)*param.FAULT)
    logger.debug("fault clients = {}".format(nr_fault_clients))
    final_nr = len(server.clients_list)-nr_fault_clients
    logger.debug("final_nr = {}".format(final_nr))
    tt = Timer(text="", logger=None)
    res = 0

    for i in tqdm(range(0, final_nr), leave=False, desc="R3Server:"):
        tt.start()
        client = server.clients_list[i]
        client.compute_key_agreements()
        client.compute_ss_of_secret_input(secret_input)
        tau, rho, shares_secret_input = client.compute_tau_rho_secret_input()
        res_c = tt.stop()
        timers_client[id(client)].append((3, res_c))
        tt.start()
        server.receive_tau_rho(client, tau, rho)
        res = res + tt.stop()
        tau_i[client] = tau
        rho_i[client] = rho
        shares[client] = shares_secret_input
    timers[id(server)].append((3, res))


def round_three_client_side(shares, list_of_servers):
    tt = Timer(text="", logger=None)
    clients = shares.keys()
    #print("clients : {}".format(clients))
    #print("clients : {}".format(len(clients)))

    for client in clients:
        #timers_client[id(client)] = []
        share = shares[client]
        for i in range(0, param.NR_SERVER):
            list_of_servers[i].receive_share_from_client(share[i], client)



def round_four_server_side(server, zis_j, omega_ijs, proofs_j, y_j):
    tt = Timer(text="", logger=None)

    server.__find_fault_clients__()
    #print(len(server.clients_list))

    for client in server.clients_list:
        tt.start()
        decrypted_shares = client.decrypt_KA_shares()
        #print(client.data_round_out[4])
        res_c = tt.stop()

        timers_client[id(client)].append((4, res_c))
        server.add_decrypted_shares(client, decrypted_shares)

    tt.start()
    zis, omega_is, proofs, y = server.aggregate()
    res = tt.stop()
    timers[id(server)].append((4, res))
    zis_j[server] = zis
    omega_ijs[server] = omega_is
    proofs_j[server] = proofs
    y_j[server] = y


def print_statistics(parameter, res, data_verify):
    t = time.localtime()
    current_time = time.strftime("%H_%M_%S", t)
    file_name = "FMLR_experiment.csv"
    file_to_save = open(file_name, "a")
    server_id = list(timers.keys())[0]
    server = list_of_servers[0]
    str_b = str(parameter.NR_CLIENTS) + ", " + str(parameter.NR_SERVER) + ", " \
            + str(parameter.THREASHOLD - 1) + ", "
    str_b += str(parameter.THREASHOLD_KEY-1) + ", " + str(parameter.FAULT*100) + ", "
    str_b += str(timers[server_id][0][1]) + ", "
    c_round_t = [0, 0, 0, 0, 0]
    c_total = [ 0, 0, 0, 0]

    s_data_in = [0, 0, 0, 0]
    s_data_out = [0, 0, 0, 0]
    for server in list_of_servers:
        for i in range(1, 5):
            s_data_in[i-1] += server.data_round_in[i]
            s_data_out[i-1] += server.data_round_out[i]

    for i in range(0,4):
        s_data_in[i] = round(s_data_in[i]/param.NR_SERVER)
        s_data_out[i] = round(s_data_out[i] / param.NR_SERVER)




    c_data_in =  [0, 0, 0, 0]
    c_data_out = [0, 0, 0, 0]


    c_clients = timers_client.keys()
    for client in c_clients:
        for i in range(0, 4):
            try:
                c_round_t[i] += timers_client[client][i][1]
                c_total[i] += 1
            except:
                pass

    str_b += str(c_round_t[0]/c_total[0]) + ","
    total_in_c = 0
    total_out_c = 0
    total_c = 0
    total_clients = 0
    for server in list_of_servers:
        for client in server.clients_list:
            total_clients += 1
            for i in range(1,5):
                c_data_in[i-1] += client.data_round_in[i]
                #print(client.data_round_out[4])
                c_data_out[i - 1] += client.data_round_out[i]
                #print(c_data_out)


    #print(c_data_in)
    print(c_data_out)

    for i in range(0, 4):
        c_data_in[i] = round(c_data_in[i]/param.NR_CLIENTS)
        c_data_out[i] = round(c_data_out[i] / param.NR_CLIENTS)

    print(c_data_out)
    #c = server.clients_list[0]

    str_b += str(s_data_in[0]) + ", "
    str_b += str(s_data_out[0]) + ", "
    str_b += str(c_data_in[0]) + ", "
    str_b += str(c_data_out[0]) + ", "

    str_b += str(timers[server_id][1][1]) + ", "
    str_b += str(c_round_t[1] / c_total[1]) + ","
    str_b += str(s_data_in[1]) + ", "
    str_b += str(s_data_out[1]) + ", "
    str_b += str(c_data_in[1]) + ", "
    str_b += str(c_data_out[1]) + ", "

    str_b += str(timers[server_id][2][1]) + ", "
    str_b += str(c_round_t[2] / c_total[2]) + ","
    str_b += str(s_data_in[2]) + ", "
    str_b += str(s_data_out[2]) + ", "
    str_b += str(c_data_in[2]) + ", "
    str_b += str(c_data_out[2]) + ", "

    str_b += str(timers[server_id][3][1]) + ", "
    str_b += str(c_round_t[3] / c_total[3]) + ","
    str_b += str(s_data_in[3]) + ", "
    str_b += str(s_data_out[3]) + ", "
    str_b += str(c_data_in[3]) + ", "
    str_b += str(c_data_out[3]) + ", "

    str_b += str(res) + ", "
    str_b += str(data_verify)

    print(str_b)
    file_to_save.write(str_b + "\n")
    file_to_save.close()



    #print("Clients (TOTAL) :")
    #print("Bytes in: {}".format(total_in_c))
    #print("Bytes out: {}".format(total_out_c))

    #print("Clients (AVG) :")
    #print("Bytes in: {}".format(total_in_c/total_c))
    #print("Bytes out: {}".format(total_out_c/total_c))







if __name__ == '__main__':
    logger.info("Starting FMLR")
    # Remove 1st argument from the
    # list of command line arguments
    # ------------ SETUP ----------------------
    param = Parameters()


    argumentList = sys.argv[1:]

    # Options
    options = "hc:s:k:t:f:"

    # Long options
    long_options = ["Help", "Nr_clients =", "Nr_servers =", "Threashold_key =", "Threashold_server =", "Fault_clients ="]
    try:
        # Parsing argument
        arguments, values = getopt.getopt(argumentList, options, long_options)

        # checking each argument
        for currentArgument, currentValue in arguments:

            if currentArgument in ("-h", "--Help"):
                print("Diplaying Help")

            elif currentArgument in ("-c", "--Nr_clients"):
                param.NR_CLIENTS = int(currentValue)

            elif currentArgument in ("-s", "--Nr_servers"):
                param.NR_SERVER = int(currentValue)

            elif currentArgument in ("-k", "--Threashold_key"):
                param.THREASHOLD_KEY = int(currentValue)+1

            elif currentArgument in ("-t", "--Threashold_server"):
                param.THREASHOLD = int(currentValue)+1

            elif currentArgument in ("-f", "--Fault_clients"):
                param.FAULT = int(currentValue)/100.0


    except getopt.error as err:
        # output error, and return with an error code
        print(str(err))
    #param.print_parameters_nice()
    t = Timer(text="", logger=None)
    param.print_parameters_nice()
    #--------------END SETUP --------------

    list_of_servers = []
    for i in range(0, param.NR_SERVER):
        server = Server(param, i+1)
        list_of_servers.append(server)
        timers[id(server)] = []

    #--------------ROUND ONE --------------

    for server in list_of_servers:
        round_one(server, param)


    #---------------END ROUND ONE-----------


    #--------------ROUND TWO ---------------

    for server in list_of_servers:
        round_two(server, param)
    #------------ END ROUND TWO ---------------


    #------------ ROUND THREE -----------------
    tau_i = {}
    rho_i = {}
    shares = {}

    for server in list_of_servers:
        round_three_server_side(server, tau_i, rho_i, shares, param)

    #("shares: {}".format(shares))

    round_three_client_side(shares, list_of_servers)

    #-------- END ROUND THREE -----------------


    #-------- ROUND FOUR ---------------------

    zis_j = {}
    omega_ijs = {}
    proofs_j = {}
    y_j = {}
    for server in list_of_servers:
        round_four_server_side(server, zis_j, omega_ijs, proofs_j, y_j)



    # ------------------ END ROUND FOUR ---------------------

    #--------------- Public Verification --------------------
    data_verify = 0
    for key in y_j.keys():
        data_verify += total_size(y_j[key])

    #data_verify += total_size(y_j)
    for key in proofs_j.keys():
        data_verify += total_size(proofs_j[key])
    #data_verify += total_size(proofs_j)

    for key in zis_j.keys():
        data_verify += total_size(zis_j[key])
    #data_verify += total_size(zis_j)
    for server in list_of_servers:
        rho_s = server.return_rho_is()
        tau_s = server.return_tau_is()
        for key in rho_s.keys():
            data_verify += total_size(rho_s[key])
        for key in tau_s.keys():
            data_verify +=total_size(tau_s[key])

    t.start()
    y_final = 0

    points = []
    # i = 0
    servers = list(y_j.keys());
    for i in range(0, param.THREASHOLD):
        server = servers[i]
        point = (server.id, y_j[server])
        #print(point)
        points.append(point)
    y_final = points_to_secret_int(points, param.Q)
    #print(y_final)
    for server in tqdm(proofs_j.keys(), leave=False, desc="PubVer:"):
        proofs = proofs_j[server]
        for proof in proofs.values():
            DLEQ_verif(proof, param)


    sigma_ms = {}
    for server in list_of_servers:
        rho_i = server.return_rho_is()
        tau_i = server.return_tau_is()
        zij = zis_j[server]
        prod_rho = 1
        prod_tau = 1
        for client in rho_i.keys():
            prod_rho = (prod_rho * rho_i[client]) % param.Q
            prod_tau = (prod_tau * tau_i[client]) % param.Q

        prod_z = 1
        for z in zij.values():
            prod_z = (prod_z*z) % param.Q


        sigma = (prod_rho*prod_tau*prod_z) % param.Q
        sigma_ms[server] = sigma

    final_sigma = 1
    for sigma_j in sigma_ms.values():
        final_sigma = (final_sigma*sigma_j) % param.Q


    res = t.stop()
    #print("Verification took {:0.5f} seconds".format(res))

    print_statistics(param, res, data_verify)



    # print("y = {}".format(y_final))
    print("sigma = {} ?= h(y) {}".format(final_sigma, pow(param.GENERATOR, y_final, param.Q)))
    if final_sigma == pow(param.GENERATOR, y_final, param.Q):
        print ("TRUE")
    else:
        print("FALSE")


 # tqdm(listOfElements, leave=False, desc="User Keygen:"):
