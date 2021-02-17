from attack import ATTACK
import networkx as nx

if __name__ == "__main__":
    from time import time

    # # Create ATT&CK framework
    # start = time()
    # attack = ATTACK.load("../data/cti")
    # print("Load took {} seconds".format(time() - start))
    #
    # start = time()
    # # Retrieve objects from framework
    # matrices       = attack.matrices
    # tactics        = attack.tactics
    # techniques     = attack.techniques
    # sub_techniques = attack.sub_techniques
    # procedures     = attack.procedures
    # mitigations    = attack.mitigations
    # groups         = attack.groups
    # software       = attack.software
    # print("Indexing took {} seconds".format(time() - start))
    #
    # start = time()
    # attack.store_pickle('attack.p')
    # print("Store took {} seconds".format(time() - start))
    start = time()
    attack = ATTACK.load_pickle('models/attack.p')
    attack.clear()
    print("Load_pickle took {} seconds".format(time() - start))

    print(attack.summary())
    start = time()
    matrices       = attack.matrices
    tactics        = attack.tactics
    techniques     = attack.techniques
    sub_techniques = attack.sub_techniques
    procedures     = attack.procedures
    mitigations    = attack.mitigations
    groups         = attack.groups
    software       = attack.software
    print("Indexing took {} seconds".format(time() - start))

    graph = attack.graph
    print(len(graph.nodes()))
    print(len(graph.edges()))
    nx.write_gexf(graph, 'models/graph.gexf')
