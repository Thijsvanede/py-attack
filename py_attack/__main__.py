# Import the ATTACK framework
from py_attack import ATTACK

if __name__ == "__main__":

    ########################################################################
    #                        Load ATTACK framework                         #
    ########################################################################

    # Download latest ATTACK framework
    # attack = ATTACK.download()

    # Alternatively load the framework from a local directory
    attack = ATTACK.load(
        # path    = '/path/to/local/cti/{domain}-attack/{domain}-attack.json',
        path    = '/home/thijs/Documents/research/eagle/data/cti/{domain}-attack/{domain}-attack.json',
        domains = ['enterprise', 'mobile', 'ics'],
    )

    ########################################################################
    #                           Search by (UU)ID                           #
    ########################################################################

    # Search by ID
    concept = attack.get(identifier='T1087')
    print(concept)

    # Search by UUID
    concept = attack.get(identifier='attack-pattern--72b74d71-8169-42aa-92e0-e7b04b9f5a08')
    print(concept)

    ########################################################################
    #                        Iterate over concepts                         #
    ########################################################################

    # We support the following concepts:
    # * attack.matrices
    # * attack.tactics
    # * attack.techniques
    # * attack.sub_techniques
    # * attack.mitigations
    # * attack.groups
    # * attack.software
    for concept in attack.matrices:
        # Do stuff with your attack concept
        pass

    # Iterate over concepts for specific domain:
    for concept in attack.domains['enterprise'].matrices:
        # Do stuff with your attack concept
        pass

    ########################################################################
    #                 ATT&CK framework as networkx.DiGraph                 #
    ########################################################################

    # Get graph for entire framework
    graph = attack.graph
    # Get graph for specific domain
    graph = attack.domains['enterprise'].graph

    ########################################################################
    #                     Find related ATT&CK concepts                     #
    ########################################################################

    # Get related concepts by ID, note UUID is NOT supported
    related_concepts = attack.related_concepts('T1087', depth=1)

    print("\nRelated concepts:")
    for related_concept_id in related_concepts:
        print(related_concept_id)
