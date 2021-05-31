# Import argument parser
import argformat
import argparse
import matplotlib.pyplot as plt
import networkx          as nx
import os

# Import the ATTACK framework
from py_attack import ATTACK

if __name__ == "__main__":
    ########################################################################
    #                        Load ATTACK framework                         #
    ########################################################################
    parser = argparse.ArgumentParser(
        description     = "Python implementation of MITRE's ATT&CK framework",
        formatter_class = argformat.StructuredFormatter,
    )

    parser.add_argument('--path'    , default = None        , help='path to local CTI repository')
    parser.add_argument('--download', action  = 'store_true', help='download framework from online repository')

    args = parser.parse_args()

    # Either --path or --download should be specified, not both
    if not bool(args.path) ^ bool(args.download):
        raise ValueError("Please specify either --path or --download, not both")

    ########################################################################
    #                        Load ATTACK framework                         #
    ########################################################################

    # Download latest ATTACK framework
    if args.download:
        attack = ATTACK.download()

    # Alternatively load the framework from a local directory
    if args.path:
        # Format of path
        path = '/path/to/local/cti/{domain}-attack/{domain}-attack.json',
        # Create path from arguments
        path = os.path.join(
            args.path,
            "{domain}-attack",
            "{domain}-attack.json"
        )

        attack = ATTACK.load(
            path    = path,
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
    # attack.concepts
    # attack.matrices
    # attack.tactics
    # attack.techniques
    # attack.sub_techniques
    # attack.mitigations
    # attack.groups
    # attack.software
    for concept in attack.concepts:
        # Do stuff with your attack concept
        pass

    # Iterate over concepts for specific domain:
    for concept in attack.domains['enterprise'].concepts:
        # Do stuff with your attack concept
        pass

    ########################################################################
    #                 ATT&CK framework as networkx.DiGraph                 #
    ########################################################################

    # Get graph for entire framework
    graph = attack.graph
    # Get graph for specific domain
    graph = attack.domains['enterprise'].graph

    # Write graph to outfile
    nx.write_gexf(graph, 'graph.gexf')

    # Plot graph
    attack.plot()
    plt.show()
    # plt.savefig('plot_attack.png', dpi=300)

    ########################################################################
    #                     Find related ATT&CK concepts                     #
    ########################################################################

    # Get related concepts by ID, note UUID is NOT supported
    related_concepts = attack.related_concepts('T1087', depth=1)

    print("\nRelated concepts:")
    for related_concept_id in related_concepts:
        print(related_concept_id)
