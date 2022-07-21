# Imports
from py_attack import ATTACK, ATTACKDomain

################################################################################
#                                   Loading                                    #
################################################################################

# Load ATTACK framework from local path
attack = ATTACK.load(
    # path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
    path    = "/home/thijs/Documents/research/eagle/data/mitre/cti_v10.1/{domain}-attack/{domain}-attack.json",
    domains = ['enterprise', 'ics', 'mobile', 'pre'],
)

# Load single enterprise domain from local path
enterprise_domain = ATTACKDomain.load(
    path   = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
    domain = 'enterprise',
)

################################################################################
#                              Manipulate ATTACK                               #
################################################################################

# Get enterprise domain
enterprise = attack['enterprise']
# Delete enterprise domain
del attack['enterprise']
# Set enterprise domain
attack['enterprise'] = enterprise_domain

################################################################################
#                                   Getters                                    #
################################################################################

# Get technique from ATTACK object
technique = attack.get('T1087')
technique = attack['enterprise'].get('T1087')
technique = attack['enterprise']['T1087']

# Get technique from ATTACKDomain object
technique = enterprise_domain.get('T1087')
technique = enterprise_domain['T1087']

################################################################################
#                                  Iterators                                   #
################################################################################

# Iterate over ATTACK concepts
for concept in attack.concepts:
    ...
    
# Iterate over ATTACK techniques
for technique in attack.techniques:
    ...

# Iterate over ATTACKDomain concepts
for concept in enterprise_domain.concepts:
    ...
    
# Iterate over ATTACKDomain techniques
for technique in enterprise_domain.techniques:
    ...

################################################################################
#                                    Graph                                     #
################################################################################

# Get graph
graph = attack.graph
graph_enterprise = attack['enterprise'].graph
graph_enterprise = enterprise_domain.graph

# Find related concepts
related = attack.related_concepts('T1087')