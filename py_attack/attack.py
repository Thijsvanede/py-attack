# Imports
import copy
import json
import networkx as nx
import os
import pickle
import re
import requests
import warnings

from collections.abc import MutableMapping
from py_attack.utils import get_id, get_uuid
from stix2           import Filter, MemoryStore

class ATTACKDomain(object):
    """The ATTACKDomain object provides a simple interface for loading and
        interacting with a domain in the ATT&CK framework."""

    ########################################################################
    #                     ATTACKDomain as a dictionary                     #
    ########################################################################

    def __init__(self, domain, store):
        """The ATTACKDomain object provides a simple interface for loading and
            interacting with a domain in the ATT&CK framework.

            Parameters
            ----------
            domain : string
                Domain covered by the ATTACKDomain. E.g., enterprise, mobile,
                ics.

            store : stix2.datastore.memory.MemoryStore
                MemoryStore for ATT&CK domain
            """
        # Set domain name
        self.domain = domain

        # Set store
        self.store = store

        # Set empty cache
        self.clear()

    ########################################################################
    #                    Retrieve specific ATT&CK data                     #
    ########################################################################

    @property
    def matrices(self):
        """Retrieve all matrices from the ATT&CKDomain.

            Returns
            -------
            matrices : list()
                List of dict() objects representing all matrices.
            """
        # Cache matrices
        if self._matrices is None:

            # Extract matrices
            self._matrices = self.store.query([
                Filter('type', '=', 'x-mitre-matrix')
            ])

            # Filter deprecated concepts
            self._matrices = self.filter_deprecated(self._matrices)

        # Return result
        return self._matrices


    @property
    def tactics(self):
        """Retrieve all tactics from the ATT&CKDomain.

            Returns
            -------
            tactics : list()
                List of dict() objects representing all tactics.
            """
        # Cache tactics
        if self._tactics is None:

            # Extract tactics
            self._tactics = self.store.query([
                Filter('type', '=', 'x-mitre-tactic')
            ])

            # Filter deprecated concepts
            self._tactics = self.filter_deprecated(self._tactics)

            # Perform checks on ID, should match TAxxxx
            regex_tactics = re.compile('TA[0-9]{4}')
            for concept in self._tactics:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

        # Return result
        return self._tactics


    @property
    def techniques(self):
        """Retrieve all techniques from the ATT&CKDomain.

            Returns
            -------
            techniques : list()
                List of dict() objects representing all techniques.
            """
        # Cache techniques
        if self._techniques is None:

            # Extract techniques
            self._techniques = self.store.query([
                Filter('type', '=', 'attack-pattern')
            ])

            # Filter deprecated concepts
            self._techniques = self.filter_deprecated(self._techniques)

            # Perform checks on ID, should match Txxxx(.yyy)
            regex_tactics = re.compile('T[0-9]{4}(\.[0-9]{3})?')
            for concept in self._techniques:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

        # Return result
        return self._techniques


    @property
    def sub_techniques(self):
        """Retrieve all sub-techniques from the ATT&CKDomain.

            Returns
            -------
            sub_techniques : list()
                List of dict() objects representing all sub-techniques.
            """
        # Cache sub-techniques
        if self._sub_techniques is None:

            # Extract sub-techniques
            self._sub_techniques = self.store.query([
                Filter('type'                   , '=', 'attack-pattern'),
                Filter('x_mitre_is_subtechnique', '=', True            ),
            ])

            # Filter deprecated concepts
            self._sub_techniques = self.filter_deprecated(self._sub_techniques)

            # Perform checks on ID, should match Txxxx.yyy
            regex_tactics = re.compile('T[0-9]{4}\.[0-9]{3}')
            for concept in self._sub_techniques:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

        # Return result
        return self._sub_techniques


    @property
    def procedures(self):
        """Retrieve all procedures from the ATT&CKDomain.

            Returns
            -------
            procedures : list()
                List of dict() objects representing all procedures.
            """
        # Cache procedures
        if self._procedures is None:

            # Extract procedures
            self._procedures = self.store.query([
                Filter('type'             , '='       , 'relationship'  ),
                Filter('relationship_type', '='       , 'uses'          ),
                Filter('target_ref'       , 'contains', 'attack-pattern'),
            ])

            # Filter deprecated concepts
            self._procedures = self.filter_deprecated(self._procedures)

        # Return result
        return self._procedures


    @property
    def relationships(self):
        """Retrieve all relationships from the ATT&CKDomain.

            Note
            ----
            While not all relationships are part of the ATT&CK concepts, it is
            useful to have a method for extracting relationships. Among others
            to build the ATT&CK graph.

            Returns
            -------
            relationships : list()
                List of dict() objects representing all relationships.
            """
        # Cache relationships
        if self._relationships is None:

            # Extract relationships
            self._relationships = self.store.query([
                Filter('type', '=', 'relationship'),
            ])

            # Filter deprecated concepts
            self._relationships = self.filter_deprecated(self._relationships)

        # Return result
        return self._relationships


    @property
    def mitigations(self):
        """Retrieve all mitigations from the ATT&CKDomain.

            Returns
            -------
            mitigations : list()
                List of dict() objects representing all mitigations.
            """
        # Cache mitigations
        if self._mitigations is None:

            # Extract mitigations and add to mitigations
            self._mitigations = self.store.query([
                Filter('type', '=', 'course-of-action')
            ])

            # Filter deprecated concepts
            self._mitigations = self.filter_deprecated(self._mitigations)

            # Perform checks on ID, should match Mxxxx
            regex_tactics = re.compile('M[0-9]{4}')
            for concept in self._mitigations:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

        # Return result
        return self._mitigations


    @property
    def groups(self):
        """Retrieve all groups from the ATT&CKDomain.

            Returns
            -------
            groups : list()
                List of dict() objects representing all groups.
            """
        # Cache groups
        if self._groups is None:

            # Extract groups
            self._groups = self.store.query([
                Filter('type', '=', 'intrusion-set')
            ])

            # Filter deprecated concepts
            self._groups = self.filter_deprecated(self._groups)

            # Perform checks on ID, should match Gxxxx
            regex_tactics = re.compile('G[0-9]{4}')
            for concept in self._groups:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

        # Return result
        return self._groups


    @property
    def software(self):
        """Retrieve all software from the ATT&CKDomain.

            Returns
            -------
            software : list()
                List of dict() objects representing all software.
            """
        # Cache software
        if self._software is None:

            # Initialise list of all software
            self._software = list()

            # Extract malware and add to software
            self._software.extend(self.store.query([
                Filter('type', '=', 'malware')
            ]))
            # Extract tools and add to software
            self._software.extend(self.store.query([
                Filter('type', '=', 'tool')
            ]))

            # Filter deprecated concepts
            self._software = self.filter_deprecated(self._software)

            # Perform checks on ID, should match Sxxxx
            regex_tactics = re.compile('S[0-9]{4}')
            for concept in self._software:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

        # Return result
        return self._software

    ########################################################################
    #                             ATT&CK graph                             #
    ########################################################################

    @property
    def graph(self):
        """Get the relations within the ATT&CK domain as a graph.

            Returns
            -------
            graph : nx.DiGraph()
                Directed graph representing the ATT&CK domain.
            """
        # Cache graph
        if self._graph is None:
            # Create graph
            self._graph = nx.DiGraph()

            ############################################################
            #                     Add graph nodes                      #
            ############################################################

            # Add all ATT&CK tactics to graph
            for tactic in self.tactics:
                self._graph.add_node(get_id(tactic))
            # Add all ATT&CK techniques to graph
            for technique in self.techniques:
                self._graph.add_node(get_id(technique))
            # Add all ATT&CK sub_techniques to graph
            for sub_technique in self.sub_techniques:
                self._graph.add_node(get_id(sub_technique))
            # Add all ATT&CK mitigations to graph
            for mitigation in self.mitigations:
                self._graph.add_node(get_id(mitigation))
            # Add all ATT&CK groups to graph
            for group in self.groups:
                self._graph.add_node(get_id(group))
            # Add all ATT&CK software to graph
            for software in self.software:
                self._graph.add_node(get_id(software))

            # Count number of nodes
            n_nodes = len(self._graph.nodes())

            ############################################################
            #                  Concepts by reference                   #
            ############################################################
            map_uuid = self.map_uuid()

            ref_tactics_name = {
                tactic.get('x_mitre_shortname'): tactic
                for tactic in self.tactics
            }

            ############################################################
            #                     Add graph edges                      #
            ############################################################

            # Add relations between (Sub-)Techniques and Tactics
            # using kill_chain_phases

            # Loop over all techniques
            for technique in self.techniques:
                # Extract technique ID
                technique_id = get_id(technique)

                # Find corresponding kill chain phases
                for phase in technique.kill_chain_phases:
                    # Find tactic of kill chain phase
                    tactic = ref_tactics_name.get(phase.get('phase_name'))
                    tactic = get_id(tactic)

                    # Add edge
                    self._graph.add_edge(
                        technique_id,
                        tactic,
                        relation = "kill_chain_phase"
                    )


            # Add relations between mitigations and techniques
            for relation in self.relationships:
                # Get source and target
                source = map_uuid.get(relation.get('source_ref'))
                target = map_uuid.get(relation.get('target_ref'))

                # Skip if the source or target is unknown
                if source is None or target is None: continue

                # Get relationship type
                relationship_type = relation.get('relationship_type')

                # Get IDs
                id_source = get_id(source)
                id_target = get_id(target)

                # Add edge
                self._graph.add_edge(
                    id_source,
                    id_target,
                    relation = relationship_type,
                )

            # Assert that adding edges did not change the number of nodes
            assert n_nodes == len(self._graph.nodes())

        # Return graph
        return self._graph

    ########################################################################
    #                  Retrieve ATT&CK concept attributes                  #
    ########################################################################

    def concepts(self):
        """Generator over all concepts of the ATT&CK framework for this domain.

            Note
            ----
            Yields the following concept types:
            Matrix
            Tactic
            Technique
            Sub-technique
            Procedure
            Mitigation
            Group
            Software

            Yields
            ------
            concept : dict()
                A dictionary describing each ATT&CK concept.
            """
        # Iterate over all concepts
        yield from self.matrices
        yield from self.tactics
        yield from self.techniques
        yield from self.procedures
        yield from self.mitigations
        yield from self.groups
        yield from self.software


    def map_id(self):
        """Get a map of all ID -> ATT&CK concepts.

            Returns
            -------
            map : dict()
                Dictionary of ID -> ATT&CK concept.
            """
        return {
            get_id(concept): concept
            for concept in self.concepts()
            if get_id(concept)
        }


    def map_uuid(self):
        """Get a map of all UUID -> ATT&CK concepts.

            Returns
            -------
            map : dict()
                Dictionary of UUID -> ATT&CK concept.
            """
        return {
            get_uuid(concept): concept
            for concept in self.concepts()
            if get_uuid(concept)
        }


    def filter_deprecated(self, concepts):
        """Filter deprecated and revoked concepts from given concepts.

            Parameters
            ----------
            concepts : list
                List of concepts to check for deprecated or revoked attributes.

            Returns
            -------
            filtered_concepts : list
                List of concepts without deprecated or revoked concepts.
            """
        # Filter depricated and revoked concepts
        return [
            concept for concept in concepts if
            not concept.get("x_mitre_deprecated", False) and
            not concept.get("revoked"           , False)
        ]

    ########################################################################
    #                             Clear cache                              #
    ########################################################################

    def clear(self):
        """Clear ATT&CKDomain cache.

            Returns
            -------
            self : self
                Returns self.
            """
        # (Re)set properties
        self._matrices       = None
        self._tactics        = None
        self._techniques     = None
        self._sub_techniques = None
        self._procedures     = None
        self._relationships  = None
        self._mitigations    = None
        self._groups         = None
        self._software       = None

        # (Re)set graph
        self._graph = None

        # Return self
        return self

    ########################################################################
    #                             I/O methods                              #
    ########################################################################

    def summary(self):
        """Returns a string summary of ATT&CKDomain."""
        return """ATT&CK domain - {}
----------------------------
# Matrices         : {:>7}
# Tactics          : {:>7}
# Techniques       : {:>7}
#   Sub-techniques : {:>7}
# Procedures       : {:>7}
# Mitigations      : {:>7}
# Groups           : {:>7}
# Software         : {:>7}""".format(
    self.domain,
    len(self.matrices      ),
    len(self.tactics       ),
    len(self.techniques    ),
    len(self.sub_techniques),
    len(self.procedures    ),
    len(self.mitigations   ),
    len(self.groups        ),
    len(self.software      ),
)


    def store_pickle(self, outfile):
        """Store ATT&CKDomain as pickled file for quicker loading.

            Parameters
            ----------
            outfile : string
                Path to file to store ATT&CKDomain as pickle.
            """
        # Write to output file
        with open(outfile, 'wb') as outfile:
            pickle.dump(self, outfile)


    @classmethod
    def load_pickle(cls, infile):
        """Load ATT&CKDomain from pickled file for quicker loading.

            Parameters
            ----------
            infile : string
                Path to file to from which to load ATT&CKDomain as pickle.

            Returns
            -------
            result : ATT&CKDomain
                ATT&CKDomain from loaded pickle file.
            """
        # Read input file
        with open(infile, 'rb') as infile:
            attack = pickle.load(infile)

        # Return ATTACK
        return attack


    @classmethod
    def load(cls, path, domain):
        """Load ATT&CKDomain from path.

            Parameters
            ----------
            path : string
                Path from which to load ATT&CKDomain.

            domains : string
                Name of domain to load.

            Returns
            -------
            result : ATT&CKDomain
                ATT&CKDomain from loaded file.
            """
        # Read file as json
        with open(path, 'r') as infile:
            stix_json = json.load(infile)

        # Store data
        store = MemoryStore(stix_data=stix_json["objects"])

        # Return ATTACK
        return cls(domain, store)


    @classmethod
    def download(cls,
            url    = "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v8.2/enterprise-attack/enterprise-attack.json",
            domain = 'enterprise',
        ):
        """Download ATTACKDomain from url.

            Example
            -------
            All content should be available from the following URL(s):
            "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}-attack/{domain}-attack.json"
            Where {version} is the version you want to retrieve, e.g. "8.2" for
            version 8.2 and {domain} is the domain you want to retrieve, e.g.
            "enterprise".

            Parameters
            ----------
            url : string, default="https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v8.2/enterprise-attack/enterprise-attack.json"
                URL from which to download ATT&CKDomain.
                If the url contains the string '{domain}', this will be
                automatically replaced by the domain specified by the parameter
                'domain'.

            domains : string, default='enterprise'
                Domain to download.

            Returns
            -------
            result : ATTACK
                ATTACK from downloaded framework.
            """
        # Specify domain from which to download ATT&CKDomain if necessary
        if "{domain}" in url:
            url = url.format(domain = domain)

        # Download ATTACKDomain as json
        stix_json = requests.get(url).json()

        # Store data
        source = MemoryStore(stix_data=stix_json["objects"])

        # Return ATTACKDomain
        return cls(domain, source)

















class ATTACK(MutableMapping):
    """The ATTACK object provides a simple interface for loading and interacting
    with the ATT&CK framework."""

    ########################################################################
    #                        ATTACK as a dictionary                        #
    ########################################################################

    def __init__(self, *args, **kwargs):
        """The ATTACK object provides a simple interface for loading and
            interacting with the ATT&CK framework.

            Parameters
            ----------
            *args : *args
                Arguments to use as dictionary

            **kwargs : **kwargs
                Arguments to use as dictionary
            """
        # Set domains as dictionary
        self.domains = dict()
        self.update(dict(*args, **kwargs))

        # Clear cache
        self.clear()


    def __getitem__(self, key):
        return self.domains[key]

    def __setitem__(self, key, value):
        self.domains[key] = value

    def __delitem__(self, key):
        del self.domains[key]

    def __iter__(self):
        return iter(self.domains)

    def __len__(self):
        return len(self.domains)

    ########################################################################
    #                    Retrieve specific ATT&CK data                     #
    ########################################################################

    @property
    def matrices(self):
        """Retrieve all matrices from the ATT&CK framework.

            Yields
            ------
            matrices : list()
                matrices of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.matrices

    @property
    def tactics(self):
        """Retrieve all tactics from the ATT&CK framework.

            Yields
            ------
            tactics : list()
                tactics of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.tactics

    @property
    def techniques(self):
        """Retrieve all techniques from the ATT&CK framework.

            Yields
            ------
            techniques : list()
                techniques of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.techniques

    @property
    def sub_techniques(self):
        """Retrieve all sub-techniques from the ATT&CK framework.

            Yields
            ------
            sub_techniques : list()
                sub_techniques of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.sub_techniques

    @property
    def procedures(self):
        """Retrieve all procedures from the ATT&CK framework.

            Yields
            ------
            procedures : list()
                procedures of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.procedures

    @property
    def relationships(self):
        """Retrieve all relationships from the ATT&CK framework.

            Note
            ----
            While not all relationships are part of the ATT&CK concepts, it is
            useful to have a method for extracting relationships. Among others
            to build the ATT&CK graph.

            Yields
            ------
            relationships : list()
                relationships of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.relationships

    @property
    def mitigations(self):
        """Retrieve all mitigations from the ATT&CK framework.

            Yields
            ------
            mitigations : list()
                mitigations of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.mitigations

    @property
    def groups(self):
        """Retrieve all groups from the ATT&CK framework.

            Yields
            ------
            groups : list()
                groups of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.groups

    @property
    def software(self):
        """Retrieve all software from the ATT&CK framework.

            Yields
            ------
            software : list()
                software of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.software

    ########################################################################
    #                          Map ID to concept                           #
    ########################################################################

    def get(self, identifier, default=None):
        """Map identifier to ATT&CK concept.

            Format
            ------
            Matrix       : MAxxxx
            Tactic       : TAxxxx
            Technique    : Txxxx(.yyy)
            Sub-Technique: Txxxx.yyy
            Mitigation   : Mxxxx
            Group        : Gxxxx
            Software     : Sxxxx
            UUID         : <STIX-TYPE>--<UUID>

            Parameters
            ----------
            identifier : string
                Identifier to map, see format for the required format of
                identifiers.

            default : object, default=None
                Object to return if no match is found.

            Returns
            -------
            concept : dict()
                Concept retrieved from identifier or default if none was found.
            """
        # Search for item
        return self.map_id  .get(identifier,
               self.map_uuid.get(identifier,
               default))

    @property
    def map_id(self):
        """Generate a map of ID to ATT&CK concept.

            Returns
            -------
            result : dict()
                Map of ID to dict() representing ATT&CK concept.
            """
        # Cache map
        if self._map_id is None:

            # Initialise map
            self._map_id = dict()

            # Add map from each domain
            for domain, attack in sorted(self.domains.items()):
                for id, concept in attack.map_id().items():

                    # Skip double entries
                    # TODO define as list to allow for double mappings?
                    if id in self._map_id and self._map_id[id] != concept:
                        warnings.warn(
                            "Double ID found: '{}', skipping entry for domain "
                            "'{}'".format(id, domain)
                        )
                        continue

                    # Add entry
                    self._map_id[id] = concept

        # Return map
        return self._map_id


    @property
    def map_uuid(self):
        """Generate a map of UUID to ATT&CK concept.

            Returns
            -------
            result : dict()
                Map of UUID to dict() representing ATT&CK concept.
            """
        # Cache map
        if self._map_uuid is None:

            # Initialise map
            self._map_uuid = dict()

            # Add map from each domain
            for domain, attack in sorted(self.domains.items()):
                for uuid, concept in attack.map_uuid().items():

                    # Skip double entries
                    # TODO define as list to allow for double mappings?
                    if uuid in self._map_uuid and\
                       self._map_uuid[uuid] != concept:
                        warnings.warn(
                            "Double UUID found: '{}', skipping entry for domain "
                            "'{}'".format(uuid, domain)
                        )
                        continue

                    # Add entry
                    self._map_uuid[uuid] = concept

        # Return map
        return self._map_uuid

    ########################################################################
    #                             ATT&CK graph                             #
    ########################################################################

    @property
    def graph(self):
        """Get the relations within the ATT&CK framework as a graph.

            Returns
            -------
            graph : nx.DiGraph()
                Directed graph representing the ATT&CK framework.
            """
        # Cache graph
        if self._graph is None:

            # Initialise graph
            self._graph = nx.DiGraph()

            # Get graphs from each ATTACKDomain
            graphs = {
                domain: copy.deepcopy(attack.graph)
                for domain, attack in self.domains.items()
            }

            # Set regex for tactics - used to link domains to tactics
            regex_tactics = re.compile("TA[0-9]{4}")

            # Add domains to each graph
            for domain, graph in graphs.items():
                # Add domain node
                graph.add_node(domain)

                # Connect domain node to all tactics
                for node in graph.nodes():
                    # Check if the node is a tactic
                    if regex_tactics.fullmatch(node):
                        # Add edge
                        graph.add_edge(domain, node)

            # Combine all graphs
            for domain, graph in sorted(graphs.items()):

                # Add all nodes
                for node in graph.nodes():
                    self._graph.add_node(node)

                # Add existing edges
                edges = dict()

                # Add all edges
                for source, target, data in graph.edges(data=True):

                    # Check if an edge exists
                    if (source, target) in edges:
                        raise ValueError("Trying to overwrite an edge!")

                    # Add edge
                    self._graph.add_edge(source, target, **data)
                    edges[(source, target)] = data

        # Return graph
        return self._graph


    def related_concepts(self, identifier, depth=1):
        """Returns all concepts related to the given identifier.

            Format
            ------
            Matrix       : MAxxxx
            Tactic       : TAxxxx
            Technique    : Txxxx(.yyy)
            Sub-Technique: Txxxx.yyy
            Mitigation   : Mxxxx
            Group        : Gxxxx
            Software     : Sxxxx

            Parameters
            ----------
            identifier : string
                Identifier according to the given format.

            depth : int, default=1
                Depth of related concepts in graph. 1 means only direct
                neighbors, 2 includes neighbors of neighbors, etc.

            Returns
            -------
            related_concepts : set()
                Set of related concepts
            """
        # Initialise related concepts
        related_concepts = {identifier}

        # Create a dictionary of related concepts by depth level
        visit_current = 0
        visited = {
            0: {identifier}
        }

        # Loop until all depths are visited
        while visit_current < depth:
            # Extract concepts to visit
            to_visit = visited[visit_current]

            # Increment current
            visit_next = visit_current + 1
            visited[visit_next] = set()

            # Loop over all nodes to visit
            for node in to_visit:
                # Get neigbors of that node
                for neighbor in nx.classes.function.all_neighbors(self.graph, node):
                    # Check if neighbor was already visited
                    if neighbor not in related_concepts:
                        visited[visit_next].add(neighbor)

                    # Add neigbor as related concept
                    related_concepts.add(neighbor)

            # Set level to visit next
            visit_current = visit_next

        # Return all related concepts except identifier
        return related_concepts - {identifier}


    ########################################################################
    #                             Clear cache                              #
    ########################################################################

    def clear(self):
        """Clear ATT&CK framework cache.

            Returns
            -------
            self : self
                Returns self.
            """
        # (Re)set properties
        self._graph    = None
        self._map_id   = None
        self._map_uuid = None

        # Return self
        return self

    ########################################################################
    #                             I/O methods                              #
    ########################################################################

    def summary(self):
        """Returns a string summary of ATT&CK framework."""
        # Initialise header
        result  = "ATT&CK Framework\n"
        result += "-"*30 + '\n'

        # Add summary of all underlying domains
        for domain, attack in sorted(self.domains.items()):
            domain_summary = attack.summary()
            domain_summary = '\n  '.join(domain_summary.split('\n'))
            result += "\n  " + domain_summary
            result += "\n"

        # Return result
        return result

    def store_pickle(self, outfile):
        """Store ATT&CK framework as pickled file for quicker loading.

            Parameters
            ----------
            outfile : string
                Path to file to store ATT&CK framework as pickle.
            """
        # Write to output file
        with open(outfile, 'wb') as outfile:
            pickle.dump(self, outfile)

    @classmethod
    def load_pickle(cls, infile):
        """Load ATT&CK framework from pickled file for quicker loading.

            Parameters
            ----------
            infile : string
                Path to file to from which to load ATT&CK framework as pickle.

            Returns
            -------
            result : ATTACK
                ATTACK from loaded pickle file.
            """
        # Read input file
        with open(infile, 'rb') as infile:
            attack = pickle.load(infile)

        # Return ATTACK
        return attack

    @classmethod
    def load(cls, path, domains=['enterprise', 'ics', 'mobile', 'pre']):
        """Load ATT&CK framework from path.

            Parameters
            ----------
            path : string
                Path from which to load ATT&CK framework.
                Should contain {domain} which will be replaced by given domains.

            domains : list, default=['enterprise', 'ics', 'mobile', 'pre']
                List of all domains to include.

            Returns
            -------
            result : ATTACK
                ATTACK from loaded framework.
            """
        # Initialise ATT&CK dictionary
        attack = dict()

        # Loop over all domains
        for domain in domains:
            # Set path for domain
            path_domain = path.format(domain=domain)

            # Store data
            attack[domain] = ATTACKDomain.load(path_domain, domain)

        # Return ATTACK
        return cls(attack)

    @classmethod
    def download(cls,
            url     = "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v8.2/{domain}-attack/{domain}-attack.json",
            domains = ['enterprise', 'ics', 'mobile', 'pre'],
        ):
        """Download ATT&CK framework from url.

            Parameters
            ----------
            url : string, default="https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v8.2/{domain}-attack/{domain}-attack.json"
                URL from which to download ATT&CK database.
                Note that URL should contain the {domain} template to set
                specific version and domains to load.

            domains : list, default=['enterprise', 'ics', 'mobile', 'pre']
                List of all domains to include.

            Returns
            -------
            result : ATTACK
                ATTACK from downloaded framework.
            """
        # Initialise ATT&CK dictionary
        attack = dict()

        # Loop over all domains
        for domain in domains:

            # Specify domain from which to download ATT&CK framework
            url_source = url.format(domain = domain)

            # Store data
            attack[domain] = ATTACKDomain.download(url_source, domain)

        # Return ATTACK
        return cls(attack)
