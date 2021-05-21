# Imports
import copy
import json
import networkx as nx
import pickle
import re
import warnings

from collections.abc   import MutableMapping
from py_attack.domains import ATTACKDomain

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
    #                  Retrieve ATT&CK concept attributes                  #
    ########################################################################

    @property
    def concepts(self):
        """Generator over all concepts of the ATT&CK framework.

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
                # Skip nodes that are not in graph
                if node not in self.graph: continue

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
