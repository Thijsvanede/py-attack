# Imports
import copy
import json
import networkx as nx
import pickle
import re
import warnings
from typing import Dict, Iterator, List, Optional, Set

from collections.abc   import MutableMapping
from py_attack.domains import ATTACKDomain

# Plot imports
import matplotlib.pyplot as plt
from py_attack.types import DomainTypes

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


    def __getitem__(self, key: DomainTypes) -> ATTACKDomain:
        """Returns the given ATTACKDomain for the given DomainType."""
        return self.domains[key]

    def __setitem__(self, key: DomainTypes, value: ATTACKDomain) -> None:
        """Sets the given DomainType to the given ATTACKDomain."""
        self.domains[key] = value

    def __delitem__(self, key: DomainTypes) -> None:
        """Removes the ATTACKDomain for the given DomainType."""
        del self.domains[key]

    def __iter__(self) -> Iterator[DomainTypes]:
        """Returns an iterator over domains in current ATTACK object."""
        return iter(self.domains)

    def __len__(self) -> int:
        """Returns the number of domains in current ATTACK object."""
        return len(self.domains)

    ########################################################################
    #                    Retrieve specific ATT&CK data                     #
    ########################################################################

    @property
    def matrices(self) -> Iterator[dict]:
        """Retrieve all matrices from the ATT&CK framework.

            Yields
            ------
            matrix : dict()
                matrix for each ATT&CK domain.
            """
        for domain, attack in self.domains.items():
            yield from attack.matrices

    @property
    def tactics(self) -> Iterator[dict]:
        """Retrieve all tactics from the ATT&CK framework.

            Yields
            ------
            tactics : dict()
                tactics of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.tactics

    @property
    def techniques(self) -> Iterator[dict]:
        """Retrieve all techniques from the ATT&CK framework.

            Yields
            ------
            techniques : dict()
                techniques of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.techniques

    @property
    def sub_techniques(self) -> Iterator[dict]:
        """Retrieve all sub-techniques from the ATT&CK framework.

            Yields
            ------
            sub_techniques : dict()
                sub_techniques of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.sub_techniques

    @property
    def procedures(self) -> Iterator[dict]:
        """Retrieve all procedures from the ATT&CK framework.

            Yields
            ------
            procedures : dict()
                procedures of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.procedures

    @property
    def relationships(self) -> Iterator[dict]:
        """Retrieve all relationships from the ATT&CK framework.

            Note
            ----
            While not all relationships are part of the ATT&CK concepts, it is
            useful to have a method for extracting relationships. Among others
            to build the ATT&CK graph.

            Yields
            ------
            relationships : dict()
                relationships of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.relationships

    @property
    def mitigations(self) -> Iterator[dict]:
        """Retrieve all mitigations from the ATT&CK framework.

            Yields
            ------
            mitigations : dict()
                mitigations of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.mitigations

    @property
    def groups(self) -> Iterator[dict]:
        """Retrieve all groups from the ATT&CK framework.

            Yields
            ------
            groups : dict()
                groups of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.groups

    @property
    def software(self) -> Iterator[dict]:
        """Retrieve all software from the ATT&CK framework.

            Yields
            ------
            software : dict()
                software of all ATT&CK domains.
            """
        for domain, attack in self.domains.items():
            yield from attack.software

    ########################################################################
    #                  Retrieve ATT&CK concept attributes                  #
    ########################################################################

    @property
    def concepts(self) -> Iterator[dict]:
        """Generator over all concepts of the ATT&CK framework.

            Note
            ----
            Yields the following concept types:
            ``Matrix``,
            ``Tactic``,
            ``Technique``,
            ``Sub-technique``,
            ``Procedure``,
            ``Mitigation``,
            ``Group``,
            ``Software``.

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

    @property
    def graph_concepts(self) -> Iterator[dict]:
        """Generator over all ATT&CK concepts present in the graph.
            This **excludes** ``matrices`` and ``procedures``.

            Note
            ----
            Yields the following concept types:
            ``Tactic``,
            ``Technique``,
            ``Sub-technique``,
            ``Mitigation``,
            ``Group``,
            ``Software``.

            Yields
            ------
            concept : dict()
                A dictionary describing each ATT&CK graph concept.
            """
        # Iterate over all concepts
        yield from self.tactics
        yield from self.techniques
        yield from self.mitigations
        yield from self.groups
        yield from self.software

    ########################################################################
    #                          Map ID to concept                           #
    ########################################################################

    def get(self, identifier: str, default: object = None) -> dict:
        """Map identifier to ATT&CK concept.
            See :ref:`format` for accepted formatting.

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
    def map_id(self) -> Dict[str, dict]:
        """Generate a map of ID to ATT&CK concept.

            Returns
            -------
            result : Dict[str, dict]
                Map of ID to dict() representing ATT&CK concept.
            """
        # Cache map
        if self._map_id is None:

            # Initialise map
            self._map_id = dict()

            # Add map from each domain
            for domain, attack in sorted(self.domains.items()):
                for id, concept in attack.map_id.items():

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
    def map_uuid(self) -> Dict[str, dict]:
        """Generate a map of UUID to ATT&CK concept.

            Returns
            -------
            result : Dict[str, dict]
                Map of UUID to dict() representing ATT&CK concept.
            """
        # Cache map
        if self._map_uuid is None:

            # Initialise map
            self._map_uuid = dict()

            # Add map from each domain
            for domain, attack in sorted(self.domains.items()):
                for uuid, concept in attack.map_uuid.items():

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
    def graph(self) -> nx.DiGraph:
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
                    self._graph.add_node(node, **graph.nodes[node])

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


    def plot(self, domain: Optional[DomainTypes] = None) -> None:
        """Plots ATTACK as a graph to show relations between concepts.

            Parameters
            ----------
            domain : string ('enterprise' | 'ics' | 'mobile' | 'pre'), optional
                If given, only plot the given domain.
            """
        # Get graph representation of ATTACK object
        if domain is None:
            graph = self.graph
        else:
            graph = self.domains.get(domain).graph

        # Get labels
        labels = {node: graph.nodes[node].get('id') for node in graph.nodes()}

        # Set positions
        pos = {
            'Group'        : list(),
            'Software'     : list(),
            'Technique'    : list(),
            'Sub-technique': list(),
            'Mitigation'   : list(),
            'Tactic'       : list(),
        }

        # Loop over all nodes
        for node in graph.nodes():
            # Get category of node
            category   = graph.nodes[node].get('category')
            if category is None: continue
            identifier = graph.nodes[node].get('id')
            # Add node to category
            pos[category].append((node, identifier))

        # Sort nodes per position
        for key, values in pos.items():
            # Sort by key
            pos[key] = [x[0] for x in sorted(values, key=lambda x: x[1])]

        # Create positions
        positions = {node: (0, 0) for node in graph.nodes()}

        spacing = 10
        padding = 50

        # Add groups
        for index, node in enumerate(pos['Group']):
            positions[node] = (
                index     * spacing + padding,
                (index+1) * spacing,
            )

        # Add software
        for index, node in enumerate(pos['Software']):
            positions[node] = (
                 index     * spacing + padding,
                -(index+1) * spacing,
            )

        # Add techniques
        x = max([y for x, y in positions.values()])
        for index, node in enumerate(pos['Technique']):
            positions[node] = (x, 0)

            # Add regular spacing
            x += spacing
            # Add spacing for each subtechnique


        # Add subtechniques


        # Set labels
        labels = {node: graph.nodes[node].get('id') for node in graph.nodes()}

        # Draw graph
        nx.draw(
            graph,
            positions,
            alpha      = 0.8,
            font_size  = 8,
            labels     = labels,
            node_size  = 50,
            node_color = 'black',
            width      = 0.5,
        )

        plt.show()



    def related_concepts(self, identifier: str, depth: int = 1) -> Set[dict]:
        """Returns all concepts related to the given identifier.
            See :ref:`format` for accepted formatting.

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


    def get_relation(
            self,
            source: str,
            target: str,
            bidirectional: bool = True,
        ) -> dict:
        """Return the relation between a source and targed node.
            See :ref:`format` for accepted formatting.

            Parameters
            ----------
            source : string
                Identifier of source concept according to the given
                :ref:`format`.

            target : string
                Identifier of target concept according to the given
                :ref:`format`.

            bidirectional : boolean, default=True
                If True, return either the target -> source relation if
                source -> target is not found.

            Returns
            -------
            relation : dict()
                Relationship between source and target
            """
        # Get relation between source -> target
        result = self.graph.get_edge_data(source, target)

        # If no relation found and bidirectional, return relation between
        # target -> source instead
        if result is None and bidirectional:
            return self.graph.get_edge_data(target, source)

        # Return result
        return result


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

    def summary(self) -> str:
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
        

    def store_pickle(self, outfile: str) -> None:
        """Store ATT&CK framework as pickled file for quicker loading.

            Parameters
            ----------
            outfile : string
                Path to file to store ATT&CK framework as pickle.
            """
        # Write to output file
        with open(outfile, 'wb') as outfile:
            pickle.dump(self, outfile)


    def to_json(self) -> str:
        """Transform ATTACK to a JSON string.
            Also see :py:meth:`from_json`.
        
            Returns
            -------
            json : str
                JSON string representing ATTACK.
            """
        return json.dumps({
            name: domain.to_json() for name, domain in self.domains.items()
        })


    @classmethod
    def from_json(cls, json_str: str):
        """Load ATTACK from JSON string.
            Also see :py:meth:`to_json`.
        
            Parameters
            ----------
            json_str : str
                JSON string representing ATTACK.
            
            Returns
            -------
            domain : ATTACK
                ATTACK loaded from JSON string.
            """
        # Load json from string
        return cls({
            name: ATTACKDomain.from_json(domain)
            for name, domain in json.loads(json_str).items()
        })


    @classmethod
    def load_pickle(cls, infile: str):
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
    def load(
            cls,
            path: str,
            domains: List[DomainTypes] = ['enterprise', 'ics', 'mobile', 'pre'],
        ):
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
            url    : str = "https://raw.githubusercontent.com/mitre/cti/master/{domain}-attack/{domain}-attack.json",
            domains: List[DomainTypes] = ['enterprise', 'ics', 'mobile', 'pre'],
        ):
        """Download ATT&CK framework from url.

            Note
            ----
            We recommend to download the MITRE CTI repository to a local
            directory and load the ATTACK object through the :py:meth:`load`
            method. This assures that your project works with a consistent
            version of the MITRE ATT&CK framework and avoids repeated
            downloading of the CTI sources.

            The MITRE CTI repository can be found here:
            https://github.com/mitre/cti.

            Parameters
            ----------
            url : string, default="https://raw.githubusercontent.com/mitre/cti/master/{domain}-attack/{domain}-attack.json"
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
