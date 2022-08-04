import json
import networkx as nx
import pickle
import re
from py_attack.types import DomainTypes
import requests
from typing import Dict, Iterable, Iterator, List, Optional, Set

from py_attack.utils  import get_id, get_uuid
from py_attack.filter import Filter, query

class ATTACKDomain:
    """The ATTACKDomain object provides a simple interface for loading and
        interacting with a domain in the ATT&CK framework."""

    ########################################################################
    #                     ATTACKDomain as a dictionary                     #
    ########################################################################

    def __init__(self, domain: DomainTypes, store: dict):
        """The ATTACKDomain object provides a simple interface for loading and
            interacting with a domain in the ATT&CK framework.

            Parameters
            ----------
            domain : DomainTypes
                Domain covered by the ATTACKDomain. E.g., enterprise, mobile,
                ics.

            store : dict()
                Dictionary for ATT&CK domain, loaded from CTI json file.
            """
        # Set domain name
        self.domain = domain

        # Set store
        self.store = store

        # Set empty cache
        self.clear()

    ########################################################################
    #                             Get methods                              #
    ########################################################################

    def __getitem__(self, key: str) -> dict:
        """Return concept for given identifier.
        
            Usage: domain[key]
        
            Parameters
            ----------
            key : str
                Key to get for domain.
            """
        return self.get(key, KeyError(key))

    def get(self, key: str, default: object = None) -> Optional[dict]:
        """Return concept for given identifier.
        
            Parameters
            ----------
            key : str
                Key to get for domain.
                
            default : object, default=None
                Default to return if no object could be found.
                
            """
        # Get result
        result = self.map_id.get(key, self.map_uuid.get(key, default))

        # Check for error
        if isinstance(result, Exception): raise result

        # Otherwise return result
        return result

    ########################################################################
    #                    Retrieve specific ATT&CK data                     #
    ########################################################################

    @property
    def matrices(self) -> List[dict]:
        """Retrieve all matrices from the ATT&CKDomain.

            Returns
            -------
            matrices : list()
                List of dict() objects representing all matrices.
            """
        # Cache matrices
        if self._matrices is None:

            # Extract matrices
            self._matrices = query(self.store, [
                Filter('type', '=', 'x-mitre-matrix')
            ])

            # Filter deprecated concepts
            self._matrices = self.filter_deprecated(self._matrices)

            # Add MITRE ATT&CK ID to concept
            self._matrices = self.add_mitre_attack_id(self._matrices)

        # Return result
        return self._matrices


    @property
    def tactics(self) -> List[dict]:
        """Retrieve all tactics from the ATT&CKDomain.

            Returns
            -------
            tactics : list()
                List of dict() objects representing all tactics.
            """
        # Cache tactics
        if self._tactics is None:

            # Extract tactics
            self._tactics = query(self.store, [
                Filter('type', '=', 'x-mitre-tactic')
            ])

            # Filter deprecated concepts
            self._tactics = self.filter_deprecated(self._tactics)

            # Perform checks on ID, should match TAxxxx
            regex_tactics = re.compile('TA[0-9]{4}')
            for concept in self._tactics:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

            # Add MITRE ATT&CK ID to concept
            self._tactics = self.add_mitre_attack_id(self._tactics)

        # Return result
        return self._tactics


    @property
    def techniques(self) -> List[dict]:
        """Retrieve all techniques from the ATT&CKDomain.

            Returns
            -------
            techniques : list()
                List of dict() objects representing all techniques.
            """
        # Cache techniques
        if self._techniques is None:

            # Extract techniques
            self._techniques = query(self.store, [
                Filter('type', '=', 'attack-pattern')
            ])

            # Filter deprecated concepts
            self._techniques = self.filter_deprecated(self._techniques)

            # Perform checks on ID, should match Txxxx(.yyy)
            regex_tactics = re.compile('T[0-9]{4}(\.[0-9]{3})?')
            for concept in self._techniques:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

            # Add MITRE ATT&CK ID to concept
            self._techniques = self.add_mitre_attack_id(self._techniques)

        # Return result
        return self._techniques


    @property
    def sub_techniques(self) -> List[dict]:
        """Retrieve all sub-techniques from the ATT&CKDomain.

            Returns
            -------
            sub_techniques : list()
                List of dict() objects representing all sub-techniques.
            """
        # Cache sub-techniques
        if self._sub_techniques is None:

            # Extract sub-techniques
            self._sub_techniques = query(self.store, [
                Filter('type'                   , '=', 'attack-pattern'),
                Filter('x_mitre_is_subtechnique', '=', True            ),
            ])

            # Filter deprecated concepts
            self._sub_techniques = self.filter_deprecated(self._sub_techniques)

            # Perform checks on ID, should match Txxxx.yyy
            regex_tactics = re.compile('T[0-9]{4}\.[0-9]{3}')
            for concept in self._sub_techniques:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

            # Add MITRE ATT&CK ID to concept
            self._sub_techniques = self.add_mitre_attack_id(self._sub_techniques)

        # Return result
        return self._sub_techniques


    @property
    def procedures(self) -> List[dict]:
        """Retrieve all procedures from the ATT&CKDomain.

            Returns
            -------
            procedures : list()
                List of dict() objects representing all procedures.
            """
        # Cache procedures
        if self._procedures is None:

            # Extract procedures
            self._procedures = query(self.store, [
                Filter('type'             , '='       , 'relationship'  ),
                Filter('relationship_type', '='       , 'uses'          ),
                Filter('target_ref'       , 'contains', 'attack-pattern'),
            ])

            # Filter deprecated concepts
            self._procedures = self.filter_deprecated(self._procedures)

            # Add MITRE ATT&CK ID to concept
            self._procedures = self.add_mitre_attack_id(self._procedures)

        # Return result
        return self._procedures


    @property
    def relationships(self) -> List[dict]:
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
            self._relationships = query(self.store, [
                Filter('type', '=', 'relationship'),
            ])

            # Filter deprecated concepts
            self._relationships = self.filter_deprecated(self._relationships)

            # Add MITRE ATT&CK ID to concept
            self._relationships = self.add_mitre_attack_id(self._relationships)

        # Return result
        return self._relationships


    @property
    def mitigations(self) -> List[dict]:
        """Retrieve all mitigations from the ATT&CKDomain.

            Returns
            -------
            mitigations : list()
                List of dict() objects representing all mitigations.
            """
        # Cache mitigations
        if self._mitigations is None:

            # Extract mitigations and add to mitigations
            self._mitigations = query(self.store, [
                Filter('type', '=', 'course-of-action')
            ])

            # Filter deprecated concepts
            self._mitigations = self.filter_deprecated(self._mitigations)

            # Perform checks on ID, should match Mxxxx
            regex_tactics = re.compile('M[0-9]{4}')
            for concept in self._mitigations:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

            # Add MITRE ATT&CK ID to concept
            self._mitigations = self.add_mitre_attack_id(self._mitigations)

        # Return result
        return self._mitigations


    @property
    def groups(self) -> List[dict]:
        """Retrieve all groups from the ATT&CKDomain.

            Returns
            -------
            groups : list()
                List of dict() objects representing all groups.
            """
        # Cache groups
        if self._groups is None:

            # Extract groups
            self._groups = query(self.store, [
                Filter('type', '=', 'intrusion-set')
            ])

            # Filter deprecated concepts
            self._groups = self.filter_deprecated(self._groups)

            # Perform checks on ID, should match Gxxxx
            regex_tactics = re.compile('G[0-9]{4}')
            for concept in self._groups:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

            # Add MITRE ATT&CK ID to concept
            self._groups = self.add_mitre_attack_id(self._groups)

        # Return result
        return self._groups


    @property
    def software(self) -> List[dict]:
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
            self._software.extend(query(self.store, [
                Filter('type', '=', 'malware')
            ]))
            # Extract tools and add to software
            self._software.extend(query(self.store, [
                Filter('type', '=', 'tool')
            ]))

            # Filter deprecated concepts
            self._software = self.filter_deprecated(self._software)

            # Perform checks on ID, should match Sxxxx
            regex_tactics = re.compile('S[0-9]{4}')
            for concept in self._software:
                assert regex_tactics.fullmatch(get_id(concept)) is not None

            # Add MITRE ATT&CK ID to concept
            self._software = self.add_mitre_attack_id(self._software)

        # Return result
        return self._software

    ########################################################################
    #                       Add MITRE ID to concepts                       #
    ########################################################################

    def add_mitre_attack_id(
            self,
            concepts: Iterable[dict],
            keys    : List[str] = ['identifier'],
        ) -> List[dict]:
        """Add MITRE ATT&CK ID to a multiple concepts.

            Parameters
            ----------
            concepts : iterable of dict()
                Concepts for which to add MITRE ATT&CK ID.

            keys : list(), default=['identifier']
                Key(s) in which to store concept ID.

            Returns
            -------
            concepts : list of dict()
                Concepts where MITRE ATT&CK ID was added to key values.
            """
        # Set MITRE ATT&CK IDs to each concept
        return [
            self._add_mitre_attack_id_(concept, keys)
            for concept in concepts
        ]

    def _add_mitre_attack_id_(
            self,
            concept: dict,
            keys   : List[str] = ['identifier'],
        ) -> dict:
        """Add MITRE ATT&CK ID to a single concept.

            Parameters
            ----------
            concept : dict()
                Dictionary for which to add MITRE ATT&CK ID.

            keys : list(), default=['identifier']
                Key(s) in which to store concept ID.

            Returns
            -------
            concept : dict()
                Concept where MITRE ATT&CK ID was added to key values.
            """
        # Perform checks
        assert isinstance(concept, dict), "Concept should be a dictionary."
        for key in keys:
            assert (
                key not in concept or
                get_id(concept) == concept.get(key)
            ), "'{}' is already in concept".format(key)

        # Add identifier to concept
        identifier = get_id(concept)
        for key in keys:
            concept[key] = identifier

        # Return concept
        return concept

    ########################################################################
    #                             ATT&CK graph                             #
    ########################################################################

    @property
    def graph(self) -> nx.DiGraph:
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
                self._graph.add_node(
                    get_id(tactic),
                    id          = get_id(tactic),
                    domain      = self.domain,
                    framework   = "ATTACK",
                    category    = "Tactic",
                    description = tactic.get('description'),
                )
            # Add all ATT&CK techniques to graph
            for technique in self.techniques:
                self._graph.add_node(
                    get_id(technique),
                    id          = get_id(technique),
                    domain      = self.domain,
                    framework   = "ATTACK",
                    category    = "Technique",
                    description = technique.get('description'),
                )
            # Add all ATT&CK sub_techniques to graph
            for sub_technique in self.sub_techniques:
                self._graph.add_node(
                    get_id(sub_technique),
                    id          = get_id(sub_technique),
                    domain      = self.domain,
                    framework   = "ATTACK",
                    category    = "Sub-technique",
                    description = sub_technique.get('description'),
                )
            # Add all ATT&CK mitigations to graph
            for mitigation in self.mitigations:
                self._graph.add_node(
                    get_id(mitigation),
                    id          = get_id(mitigation),
                    domain      = self.domain,
                    framework   = "ATTACK",
                    category    = "Mitigation",
                    description = mitigation.get('description'),
                )
            # Add all ATT&CK groups to graph
            for group in self.groups:
                self._graph.add_node(
                    get_id(group),
                    id          = get_id(group),
                    domain      = self.domain,
                    framework   = "ATTACK",
                    category    = "Group",
                    description = group.get('description'),
                )
            # Add all ATT&CK software to graph
            for software in self.software:
                self._graph.add_node(
                    get_id(software),
                    id          = get_id(software),
                    domain      = self.domain,
                    framework   = "ATTACK",
                    category    = "Software",
                    description = software.get('description'),
                )

            # Count number of nodes
            n_nodes = len(self._graph.nodes())

            ############################################################
            #                  Concepts by reference                   #
            ############################################################

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
                for phase in technique.get("kill_chain_phases"):
                    # Find tactic of kill chain phase
                    tactic = ref_tactics_name.get(phase.get('phase_name'))
                    tactic = get_id(tactic)

                    # Add edge
                    self._graph.add_edge(
                        technique_id,
                        tactic,
                        relation = "kill_chain_phase",
                    )


            # Add relations between mitigations and techniques
            for relation in self.relationships:
                # Get source and target
                source = self.map_uuid.get(relation.get('source_ref'))
                target = self.map_uuid.get(relation.get('target_ref'))

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
                    info     = relation,
                )

            # Assert that adding edges did not change the number of nodes
            assert n_nodes == len(self._graph.nodes())

        # Return graph
        return self._graph


    def related_concepts(
            self,
            identifier: str,
            depth     : int = 1,
        ) -> Set[dict]:
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

    ########################################################################
    #                  Retrieve ATT&CK concept attributes                  #
    ########################################################################

    @property
    def concepts(self) -> Iterator[dict]:
        """Generator over all concepts of the ATT&CK framework for this domain.

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
    def map_id(self) -> Dict[str, dict]:
        """Get a map of all ID -> ATT&CK concepts.

            Returns
            -------
            map : dict()
                Dictionary of ID -> ATT&CK concept.
            """
        # Cache map
        if self._map_id is None:

            # Initialise map
            self._map_id = {
                get_id(concept): concept
                for concept in self.concepts
                if get_id(concept)
            }

        # Return map
        return self._map_id


    @property
    def map_uuid(self) -> Dict[str, dict]:
        """Get a map of all UUID -> ATT&CK concepts.

            Returns
            -------
            map : dict()
                Dictionary of UUID -> ATT&CK concept.
            """
        # Cache map
        if self._map_uuid is None:

            # Initialise map
            self._map_uuid = {
                get_uuid(concept): concept
                for concept in self.concepts
                if get_uuid(concept)
            }

        # Return map
        return self._map_uuid


    def filter_deprecated(self, concepts: Iterable[dict]) -> List[dict]:
        """Filter deprecated and revoked concepts from given concepts.

            Parameters
            ----------
            concepts : Iterable[dict]
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

        # (Re)set maps
        self._map_id   = None
        self._map_uuid = None

        # (Re)set graph
        self._graph = None

        # Return self
        return self

    ########################################################################
    #                             I/O methods                              #
    ########################################################################

    def summary(self) -> str:
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


    def store_pickle(self, outfile: str) -> None:
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
    def load_pickle(cls, infile: str):
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


    def to_json(self) -> str:
        """Transform AttackDomain to a JSON string.
            Also see :py:meth:`from_json`.
        
            Returns
            -------
            json : str
                JSON string representing domain.
            """
        return json.dumps({
            'domain': self.domain,
            'store' : self.store,
        })


    @classmethod
    def from_json(cls, json_str: str):
        """Load AttackDomain from JSON string.
            Also see :py:meth:`to_json`.
        
            Parameters
            ----------
            json_str : str
                JSON string representing domain.
            
            Returns
            -------
            domain : AttackDomain
                AttackDomain loaded from JSON string.
            """
        # Load json from string
        json_str = json.loads(json_str)

        # Return ATTACK
        return cls(
            domain = json_str['domain'],
            store  = json_str['store'],
        )


    @classmethod
    def load(cls, path: str, domain: DomainTypes):
        """Load ATT&CKDomain from path.

            Parameters
            ----------
            path : string
                Path from which to load ATT&CKDomain.
                If the path contains the string ``{domain}``, this will be
                automatically replaced by the domain specified by the parameter
                ``domain``.

            domain : DomainTypes
                Name of domain to load.

            Returns
            -------
            result : ATT&CKDomain
                ATT&CKDomain from loaded file.
            """
        # Specify domain from which to load ATT&CKDomain if necessary
        if "{domain}" in path:
            path = path.format(domain = domain)

        # Read file as json
        with open(path, 'r') as infile:
            stix_json = json.load(infile)

        # Return ATTACK
        return cls(domain, stix_json["objects"])


    @classmethod
    def download(cls,
            url   : str = "https://raw.githubusercontent.com/mitre/cti/master/{domain}-attack/{domain}-attack.json",
            domain: DomainTypes = 'enterprise',
        ):
        """Download ATTACKDomain from url.

            Note
            ----
            We recommend to download the MITRE CTI repository to a local
            directory and load the ATTACKDomain object through the
            :py:meth:`load` method. This assures that your project works with a
            consistent version of the MITRE ATT&CK framework and avoids repeated
            downloading of the CTI sources.

            The MITRE CTI repository can be found here:
            https://github.com/mitre/cti.

            Example
            -------
            All content should be available from the following URL(s):
            ``https://raw.githubusercontent.com/mitre/cti/{version}/{domain}-attack/{domain}-attack.json``
            Where ``{version}`` is the version you want to retrieve, e.g.
            ``master`` for the current version or ``ATT%26CK-v8.2`` for version
            8.2 and ``{domain}`` is the domain you want to retrieve, e.g.
            ``enterprise``.

            Parameters
            ----------
            url : string, default="https://raw.githubusercontent.com/mitre/cti/master/{domain}-attack/{domain}-attack.json"
                URL from which to download ATT&CKDomain.
                If the url contains the string ``{domain}``, this will be
                automatically replaced by the domain specified by the parameter
                ``domain``.

            domain : DomainTypes, default='enterprise'
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

        # Return ATTACKDomain
        return cls(domain, stix_json)
