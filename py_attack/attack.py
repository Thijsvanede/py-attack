# Imports
import json
import networkx as nx
import os
import pickle
import re
import requests

from collections.abc import MutableMapping
from stix2           import Filter, MemoryStore

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
        # Set store as dictionary
        self.store = dict()
        self.update(dict(*args, **kwargs))

        # Set empty cache
        self.clear()


    def __getitem__(self, key):
        return self.store[key]

    def __setitem__(self, key, value):
        self.store[key] = value

    def __delitem__(self, key):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    ########################################################################
    #                    Retrieve specific ATT&CK data                     #
    ########################################################################

    @property
    def domains(self):
        """Return all domains from the ATT&CK framework.

            Returns
            -------
            domains : list()
                List of all domains stored in the framework.
            """
        return list(sorted(self.store.keys()))

    @property
    def matrices(self):
        """Retrieve all matrices from the ATT&CK framework.

            Returns
            -------
            matrices : list()
                List of dict() objects representing all matrices.
            """
        # Cache matrices
        if self._matrices is None:

            # Initialise list of all matrices
            self._matrices = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract matrices and add to matrices
                self._matrices.extend(attack.query([
                    Filter('type', '=', 'x-mitre-matrix')
                ]))

            # Filter deprecated concepts
            self._matrices = self.filter_deprecated(self._matrices)

        # Return result
        return self._matrices

    @property
    def tactics(self):
        """Retrieve all tactics from the ATT&CK framework.

            Returns
            -------
            tactics : list()
                List of dict() objects representing all tactics.
            """
        # Cache tactics
        if self._tactics is None:

            # Initialise list of all tactics
            self._tactics = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract tactics and add to tactics
                self._tactics.extend(attack.query([
                    Filter('type', '=', 'x-mitre-tactic')
                ]))

            # Filter deprecated concepts
            self._tactics = self.filter_deprecated(self._tactics)

            # Perform checks on ID, should match TAxxxx
            regex_tactics = re.compile('TA[0-9]{4}')
            for concept in self._tactics:
                assert regex_tactics.fullmatch(self.get_id(concept)) is not None

        # Return result
        return self._tactics

    @property
    def techniques(self):
        """Retrieve all techniques from the ATT&CK framework.

            Returns
            -------
            techniques : list()
                List of dict() objects representing all techniques.
            """
        # Cache techniques
        if self._techniques is None:

            # Initialise list of all techniques
            self._techniques = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract techniques and add to techniques
                self._techniques.extend(attack.query([
                    Filter('type', '=', 'attack-pattern')
                ]))

            # Filter deprecated concepts
            self._techniques = self.filter_deprecated(self._techniques)

            # Perform checks on ID, should match Txxxx(.yyy)
            regex_tactics = re.compile('T[0-9]{4}(\.[0-9]{3})?')
            for concept in self._techniques:
                assert regex_tactics.fullmatch(self.get_id(concept)) is not None

        # Return result
        return self._techniques

    @property
    def sub_techniques(self):
        """Retrieve all sub-techniques from the ATT&CK framework.

            Returns
            -------
            sub_techniques : list()
                List of dict() objects representing all sub-techniques.
            """
        # Cache sub-techniques
        if self._sub_techniques is None:

            # Initialise list of all sub-techniques
            self._sub_techniques = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract sub-techniques and add to sub-techniques
                self._sub_techniques.extend(attack.query([
                    Filter('type'                   , '=', 'attack-pattern'),
                    Filter('x_mitre_is_subtechnique', '=', True            ),
                ]))

            # Filter deprecated concepts
            self._sub_techniques = self.filter_deprecated(self._sub_techniques)

            # Perform checks on ID, should match Txxxx.yyy
            regex_tactics = re.compile('T[0-9]{4}\.[0-9]{3}')
            for concept in self._sub_techniques:
                assert regex_tactics.fullmatch(self.get_id(concept)) is not None

        # Return result
        return self._sub_techniques

    @property
    def procedures(self):
        """Retrieve all procedures from the ATT&CK framework.

            Returns
            -------
            procedures : list()
                List of dict() objects representing all procedures.
            """
        # Cache procedures
        if self._procedures is None:

            # Initialise list of all procedures
            self._procedures = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract procedures and add to procedures
                self._procedures.extend(attack.query([
                    Filter('type'             , '='       , 'relationship'  ),
                    Filter('relationship_type', '='       , 'uses'          ),
                    Filter('target_ref'       , 'contains', 'attack-pattern'),
                ]))

            # Filter deprecated concepts
            self._procedures = self.filter_deprecated(self._procedures)

        # Return result
        return self._procedures

    @property
    def relationships(self):
        """Retrieve all relationships from the ATT&CK framework.

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

            # Initialise list of all relationships
            self._relationships = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract relationships and add to relationships
                self._relationships.extend(attack.query([
                    Filter('type', '=', 'relationship'),
                ]))

            # Filter deprecated concepts
            self._relationships = self.filter_deprecated(self._relationships)

        # Return result
        return self._relationships

    @property
    def mitigations(self):
        """Retrieve all mitigations from the ATT&CK framework.

            Returns
            -------
            mitigations : list()
                List of dict() objects representing all mitigations.
            """
        # Cache mitigations
        if self._mitigations is None:

            # Initialise list of all mitigations
            self._mitigations = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract mitigations and add to mitigations
                self._mitigations.extend(attack.query([
                    Filter('type', '=', 'course-of-action')
                ]))

            # Filter deprecated concepts
            self._mitigations = self.filter_deprecated(self._mitigations)

            # Perform checks on ID, should match Mxxxx
            regex_tactics = re.compile('M[0-9]{4}')
            for concept in self._mitigations:
                assert regex_tactics.fullmatch(self.get_id(concept)) is not None

        # Return result
        return self._mitigations

    @property
    def groups(self):
        """Retrieve all groups from the ATT&CK framework.

            Returns
            -------
            groups : list()
                List of dict() objects representing all groups.
            """
        # Cache groups
        if self._groups is None:

            # Initialise list of all groups
            self._groups = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract groups and add to groups
                self._groups.extend(attack.query([
                    Filter('type', '=', 'intrusion-set')
                ]))

            # Filter deprecated concepts
            self._groups = self.filter_deprecated(self._groups)

            # Perform checks on ID, should match Gxxxx
            regex_tactics = re.compile('G[0-9]{4}')
            for concept in self._groups:
                assert regex_tactics.fullmatch(self.get_id(concept)) is not None

        # Return result
        return self._groups

    @property
    def software(self):
        """Retrieve all software from the ATT&CK framework.

            Returns
            -------
            software : list()
                List of dict() objects representing all software.
            """
        # Cache software
        if self._software is None:

            # Initialise list of all software
            self._software = list()

            # Loop over all domains
            for domain, attack in self.items():
                # Extract malware and tools and add to software
                self._software.extend(attack.query([
                    Filter('type', '=', 'malware')
                ]))
                self._software.extend(attack.query([
                    Filter('type', '=', 'tool')
                ]))

            # Filter deprecated concepts
            self._software = self.filter_deprecated(self._software)

            # Perform checks on ID, should match Sxxxx
            regex_tactics = re.compile('S[0-9]{4}')
            for concept in self._software:
                assert regex_tactics.fullmatch(self.get_id(concept)) is not None

        # Return result
        return self._software

    ########################################################################
    #                  Retrieve ATT&CK concept attributes                  #
    ########################################################################

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

    def map_uuid(self):
        """Get a map of all UUID -> ATT&CK concepts.

            Returns
            -------
            map : dict()
                Dictionary of UUID -> ATT&CK concept.
            """
        return {self.get_uuid(concept): concept for concept in self.concepts()}

    def get_uuid(self, concept):
        """Get the UUID of an ATT&CK concept.

            Format
            ------
            <STIX-TYPE>--<UUID>

            Parameters
            ----------
            concept : dict()
                ATT&CK concept from which to retrieve UUID.

            Returns
            -------
            UUID : string
                ATT&CK UUID of concept.
            """
        return concept.get('id')

    def get_id(self, concept):
        """Get the human readable ID of an ATT&CK concept.

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
            concept : dict()
                ATT&CK concept from which to retrieve ID.

            Returns
            -------
            ID : string
                ATT&CK ID of concept.
            """
        return concept.get('external_references', [{}])[0].get('external_id')


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
            # Create graph
            self._graph = nx.DiGraph()

            ############################################################
            #                     Add graph nodes                      #
            ############################################################

            # Add all ATT&CK domains
            for domain in self.domains:
                self._graph.add_node(domain)

            # Add all ATT&CK tactics to graph
            for tactic in self.tactics:
                self._graph.add_node(self.get_id(tactic))
            # Add all ATT&CK techniques to graph
            for technique in self.techniques:
                self._graph.add_node(self.get_id(technique))
            # Add all ATT&CK sub_techniques to graph
            for sub_technique in self.sub_techniques:
                self._graph.add_node(self.get_id(sub_technique))
            # Add all ATT&CK mitigations to graph
            for mitigation in self.mitigations:
                self._graph.add_node(self.get_id(mitigation))
            # Add all ATT&CK groups to graph
            for group in self.groups:
                self._graph.add_node(self.get_id(group))
            # Add all ATT&CK software to graph
            for software in self.software:
                self._graph.add_node(self.get_id(software))

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

            # Add domain -> tactics
            for matrix in self.matrices:
                # Extract domain from matrix
                # Note: For some bizzare reason the ICS matrix has a 'correct'
                # ID according to the format MAxxx, but the others don't. So
                # we have to parse those differently
                domain = self.get_id(matrix).split('-')[0]

                # Special case for ICS
                # Check for MAxxx case, if so, retrieve trhough source_name
                if re.compile("MA[0-9]{4}").fullmatch(domain):
                    domain = matrix.get('external_references', [{}])[0]
                    domain = domain.get('source_name').split('-')[1]

                # Loop over all tactics in matrix
                for tactic in matrix.get('tactic_refs', list()):
                    tactic = self.get_id(map_uuid.get(tactic, {}))

                    # Add edge
                    self._graph.add_edge(
                        domain,
                        tactic,
                        relation = "matrix",
                    )


            # Add relations between (Sub-)Techniques and Tactics
            # using kill_chain_phases

            # Loop over all techniques
            for technique in self.techniques:
                # Extract technique ID
                technique_id = self.get_id(technique)

                # Find corresponding kill chain phases
                for phase in technique.kill_chain_phases:
                    # Find tactic of kill chain phase
                    tactic = ref_tactics_name.get(phase.get('phase_name'))
                    tactic = self.get_id(tactic)

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
                id_source = self.get_id(source)
                id_target = self.get_id(target)

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
        """Returns a string summary of ATT&CK framework."""
        return """ATT&CK Framework
------------------------------
  Domains            : {:>7}
  # Matrices         : {:>7}
  # Tactics          : {:>7}
  # Techniques       : {:>7}
  #   Sub-techniques : {:>7}
  # Procedures       : {:>7}
  # Mitigations      : {:>7}
  # Groups           : {:>7}
  # Software         : {:>7}
""".format(
    len(self.store         ),
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

            domains : list, default=['enterprise', 'ics', 'mobile', 'pre']
                List of all domains to include.

            Returns
            -------
            result : ATTACK
                ATTACK from loaded framework.
            """
        # Initialise ATT&CK dictionary
        attack = dict()

        # Set base path
        path = os.path.join(path, "{domain}-attack", "{domain}-attack.json")

        # Loop over all domains
        for domain in domains:
            # Set path for domain
            path_domain = path.format(domain=domain)

            # Read file as json
            with open(path_domain, 'r') as infile:
                stix_json = json.load(infile)

            # Store data
            attack[domain] = MemoryStore(stix_data=stix_json["objects"])

        # Return ATTACK
        return cls(attack)

    @classmethod
    def download(cls,
            url     = "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version:}/{domain:}-attack/{domain:}-attack.json",
            version = "8.2",
            domains = ['enterprise', 'ics', 'mobile', 'pre'],
        ):
        """Download ATT&CK framework from url.

            Parameters
            ----------
            url : string, default="https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}-attack/{domain}-attack.json"
                URL from which to download ATT&CK database.
                Note that URL should contain {version} and {domain} templates
                to set specific version and domains to load.

            version : string, default="8.2"
                Version of ATT&CK to load.

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
            url_source = url.format(
                version = version,
                domain  = domain,
            )

            # Download ATT&CK as json
            stix_json = requests.get(url_source).json()

            # Store data
            attack[domain] = MemoryStore(stix_data=stix_json["objects"])

        # Return ATTACK
        return cls(attack)
