import json
import networkx as nx
import pickle
import re
import requests

from stix2           import Filter, MemoryStore
from py_attack.utils import get_id, get_uuid

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

    @property
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
            for concept in self.concepts
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
            for concept in self.concepts
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
