.. _ATTACK:

ATTACK
======
The ATTACK object provides a simple interface for loading and interacting with the ATT&CK framework.

.. autoclass:: attack.ATTACK

Initialization
^^^^^^^^^^^^^^
We provide two methods of loading the ATTACK object, either from a local repository through :py:meth:`load`, or by downloading the ATTACK object from a remote repository using :py:meth:`download`.
The recommended way of initializing an ATTACK object is through :py:meth:`load` as this assures that your project works with a consistent version of the MITRE ATT&CK framework and avoids repeated downloading of the CTI sources.

.. automethod:: attack.ATTACK.load

.. automethod:: attack.ATTACK.download

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACK

    # Load from local repository - recommended
    attack = ATTACK.load(
        path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

    # Download from online source
    attack = ATTACK.download(
        url     = "https://raw.githubusercontent.com/mitre/cti/master/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

Domains
^^^^^^^
You can get, set and delete MITRE :ref:`ATTACKDomain` s according to its DomainTypes (see :ref:`types`).

.. automethod:: attack.ATTACK.__getitem__

.. automethod:: attack.ATTACK.__setitem__

.. automethod:: attack.ATTACK.__delitem__

.. automethod:: attack.ATTACK.__iter__

.. automethod:: attack.ATTACK.__len__

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACK, ATTACKDomain

    # Load from local repository - recommended
    attack = ATTACK.load(
        path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

    # Get enterprise domain
    enterprise = attack['enterprise']
    # Delete enterprise domain
    del attack['enterprise']
    # Set enterprise domain
    attack['enterprise'] = ATTACKDomain.load(
        path   = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domain = 'enterprise',
    )

    # Iterate over all domains
    for domain in attack:
        ...

    # Show number of domains
    print(len(attack))


Iterators
^^^^^^^^^
Similar to :ref:`ATTACKDomain`, ``ATTACK`` provides iterators to iterate over all ``concepts`` for each :ref:`ATTACKDomain` of the ``ATTACK`` object.
The ``ATTACK`` object supports iterators for the following ``concepts``: ``matrices``, ``tactics``, ``techniques``, ``sub_techniques``, ``groups``, ``software``, ``procedures``, ``relationships`` and ``mitigations``,.
All of these are easily accessible via the following iterator properties:

.. autoproperty:: attack.ATTACK.concepts

.. autoproperty:: attack.ATTACK.graph_concepts

.. autoproperty:: attack.ATTACK.matrices

.. autoproperty:: attack.ATTACK.tactics

.. autoproperty:: attack.ATTACK.techniques

.. autoproperty:: attack.ATTACK.sub_techniques

.. autoproperty:: attack.ATTACK.groups

.. autoproperty:: attack.ATTACK.software

.. autoproperty:: attack.ATTACK.procedures

.. autoproperty:: attack.ATTACK.relationships

.. autoproperty:: attack.ATTACK.mitigations

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACK

    # Load from local repository - recommended
    attack = ATTACK.load(
        path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

    # Iterate over different concepts
    for concept in attack.concepts:
        ...
    for matrices in attack.matrices:
        ...
    for tactics in attack.tactics:
        ...
    for techniques in attack.techniques:
        ...
    for sub_techniques in attack.sub_techniques:
        ...
    for groups in attack.groups:
        ...
    for software in attack.software:
        ...
    for procedures in attack.procedures:
        ...
    for relationships in attack.relationships:
        ...
    for mitigations in attack.mitigations:
        ...

Graph
^^^^^
All concepts within the ``ATTACK`` have defined relations between them.
E.g., each ``domain`` specifies ``groups`` that use ``techniques`` to achieve ``tactics`` using specific ``software``.
These concepts and relations can therefore be modeled in a graph provided by the ``graph`` property.

.. autoproperty:: attack.ATTACK.graph

Because all these concepts are related, we provide a method to find concepts that are (in)directly related to a given concept:

.. automethod:: attack.ATTACK.related_concepts

.. automethod:: attack.ATTACK.get_relation

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACK

    # Load from local repository - recommended
    attack = ATTACK.load(
        path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

    # Get domain graph
    graph = attack.graph

    # Get concepts related to given ID T1087
    related = attack.related_concepts('T1087')