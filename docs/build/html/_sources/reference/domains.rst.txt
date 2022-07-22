.. _ATTACKDomain:

ATTACKDomain
============
The ``ATTACKDomain`` object provides a simple interface for loading and interacting with a single domain within the ATT&CK framework.

.. autoclass:: attack.ATTACKDomain

Initialization
^^^^^^^^^^^^^^
We provide two methods of loading the ``ATTACKDomain`` object, either from a local repository through :py:meth:`load`, or by downloading the ``ATTACKDomain`` object from a remote repository using :py:meth:`download`.
The recommended way of initializing an ``ATTACKDomain`` object is through :py:meth:`load` as this assures that your project works with a consistent version of the MITRE ATT&CK framework and avoids repeated downloading of the CTI sources.

.. automethod:: attack.ATTACKDomain.load

.. automethod:: attack.ATTACKDomain.download

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACKDomain

    # Load from local repository - recommended
    domain = ATTACKDomain.load(
        path   = "path/to/local/cti/enterprise-attack/enterprise-attack.json",
        domain = 'enterprise',
    )

    # Download from online source
    domain = ATTACKDomain.download(
        url    = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        domain = 'enterprise',
    )

.. _DomainGetter:

Getters
^^^^^^^
You can retrieve a specific MITRE ATT&CK concept according to its identifier (see :ref:`format`) or ``UUID``.

.. automethod:: attack.ATTACKDomain.__getitem__

.. automethod:: attack.ATTACKDomain.get

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACKDomain

    # Load from local repository - recommended
    domain = ATTACKDomain.load(
        path   = "path/to/local/cti/enterprise-attack/enterprise-attack.json",
        domain = 'enterprise',
    )

    # Get technique using ID T1087
    technique = domain['T1087']     
    technique = domain.get('T1087')

Iterators
^^^^^^^^^
Rather than retrieving a concept via one of the `DomainGetter`_ methods, you can also iterate over various ``concepts``.
A domain within the MITRE ATT&CK framework consists of the following ``concepts``: ``matrices``, ``tactics``, ``techniques``, ``sub_techniques``, ``groups``, ``software``, ``procedures``, ``relationships`` and ``mitigations``,.
All of these are easily accessible via the following iterator properties:

.. autoproperty:: attack.ATTACKDomain.concepts

.. autoproperty:: attack.ATTACKDomain.matrices

.. autoproperty:: attack.ATTACKDomain.tactics

.. autoproperty:: attack.ATTACKDomain.techniques

.. autoproperty:: attack.ATTACKDomain.sub_techniques

.. autoproperty:: attack.ATTACKDomain.groups

.. autoproperty:: attack.ATTACKDomain.software

.. autoproperty:: attack.ATTACKDomain.procedures

.. autoproperty:: attack.ATTACKDomain.relationships

.. autoproperty:: attack.ATTACKDomain.mitigations

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACKDomain

    # Load from local repository - recommended
    domain = ATTACKDomain.load(
        path   = "path/to/local/cti/enterprise-attack/enterprise-attack.json",
        domain = 'enterprise',
    )

    # Iterate over different concepts
    for concept in domain.concepts:
        ...
    for matrices in domain.matrices:
        ...
    for tactics in domain.tactics:
        ...
    for techniques in domain.techniques:
        ...
    for sub_techniques in domain.sub_techniques:
        ...
    for groups in domain.groups:
        ...
    for software in domain.software:
        ...
    for procedures in domain.procedures:
        ...
    for relationships in domain.relationships:
        ...
    for mitigations in domain.mitigations:
        ...

Graph
^^^^^
All concepts within the ``ATTACKDomain`` have defined relations between them.
E.g., ``groups`` use ``techniques`` to achieve ``tactics`` using specific ``software``.
These concepts and relations can therefore be modeled in a graph provided by the ``graph`` property.

.. autoproperty:: attack.ATTACKDomain.graph

Because all these concepts are related, we provide a method to find concepts that are (in)directly related to a given concept:

.. automethod:: attack.ATTACKDomain.related_concepts

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACKDomain

    # Load from local repository - recommended
    domain = ATTACKDomain.load(
        path   = "path/to/local/cti/enterprise-attack/enterprise-attack.json",
        domain = 'enterprise',
    )

    # Get domain graph
    graph = domain.graph

    # Get concepts related to given ID T1087
    related = domain.related_concepts('T1087')