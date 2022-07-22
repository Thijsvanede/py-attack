.. _filter:

filter
======
The ``py_attack.filter`` module provides a :py:class:`Filter` object for filtering the CTI repository and a :py:meth:`query` method for applying those filters.

.. autoclass:: py_attack.filter.Filter

.. automethod:: py_attack.filter.Filter.__init__

.. automethod:: py_attack.filter.Filter.match

.. automethod:: py_attack.filter.Filter.compare

Query
^^^^^
You can query a CTI repository (``Iterable[dict]`` with a ``List[Filters]``) using the following method:

.. autofunction:: py_attack.filter.query

Example
^^^^^^^

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACK
    from py_attack.filter import Filter, query

    # Load from local repository 
    attack = ATTACK.load(
        path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

    # Query for all MITRE ATT&CK techniques in store of enterprise objects
    techniques = query(
        iterable = attack['enterprise'].store, # Underlying CTI datastructure of 'enterprise' domain
        filters  = [
            Filter('type', '=', 'attack-pattern'), # Filter all CTI entries where type == attack-pattern, i.e., MITRE ATT&CK techniques
        ]
    )