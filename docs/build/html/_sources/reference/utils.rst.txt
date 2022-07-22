.. _utils:

utils
=====
The ``py_attack.utils`` module provides functions to get ``ID`` and ``UUID`` values from ATT&CK concepts.

.. autofunction:: py_attack.utils.get_id

.. autofunction:: py_attack.utils.get_uuid

Example
-------

.. code:: python

    # Import ATT&CK
    from py_attack import ATTACK

    # Load from local repository 
    attack = ATTACK.load(
        path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
        domains = ['enterprise', 'ics', 'mobile', 'pre'],
    )

    # Get concept by identifier
    concept = attack.get(identifier='T1087')

   # Get ID from concept
   id = get_id(concept)
   # Get UUID from concept
   uuid = get_uuid(concept)