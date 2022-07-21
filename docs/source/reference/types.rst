.. _types:

types
=====
The `py_attack.types` module provides types used for type hinting.

.. autoproperty:: py_attack.types.DomainTypes

.. _format:

format
======

Additionally, we specify the formatting of MITRE ATT&CK concepts:

.. csv-table:: MITRE ATT&CK concept formats
    :header: "Concept", "Format"

    "Tactics", ``TAxxxx``
    "Techniques", ``Txxxx``
    "Sub-techniques", ``Txxxx.xxx``
    "Mitigation", ``Mxxxx``
    "Group", ``Gxxxx``
    "Software", ``Sxxxx``
    "UUID", ``<STIX-TYPE>--<UUID>``