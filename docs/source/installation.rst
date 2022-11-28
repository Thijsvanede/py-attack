Installation
============
The most straightforward way of installing `py-attack` is via pip.

.. code::

  pip3 install py-attack

.. _`From source`:

From source
^^^^^^^^^^^
If you wish to stay up to date with the latest development version, you can instead download the `source code`_.
In this case, make sure that you have all the required `dependencies`_ installed.
You can clone the code from GitHub:

.. code::

   git clone git@github.com:Thijsvanede/py-attack.git

Next, you can install the latest version using pip:

.. code::

  pip install -e <path/to/py-attack/directory/containing/setup.py>

.. _source code: https://github.com/Thijsvanede/py-attack

Dependencies
------------
`py-attack` requires the following python packages to be installed:

- argformat: https://pypi.org/project/argformat/
- matplotlib: https://pypi.org/project/matplotlib/
- networkx: https://pypi.org/project/networkx/
- requests: https://pypi.org/project/requests/

All dependencies should be automatically downloaded if you install `py-attack` via pip. However, should you want to install these libraries manually, you can install the dependencies using the requirements.txt file

.. code::

  pip install -r requirements.txt

Or you can install these libraries yourself

.. code::

  pip install -U argformat matplotlib networkx requests
