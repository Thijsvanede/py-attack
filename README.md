# py-attack
Python wrapper for using the ATT&amp;CK framework.

## Introduction
This python wrapper provides a simple interface for querying the ATT&CK framework.
Among other things, we provide the following functionality:
 * Search by ID
 * Search by UUID
 * Iterate over matrices (both overall and per domain)
 * Iterate over tactics (both overall and per domain)
 * Iterate over techniques (both overall and per domain)
 * Iterate over sub_techniques (both overall and per domain)
 * Iterate over mitigations (both overall and per domain)
 * Iterate over groups (both overall and per domain)
 * Iterate over software (both overall and per domain)
 * Representation of the ATT&CK framework as a graph, where all items are linked
 * Finding related ATT&CK concepts

## Documentation
In the future we will provide a full documentation plus reference guide on readthedocs.io.
Until then, we provide some basic documentation here.

### Installation
The `py-attack` module can be installed using pip if downloaded locally.
There currently is no way of installing it directly from the pip repository.

```
pip3 installl -e <path/to/dir/containing/setup.py>
```

### Usage
To use py_attack, we need to import it:
```python
from py_attack       import ATTACK           # The main object that implements the ATT&CK framework
from py_attack       import ATTACKDomain     # Optional, only if working with a single domain
from py_attack.utils import get_id, get_uuid # Optional, add utilities
```

Next we can load the ATT&CK framework from various sources.
Please note that the `url` or `path` should contain the template `{domain}`, which will be replaced by the different domains specified by the `domains` parameter.
```python
# Download from online source
attack = ATTACK.download(
    url     = "https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v8.2/{domain}-attack/{domain}-attack.json",
    domains = ['enterprise', 'ics', 'mobile', 'pre'],
)

# Load from local path
attack = ATTACK.load(
    path    = "path/to/local/cti/{domain}-attack/{domain}-attack.json",
    domains = ['enterprise', 'ics', 'mobile', 'pre'],
)
```

Now that we have loaded the ATT&CK framework in the `attack` variable, we can use it for various tasks.
Below we give various examples of tasks for which we provide an easy interface.
Please note that most concepts will be returned as `dict()`, some concepts are returned as special objects, however, they can also be addressed as a Python `dict()`.

#### Searching
```python
# Search by ID
concept = attack.get(identifier='T1087')

# Search by UUID
concept = attack.get(identifier='attack-pattern--72b74d71-8169-42aa-92e0-e7b04b9f5a08')

# Get ID from concept
id = get_id(concept)

# Get UUID from concept
uuid = get_uuid(concept)
```

#### Iterating
```python
# We support the following concepts:
# attack.concepts
# attack.matrices
# attack.tactics
# attack.techniques
# attack.sub_techniques
# attack.mitigations
# attack.groups
# attack.software
for concept in attack.concepts:
    # Do stuff with your attack concept
    pass

# Iterate over concepts for specific domain:
for concept in attack.domains['enterprise'].concepts:
    # Do stuff with your attack concept
    pass
```

#### Graphs
```python
# Import networkx and plot libraries
import matplotlib.pyplot as plt
import networkx          as nx

# Get graph for entire framework
graph = attack.graph
# Get graph for specific domain
graph = attack.domains['enterprise'].graph

# Write graph to outfile
nx.write_gexf(graph, 'graph.gexf')

# Plot graph
attack.plot()
plt.show()
plt.savefig('path/to/plot.png', dpi=300)
```

#### Finding related concepts
```python
# Get related concepts by ID, note UUID is NOT supported
related_concepts = attack.related_concepts('T1087', depth=1)

print("\nRelated concepts:")
for related_concept_id in related_concepts:
    print(related_concept_id)
```

## Visualisation - In progress
We provide a Django app for visualisation.
Note that this is meant to run locally and not for production purposes!

## References
[1] TODO

### Bibtex
```
@inproceedings{TODO

}
```
