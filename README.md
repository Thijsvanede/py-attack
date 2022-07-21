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
We provide an extensive documentation including installation instructions and reference at [py-attack.readthedocs.io](https://py-attack.readthedocs.io/).

However, that documentation is currently not yet online, so instead, please refer to the `/docs/` directory.
To build the documentation, simply run `make html` from within the `/docs/` directory.

## Installation
The `py-attack` module can be installed using pip if downloaded locally.
There currently is no way of installing it directly from the pip repository.

```
pip3 installl -e <path/to/dir/containing/setup.py>
```

## References
[1] TODO

### Bibtex
```
@inproceedings{TODO

}
```
