def query(iterable, filters):
    """Perform a filter query on the given iterable.
        Will return all values in iterable matching the given filters

        Parameters
        ----------
        iterable : iterable
            Iterable of dictionary to match against filters.

        filters : list
            List of filters to apply, if empty, return all values in iterable.
        """
    # Initialise result
    result = list()

    # Loop over all iterables
    for object in iterable:
        if any(not filter.match(object) for filter in filters):
            continue
        else:
            result.append(object)

    # Return result
    return result

class Filter(object):

    def __init__(self, key, relation, value):
        """Filter object for filtering dictionaries based on given allowed
            relation.

            Parameters
            ----------
            key : object
                Object to use as key for dictionary item to compare.

            relation : string
                Allowed relation, see compare method for implemented relations.

            value : object
                Object that should match according to filter.
            """
        # Store values
        self.key      = key
        self.relation = relation
        self.value    = value

    def match(self, object):
        """Check if an object matches the filter.

            Parameters
            ----------
            object : dict()
                Dictionary object to match against filter.

            Returns
            -------
            result : boolean
                True if object is allowed by filter, False otherwise.
            """
        return self.key in object and self.compare(object[self.key], self.value)

    def compare(self, object, value):
        """Compare with value according to relation.

            Note
            ----
            Currently, only the following relations are implemented:
             - '=', equals
             - 'contains', check value is in object

            Parameters
            ----------
            object : object
                Object to compare against value.

            value : object
                Value for which to compare object.

            Returns
            -------
            result : boolean
                True if comparison is allowed by relation, False otherwise.
            """
        if self.relation == '=':
            return object == value
        elif self.relation == 'contains':
            return value in object
        else:
            raise NotImplementedError(
                "Relation '{}' not implemented".format(self.relation)
            )
