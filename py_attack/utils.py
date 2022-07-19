def get_uuid(concept: dict) -> str:
    """Get the UUID of an ATT&CK concept.

        Format
        ------
        <STIX-TYPE>--<UUID>

        Parameters
        ----------
        concept : dict()
            ATT&CK concept from which to retrieve UUID.

        Returns
        -------
        UUID : string
            ATT&CK UUID of concept.
        """
    return concept.get('id')


def get_id(concept: dict) -> str:
    """Get the human readable ID of an ATT&CK concept.

        Format
        ------
        Matrix       : MAxxxx
        Tactic       : TAxxxx
        Technique    : Txxxx(.yyy)
        Sub-Technique: Txxxx.yyy
        Mitigation   : Mxxxx
        Group        : Gxxxx
        Software     : Sxxxx

        Parameters
        ----------
        concept : dict()
            ATT&CK concept from which to retrieve ID.

        Returns
        -------
        ID : string
            ATT&CK ID of concept.
        """
    return concept.get('external_references', [{}])[0].get('external_id')
