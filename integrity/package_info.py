
class PackageInfo:

    def __init__(
        self,
        name,
        version,
        ecosystem,
        file_path,
        expected_hash,
        expected_version,
        actual_version,
        source,
        signed_data=None,
        signature=None,
        public_key_bytes=None
    ):

        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.file_path = file_path

        self.expected_hash = expected_hash
        self.expected_version = expected_version
        self.actual_version = actual_version
        self.source = source

        # Digital signature verification fields
        self.signed_data = signed_data
        self.signature = signature
        self.public_key_bytes = public_key_bytes
