TRUSTED_SOURCES = {
    "pypi.org",
    "github.com",
    "registry.npmjs.org"
}


def verify_source(source):

    if source in TRUSTED_SOURCES:

        return {
            "source": source,
            "status": "TRUSTED"
        }

    return {
        "source": source,
        "status": "UNKNOWN"
    }