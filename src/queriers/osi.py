import requests
from loguru import logger

OSI_API = "https://api.deps.dev/v3"

class OSIQuerier:
    """
    A class to query OSI API
    """

    def __init__(self, *args, **kwargs):
        pass

    def __query_failed(self, response):
        """
        Check if the response suggests that the query failed
        """
        return response.status_code != 200 or response.text == "Not Found"

    def query_package(self, package: str, platform: str = "pypi"):
        """
        Query OSI for a package
        """
        package = package.strip().lower()
        platform = platform.strip().lower()
        url = f"{OSI_API}/systems/{platform}/packages/{package}"
        response = requests.get(url)
        if self.__query_failed(response):
            logger.error(f"Error querying OSI for '{platform}' package '{package}': {response.status_code}: {response.text}")
            return None
        return response.json()
    
    def query_dependencies(self, package: str, version: str = None, platform: str = "pypi"):
        """
        Query OSI for a package's dependencies for a specific version
        If version is None, then the 'isDefault' version is used
        """
        package = package.strip().lower()
        platform = platform.strip().lower()
        if version is None:
            package_info = self.query_package(package, platform)
            if package_info is None:
                return None
            versions = package_info.get('versions', [])
            if not versions:
                logger.error(f"No versions found for '{platform}' package '{package}'")
                return None
            # Start on the latest version and work backwards for improved performance
            for i in range(-1, -len(versions), -1):
                version = versions[i]
                if version.get('isDefault', False):
                    version = version.get('versionKey', {}).get('version', None)
                    if version is None:
                        logger.error(f"No version found for '{platform}' package '{package}' when searching for default version")
                        return None
                    break
        url = f"{OSI_API}/systems/{platform}/packages/{package}/versions/{version}:dependencies"
        response = requests.get(url)
        if self.__query_failed(response):
            logger.error(f"Error querying OSI for '{platform}' package '{package}' dependencies: {response.status_code}: {response.text}")
            return None
        return response.json()
