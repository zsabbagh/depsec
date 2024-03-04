import requests, sys

# This file will handle querying the libraries.io API

LIBRARIES_IO_API = "https://libraries.io/api"
LIBRARIES_IO_API_VERSION = "1.1"

class LibrariesQuerier:
    """
    A class to query libraries.io API
    """

    def __init__(self, config: dict =None):
        """
        Initialise the class, config:

        libraries: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key
        """
        self.config(config)
    
    def config(self, config: dict):
        """
        Set the config

        libraries: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key
        """
        if 'libraries' in config:
            config = config['libraries']
        self.__api_key = config.get('key', None)
    
    def search_packages(self, search_term: str):
        """
        Search libraries.io API for a package
        search_term: The search term
        """
        if self.__api_key is None:
            return Exception("API key is required")
        url = f"{LIBRARIES_IO_API}/search?q={search_term}&platform=pypi"
        response = requests.get(url)
        return response.json()

    def query_package(self, package_name: str, get_dependencies: bool=False):
        """
        Query libraries.io API for a package
        package_name: The name of the package
        get_dependencies: Whether to get the package's dependencies
        """
        if self.__api_key is None:
            return Exception("API key is required")
        url = f"{LIBRARIES_IO_API}/pypi/{package_name}?api_key={self.__api_key}"
        response = requests.get(url)
        if response.status_code != 200:
            print(f"Error querying libraries.io for {package_name}: {response.status_code}: {response.text}", file=sys.stderr)
            return None
        return response.json()

    def query_dependencies(self, package_name: str, version:str=None, package_manager: str="pypi"):
        """
        Query libraries.io API for a package's dependencies
        package_name: The name of the package
        version: The version of the package
        package_manager: The package manager
        """
        if self.__api_key is None:
            return Exception("API key is required")
        if version is None:
            return Exception("Version is required")
        url = f"{LIBRARIES_IO_API}/{package_manager}/{package_name}/{version}/dependencies?api_key={self.__api_key}"
        response = requests.get(url)
        return response.json()
    