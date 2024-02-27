import os, requests, yaml, sys

LIBRARIES_IO_API = "https://libraries.io/api"
LIBRARIES_IO_API_VERSION = "1.1"

class LibrariesQuerier:
    """
    A class to query libraries.io API
    """

    def __init__(self, config_path=".."):
        try:
            with open(os.path.expanduser(f"{config_path}/config.yml")) as f:
                yml = yaml.safe_load(f)
                self.__api_key = yml["api_keys"]["libraries"]
        except Exception as e:
            print(f"Error parsing API key: {e}", file=sys.stderr)
            self.__api_key = None

    def search_packages(self, search_term):
        """
        Search libraries.io API for a package
        """
        if self.__api_key is None:
            return Exception("API key is required")
        url = f"{LIBRARIES_IO_API}/search?q={search_term}&platform=pypi"
        response = requests.get(url)
        return response.json()

    def query_package(self, package_name, get_dependencies=False):
        """
        Query libraries.io API for a package
        """
        if self.__api_key is None:
            return Exception("API key is required")
        url = f"{LIBRARIES_IO_API}/pypi/{package_name}?api_key={self.__api_key}"
        response = requests.get(url)
        return response.json()

    def query_dependencies(self, package_name, version=None, package_manager="pypi"):
        """
        Query libraries.io API for a package's dependencies
        """
        if self.__api_key is None:
            return Exception("API key is required")
        if version is None:
            return Exception("Version is required")
        url = f"{LIBRARIES_IO_API}/{package_manager}/{package_name}/{version}/dependencies?api_key={self.__api_key}"
        response = requests.get(url)
        return response.json()
    