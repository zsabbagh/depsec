import os, requests, yaml, sys, re
from src.tools.config import Config
from src.database.schema import *

# This file will handle querying the libraries.io API

LIBRARIES_IO_API = "https://libraries.io/api"
LIBRARIES_IO_API_VERSION = "1.1"

class LibrariesQuerier:
    """
    A class to query libraries.io API
    """

    def __init__(self, api_key: str =None):
        """
        Initialise the class
        api_key_or_config: The API key or path or dict of the config file
        """
        self.__api_key = api_key
        if api_key is None:
            print(f"Warning: Libraries.io API key is None, trying to get from config file", file=sys.stderr)
    
    def set_api_key(self, api_key: str):
        """
        Set the API key
        api_key: The API key
        """
        self.__api_key = api_key
    
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
    