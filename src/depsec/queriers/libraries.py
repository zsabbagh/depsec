import requests, sys, time
from loguru import logger

# This file will handle querying the libraries.io API

LIBRARIES_IO_API = "https://libraries.io/api"
LIBRARIES_IO_API_VERSION = "1.1"


class LibrariesQuerier:
    """
    A class to query libraries.io API
    """

    def __wait_if_necessary(self):
        """
        Wait for a short time to avoid rate limiting
        """
        split = 0
        for i in range(len(self.__queries_done)):
            if time.time() - self.__queries_done[i] > 60:
                split = i
                break
        self.__queries_done = self.__queries_done[split:]
        self.__queries_done.append(time.time())
        if len(self.__queries_done) < self.__limit:
            return
        latest = self.__queries_done[0] if self.__queries_done else 0
        wait_time = 60 - (time.time() - latest)
        for i in range(wait_time // 1.0, 0, -1):
            print(f"Libraries.io waiting for {i} seconds...", end="\r")
            time.sleep(1)

    def __init__(self, config: dict = None, limit: int = 60):
        """
        Initialise the class, config:

        libraries: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key
        """
        logger.info("Initialising LibrariesQuerier")
        self.config(config)
        self.__limit = limit
        self.__queries_done = []

    def config(self, config: dict):
        """
        Set the config

        libraries: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key
        """
        if "libraries" in config:
            config = config["libraries"]
        self.__api_key = config.get("key", None)

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

    def query_package(
        self, package_name: str, platform: str = "pypi", get_dependencies: bool = False
    ):
        """
        Query libraries.io API for a package
        package_name: The name of the package
        get_dependencies: Whether to get the package's dependencies
        """
        platform = platform.lower()
        if self.__api_key is None:
            logger.error("API key is required")
            return Exception("API key is required")
        url = f"{LIBRARIES_IO_API}/{platform}/{package_name}?api_key={self.__api_key}"
        logger.debug(f"Querying libraries.io for {package_name}")
        response = requests.get(url)
        if response.status_code != 200:
            logger.error(
                f"Error querying libraries.io for {package_name}: {response.status_code}: {response.text}"
            )
            return None
        logger.debug(f"Queried libraries.io for {package_name}")
        return response.json()

    def query_dependencies(
        self, package_name: str, version: str = None, package_manager: str = "pypi"
    ):
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
