import sys
import requests
import depsec.utils.tools as tools

# This file will handle querying the libraries.io API

SNYK_API_URL = "https://api.snyk.io/"
SNYK_API_VERSION = "v1"


class SnykQuerier:
    """
    A class to query Snyk API
    """

    def __create_headers(self):
        """
        Create the headers for the request
        """
        if self.__api_key is None:
            self.__headers = None
            print("Warning: No API key provided for Snyk API", file=sys.stderr)
            return
        self.__headers = {"Authorization": f"Token {self.__api_key}"}

    def __init__(self, config: dict = None):
        """
        SnykQuerier constructor, config:

        snyk: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key (found in account settings)
            org: The organisation ID (found in account settings)
        """
        self.config(config)

    def config(self, config: dict):
        """
        Set the config

        snyk: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key
            org: The organisation ID
        """
        if "snyk" in config:
            config = config["snyk"]
        self.__api_key = config.get("key", None)
        self.__org_id = config.get("org", None)
        self.__create_headers()

    def query_package_issues(
        self,
        platform: str,
        name: str,
        version: str,
        namespace: str = None,
        qualifiers: dict = None,
        subpath: str = None,
    ):
        """
        Query Snyk API for a project

        platform: The platform of the package
        name: The name of the package
        version: The version of the package
        namespace (optional): The namespace of the package
        qualifiers (optional): The qualifiers of the package
        subpath (optional): The subpath of the package
        """
        if self.__api_key is None:
            return Exception("API key is required")
        purl = tools.create_purl(
            platform, namespace, name, version, qualifiers, subpath
        )
        url = f"{SNYK_API_URL}/{SNYK_API_VERSION}/orgs/{self.__org_id}/packages/{purl}/issues"
        response = requests.get(url, headers=self.__headers)
        return response.json()
