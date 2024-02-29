import sys, requests
from purl import URL

# This file will handle querying the libraries.io API

SNYK_API_URL = "https://snyk.io/api/v1"

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
            print(f"Warning: No API key provided for Snyk API", file=sys.stderr)
            return
        self.__headers = {
            "Authorization": f"Token {self.__api_key}"
        }

    def __init__(self, config: dict = None):
        """
        SnykQuerier constructor, config:

        snyk: (first search in dict, if not found, then assume it's a dict with the following keys)
            key: The API key
            org: The organisation ID
        """
        self.config(config)
    
    def config(self, config: dict):
        """
        Set the API key
        """
        if 'snyk' in config:
            config = config['snyk']
        self.__api_key = config.get('key', None)
        self.__org_id = config.get('org', None)
        self.__create_headers()
    
    
