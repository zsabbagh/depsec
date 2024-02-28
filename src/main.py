import argparse
from queriers.libraries import LibrariesQuerier
from tools.parse import Config

config = Config("config.yml")

lib = LibrariesQuerier()

def print_response_keys(response, indent=0):
    """
    Get the keys from a response
    """
    if type(response) != dict:
        print(f"{' ' * indent}{type(response).__name__}")
        return
    for key in response.keys():
        print(f"{' ' * indent}{key}", end="")
        if isinstance(response[key], dict):
            print()
            print_response_keys(response[key], indent + 2)
        elif type(response[key]) == list:
            print(' [')
            if len(response[key]) > 0:
                print_response_keys(response[key][0], indent + 2)
            print(' ' * indent + ']', end="")
        else:
            print(f": {type(response[key]).__name__}", end="")
        print()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Query libraries.io API")
    parser.add_argument("config", help="The query")
    pass