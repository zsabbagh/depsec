import os, yaml, json

# This file handles parsing of the config file

class Config:

    class APIKeys:
        """
        API keys that could be defined in the config file
        """
        def __init__(self, config_dict: dict) -> None:
            """
            Initialise the class
            """
            self.libraries = config_dict.get("libraries", None)
            self.github = config_dict.get("github", None)
            self.snyk = config_dict.get("snyk", None)
            self.nvd = config_dict.get("nvd", None)            

    def __init__(self, config_file: str | dict):
        """
        Returns the config file
        Accepts yml, yaml, and json files
        """
        self.__config = None
        if type(config_file) == dict:
            self.__config = config_file
        else:
            directory = os.path.dirname(config_file)
            if directory == "":
                directory = os.getcwd()
            for file_extension in ["yaml", "yml", "json"]:
                if os.path.isfile(f"{directory}/config.{file_extension}"):
                    with open(f"{directory}/config.{file_extension}", "r") as file:
                        if file_extension == "json":
                            self.__config = json.load(file)
                        else:
                            self.__config = yaml.safe_load(file)
                if self.__config is not None:
                    break
        self.api_keys = self.APIKeys(self.__config.get("api_keys", {}))
        for key in self.__config.keys():
            setattr(self.api_keys, key, self.__config[key])
        self.__database_path = self.__config.get("database", {}).get("path", None)
        self.__database_path = os.path.abspath(self.__database_path) if self.__database_path is not None else None
    
    def get_database_path(self) -> str | None:
        """
        Get the database path
        """
        return self.__database_path
        
