# DepSec: Dependency Security Analysis Tool

This is a collection of tools and scripts used to collect data and perform analysis for my master thesis.
A project run, tested, and developed with Python 3.11.6.

## Running the code

To run the code, you need to have the following installed:
```
argparse
gitpython
lizard
loguru
matplotlib
numpy
packaging
pandas
peewee
requests
seaborn
```

Then you need to add the `src` folder to your `PYTHONPATH`:
```
export PYTHONPATH=$PYTHONPATH:/path/to/securipy/src
```

## Project file structure

For each project wanting to be processed, one should define them in a `projects.json` file.
For examples, see `projects.json` in the root of the repository.
This is structured:

```
{
  <platform-name>: {
    <project-name>: {
      "vendor": <vendor-name>,      -- optional for defining CPE vendor
      "product": <product-name>,    -- optional for defining CPE product
      "repo": {
        "url": <url>,               -- URL to the repository, format github.com/<user>/<repo>
        "includes": <list> | <str>, -- optional, list of directories to include in the analysis
        "excludes": <list> | <str>  -- optional, list of directories to exclude in the analysis
      }
    }
  }
}

```

## Config format

```
apis:
  libraries:
    key: <key>
databases:
  projects:
    name: projects
    path: <path>
  vulnerabilities:
    name: vulnerabilities
    path: <path>
  weaknesses:
    name  weaknesses:
    path: <path>
repositories:
  path: <path>
```

The `repositories` path should be the path to the folder where the repositories are cloned.
The `databases` paths should be the path to the SQLite3 databases are stored.
API keys are necessary for some services.

### Scripts

There are four main scripts for collecting data, whereof three are for migrating data.
Use `--help` to see the available options for each script.
They are located in `scripts/`.

- `cwemigrate.py` migrates data from a downloaded CWE XML file to a SQLite database defined in `weaknesses` in the config file.
  This is a preparation step.
- `nvdmigrate.py` migrates data from a downloaded NVD JSON file to a SQLite database defined in `vulnerabilities` in the config file.
  This is a preparation step.
- `plotter.py` is the plotting script for the thesis.
