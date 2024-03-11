# Master Thesis Implementation part

This is a collection of tools and scripts used to collect data and perform analysis for my master thesis.

## Running the code

To run the code, you need to have the following installed:
```
argparse
loguru
peewee
requests
seaborn
matplotlib
numpy
pandas
```

Then you need to add the `src` folder to your `PYTHONPATH`:
```
export PYTHONPATH=$PYTHONPATH:/path/to/securipy/src
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
```

### Data collection

There are two main scripts for populating the database.
They are located in `src/scripts` and are called `cwemigrate.py` and `nvdmigrate.py`.
Each of them handle the migration of data from the respective sources to the database, that use downloaded data from the NVD and the CWE.