import time, yaml, json, glob, sys, pandas as pd, datetime as dt, itertools
import depsec.schemas.nvd as nvd
import depsec.schemas.cwe as cwe
import depsec.utils.db as db
import depsec.utils.giterate as giterate
import argparse
import numpy as np
from copy import deepcopy
from packaging import version as semver
from playhouse.shortcuts import model_to_dict
from pprint import pprint
from depsec.queriers.libraries import LibrariesQuerier
from depsec.queriers.snyk import SnykQuerier
from depsec.queriers.osi import OSIQuerier
from depsec.schemas.projects import *
from depsec.utils.tools import *
from loguru import logger
from pathlib import Path
from typing import List, Dict


def pm(model: List[Model] | Model, recurse=False):
    """
    Pretty print a model
    """

    def fn(m):
        if isinstance(m, Model):
            return model_to_dict(m, recurse=recurse)
        return m

    if isinstance(model, list):
        model = list(map(fn, model))
    else:
        model = fn(model)
    pprint(model)


def project_to_config(project: Project):
    """
    Convert a project to a config
    """
    if not project:
        return None

    includes = project.includes
    if includes:
        includes = includes.split(",")
    excludes = project.excludes
    if excludes:
        excludes = excludes.split(",")
    return {
        "product": project.product,
        "vendor": project.vendor,
        "repo": {
            "url": project.repository_url,
            "includes": includes,
            "excludes": excludes,
            "tags": project.tag_regex,
        },
    }


def pprows(df: pd.DataFrame, *cols: str, n: int = 10):
    print(f"{' '.join(cols)}")
    print("-" * 80)
    for i, row in df.iterrows():
        for col in cols:
            print(row[col], end=" ")
        print()
        if i > n:
            break


class Aggregator:
    """
    The Aggregator to communicate with the databases and the APIs
    """

    def __format_strings(self, *strings: str):
        """
        Format arbitrary amount of strings
        """

        def _fmt(string: str):
            if not string:
                return ""
            return string.strip().lower()

        strings = tuple(map(_fmt, strings))

        return strings

    def config(self, config_path: str):
        """
        Set the config file
        """
        self.__config = None
        extension = config_path.split(".")[-1]
        # lambda for loading the file
        loader = lambda f: json.load(f) if extension == "json" else yaml.safe_load(f)
        if os.path.exists(config_path):
            with open(config_path) as f:
                self.__config = loader(f)
        if self.__config is None:
            dir = os.path.dirname(os.path.abspath(__file__))
            for file_ext in ["json", "yml", "yaml"]:
                for file in glob.glob(f"{dir}/*.{file_ext}"):
                    with open(file) as f:
                        self.__config = loader(f)
                    if self.__config is not None:
                        break
                if self.__config is not None:
                    break
        if self.__config is None:
            raise Exception(f"Config file not found at {config_path}")
        apis = self.__config.get("apis", {})
        self.libraries = LibrariesQuerier(apis)
        self.snyk = SnykQuerier(apis)
        self.osi = OSIQuerier(apis)

        databases = self.__config.get("databases", {})
        if not databases:
            logger.warning("No databases found in config file")
            raise Exception("No databases found in config file")

        # Configure the databases
        projects_path, projects_name = get_database_dir_and_name(databases, "projects")
        self.__repos_dir = self.__config.get("repositories", {}).get("path")
        vulns_path, vulns_name = get_database_dir_and_name(databases, "vulnerabilities")
        weaks_path, weaks_name = get_database_dir_and_name(databases, "weaknesses")
        DB_PROJECTS.set(projects_path, projects_name)
        nvd.CONFIG.set(vulns_path, vulns_name)
        cwe.CONFIG.set(weaks_path, weaks_name)

    def set_debug(self, debug: bool = None):
        """
        Set debug
        """
        if debug is not None:
            self.__debug = debug
        else:
            self.__debug = not self.__debug

    def __init__(
        self, config_path: str, debug: bool = False, debug_delay: int = None
    ) -> None:
        """
        Initialise the Aggregator
        """
        self.__analysed_projects = {}
        self.__debug = debug
        self.__debug_delay = debug_delay
        logger.debug(f"Initalising Aggregator with config file {config_path}")
        self.config(config_path)

    def save_projects(self, file: str = "projects.json"):
        """
        Save the projects to a file
        """
        if not file.endswith(".json"):
            file = f"{file}.json"
        logger.info(f"Saving projects to '{file}'")
        path = Path(file)
        with open(path, "w") as f:
            json.dump(self.__analysed_projects, f, indent=4)
        logger.info(f"Saved {len(self.__analysed_projects)} projects")

    def load_projects(self, *projects: str, file: str = "projects.json") -> Project:
        """
        Update the projects
        """
        if not file.endswith(".json"):
            file = f"{file}.json"
        logger.info(f"Loading projects from '{file}'")
        path = Path(file)
        result = []
        if len(projects) > 0 and not Path(projects[0]).exists():
            for project in projects:
                logger.debug(f"Loading project {project}")
                project = self.get_project(project)
                result.append(project)
            return result
        with open(path) as f:
            data = json.load(f)
            self.__analysed_projects = deepcopy(data)
            for platform in data:
                logger.debug(f"Loading platform {platform}")
                projects = data[platform]
                for proj in projects:
                    logger.debug("Loading project {proj}")
                    info = projects[proj]
                    project = self.get_project(proj, platform)
                    vendor = info.get("vendor")
                    product = info.get("product")
                    if vendor is not None:
                        project.vendor = vendor
                    if product is not None:
                        project.product = product
                    project.save()
                    repo = info.get("repo")
                    if repo:
                        repo_url = repo.get("url")
                        includes = repo.get("includes")
                        excludes = repo.get("excludes")
                        tag_regex = repo.get("tags")
                        if repo_url:
                            project.repository_url = repo_url
                        project.includes = (
                            ",".join(includes) if type(includes) == list else includes
                        )
                        project.excludes = (
                            ",".join(excludes) if type(excludes) == list else excludes
                        )
                        project.tag_regex = tag_regex
                        project.save()
                    result.append(project)
        logger.info(f"Loaded {len(result)} projects")
        return result

    def get_project(self, project_name: str, platform: str = "pypi") -> Project:
        """
        When you get a project, it does the following:

        1) If the project is in the database, it returns it
        2) Query API for the project
        3) Create the project and its releases in the database
        """
        if isinstance(project_name, Project):
            return project_name
        # Force lowercase
        project_name = project_name.strip().lower()
        platform = platform.strip().lower()
        logger.debug(f"Getting {project_name} from database with platform {platform}")
        # Query the database
        project = Project.get_or_none(
            Project.name == project_name, Project.platform == platform
        )
        if project is not None and project.releases.count() > 0:
            # If the package is in the database, return it
            logger.debug(f"Found {project_name} in database")
            if not project.osi_verified:
                self._verify_dates(project)
            if platform not in self.__analysed_projects:
                self.__analysed_projects[platform] = {}
            self.__analysed_projects[platform][project_name] = project_to_config(
                project
            )
            return project
        elif project is not None:
            logger.debug(f"Project {project_name} in database but no releases found")
            project.delete_instance()
        logger.debug(f"Querying libraries.io for {project_name}")

        # Query libraries.io if the package is not in the database
        logger.debug(f"Querying libraries.io for {project_name}")
        time.sleep(1)
        result: dict = self.libraries.query_package(project_name, platform=platform)
        if result is None:
            logger.error(f"Project {project_name} not found in libraries.io")
            return None

        name = result.get("name", "")
        platform = result.get("platform", "")
        language = result.get("language", "")
        name, platform, language = self.__format_strings(name, platform, language)
        package_manager_url = result.get("package_manager_url")
        repository_url = result.get("repository_url")
        stars, forks = result.get("stars"), result.get("forks")
        contributions = result.get("contributions_count")
        dependent_repos = result.get("dependent_repos_count")
        dependent_projects = result.get("dependent_projects_count")
        homepage = result.get("homepage")
        vendor_name = homepage_to_vendor(homepage)
        logger.debug(f"Creating project {name}")
        project = Project.create(
            contributions=contributions,
            dependent_projects=dependent_projects,
            dependent_repos=dependent_repos,
            homepage=homepage,
            vendor=vendor_name,
            forks=forks,
            language=language,
            name=name,
            package_manager_url=package_manager_url,
            platform=platform,
            repository_url=repository_url,
            stars=stars,
        )
        if project:
            project.save()
            logger.debug(f"Created project {name} in database")
            # Create releases
            for release in result.get("versions", []):
                number = release.get("number", "")
                logger.debug(f"Creating release {number}")
                if number == "":
                    continue
                published_at = release.get("published_at", None)
                try:
                    # transform the date to a datetime object
                    published_at = dt.datetime.strptime(
                        published_at, "%Y-%m-%dT%H:%M:%S.%fZ"
                    )
                except:
                    published_at = None
                release = Release.create(
                    project=project,
                    version=number,
                    published_at=published_at,
                )
                release.save()
            # get the latest release
            latest_release = (
                Release.select()
                .where(Release.project == project)
                .order_by(Release.published_at.desc())
                .first()
            )
            project.latest_release = latest_release.version
            project.save()
        self._verify_dates(project)
        if platform not in self.__analysed_projects:
            self.__analysed_projects[platform] = {}
        self.__analysed_projects[platform][name] = project_to_config(project)
        return project

    def get_releases(
        self,
        project: str | Project,
        platform: str = "pypi",
        descending: bool = True,
        exclude_deprecated: bool = False,
        exclude_nonstable: bool = True,
        sort_semantically: bool = True,
        before: str | int | dt.datetime = None,
        after: str | int | dt.datetime = None,
        analysed: bool = False,
        osi_verified: bool = True,
        requirements: str = None,
    ) -> List[Release]:
        """
        Gets all releases of a project
        Returns a sorted list of releases, based on the semantic versioning

        project: str | Project, the project name or the project object
        platform: str, default: pypi
        descending: bool, default: True
        exclude_deprecated: bool, default: True
        sort_semantically: bool, default: True, this will sort the releases based on the semantic versioning
        before: str | int | dt.datetime, default: None, if provided, only the releases before the date are returned
        after: str | int | dt.datetime, default: None, if provided, only the releases after the date are returned
        requirements: str, default: None, if provided (a comma separated list of requirements), only the releases that satisfy the requirements are returned
        """
        project = self.get_project(project, platform)
        if project is None:
            return None
        project_name = project.name
        releases = []
        before_date = strint_to_date(before)
        after_date = strint_to_date(after)
        for release in project.releases:
            try:
                version = semver.parse(release.version)
            except Exception as e:
                logger.debug(
                    f"Error parsing version {release.version} for {project_name}: {e}"
                )
                continue
            if osi_verified and db.reliable_published_date(release) is None:
                logger.debug(
                    f"Skipping release {release.version} for {project_name} as it is not OSI verified"
                )
                continue
            if before_date is not None and release.published_at > before_date:
                logger.debug(
                    f"Skipping release {release.version} published after {before_date} for {project_name}"
                )
                continue
            if after_date is not None and release.published_at < after_date:
                logger.debug(
                    f"Skipping release {release.version} published before {after_date} for {project_name}"
                )
                continue
            if version is None:
                logger.error(f"Invalid version {release.version} for {project_name}")
                continue
            if exclude_deprecated and not version.major >= 1:
                logger.debug(
                    f"Skipping deprecated version {release.version} for {project_name}"
                )
                continue
            if exclude_nonstable and version.pre is not None:
                logger.debug(
                    f"Skipping non-stable version {release.version} for {project_name}"
                )
                continue
            if requirements is not None and bool(requirements.strip()):
                # check if the version satisfies the requirements
                if not version_satisfies_requirements(version, requirements):
                    logger.debug(
                        f"Version {release.version} does not satisfy requirements {requirements} for {project_name}"
                    )
                    continue
            if analysed and release.nloc_total is None:
                logger.debug(
                    f"Skipping release {release.version} without static analysis for {project_name}"
                )
                continue
            releases.append(release)
        if sort_semantically:
            releases = sorted(
                releases, key=lambda x: semver.parse(x.version), reverse=descending
            )
        else:
            releases = sorted(
                releases, key=lambda x: x.published_at, reverse=descending
            )
        return releases

    def _verify_dates(self, project: Project | str):
        res = self.osi.query_package(project.name, platform=project.platform)
        if res is None:
            logger.error(f"Project {project.name} not found in OSI")
            return
        for vdict in res.get("versions", []):
            published_at = vdict.get("publishedAt", None)
            vkey = vdict.get("versionKey", {})
            version = vkey.get("version", None)
            if published_at is not None:
                release = Release.get_or_none(
                    Release.project == project, Release.version == version
                )
                if release is None:
                    if version.endswith(".0"):
                        version = version[:-2]
                    release = Release.get_or_none(
                        Release.project == project, Release.version == version
                    )
                    if release is None:
                        continue
                published_at = dt.datetime.strptime(published_at, "%Y-%m-%dT%H:%M:%SZ")
                release.published_at = published_at
                release.osi_verified = True
                release.save()
        project.osi_verified = True
        project.save()

    def get_release(
        self,
        project_or_release: str | Project | Release,
        version: str = None,
        platform: str = "pypi",
        before: str | int | dt.datetime = None,
        requirements: str = None,
        osi_verified: bool = True,
        analysed: bool = False,
        after: str | int | dt.datetime = None,
    ) -> Release:
        """
        Get a specific release of a project, uses latest release if version is None

        project: str | Project, the project name or the project object
        version: str, the version number, if None, the latest release is used
        platform: str, default: pypi
        before: str | int | dt.datetime, default: None, if provided, only the releases before the date are returned
        after: str | int | dt.datetime, default: None, if provided, only the releases after the date are returned
        requirements: str, default: None, if provided (a comma separated list of requirements), only the releases that satisfy the requirements are returned
        analysed: bool, default: False, if True, a release with static analysis is returned if available
        """
        if isinstance(project_or_release, Release):
            return project_or_release
        project = self.get_project(project_or_release, platform)
        if project is None:
            return None
        version = version if version else project.latest_release
        before_date = strint_to_date(before)
        after_date = strint_to_date(after)
        if (
            before_date is not None
            or after_date is not None
            or requirements is not None
            or analysed
        ):
            releases = self.get_releases(
                project.name,
                platform=platform,
                before=before_date,
                after=after,
                sort_semantically=True,
                requirements=requirements,
                osi_verified=osi_verified,
                analysed=analysed,
            )
            return releases[0] if len(releases) > 0 else None
        release = Release.get_or_none(
            Release.project == project.id, Release.version == version
        )
        return release

    def get_most_recent_release(
        self,
        project: str | Project,
        date: dt.datetime = None,
        platform: str = "pypi",
        exclude_deprecated: bool = False,
        sort_semantically: bool = True,
    ) -> Release:
        """
        Get the most recent release of a project at a specific date
        """
        project = self.get_project(project, platform)
        rels = Release.select().where(
            Release.project == project, Release.published_at <= date
        )
        if exclude_deprecated:
            rels = [rel for rel in rels if version_is_stable(semver.parse(rel.version))]

        if sort_semantically:
            rels = sorted(rels, key=lambda x: semver.parse(x.version), reverse=True)
        else:
            rels = sorted(rels, key=lambda x: x.published_at, reverse=True)

        return rels[-1] if len(rels) > 0 else None

    def get_release_timeline(
        self,
        project_name: str,
        start_date: str | int | dt.datetime = 2019,
        end_date: str = None,
        step: str = "y",
        platform: str = "pypi",
        exclude_deprecated: bool = False,
        sort_semantically: bool = True,
    ) -> List[tuple]:
        """
        Computes the release timeline of a project in a specific time range

        returns: list of tuples (datetime, Release)
        """
        start_date = strint_to_date(start_date)
        end_date = strint_to_date(end_date)
        step = step.strip().lower()
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        if not end_date:
            end_date = dt.datetime.now()
        # for each date in the range, get the most recent releases and check for vulnerabilities
        results: list = []
        # releases are sorted in descending order
        releases = self.get_releases(
            project.name,
            platform=platform,
            descending=True,
            exclude_deprecated=exclude_deprecated,
            sort_semantically=sort_semantically,
        )
        while start_date <= end_date:
            release_most_recent = None
            # naive quadratic time complexity, could be improved
            for i, rel in enumerate(releases):
                if rel.published_at <= start_date:
                    release_most_recent = rel
                    break
            results.append((start_date, release_most_recent))
            start_date = datetime_increment(start_date, step)
        return results

    def get_vulnerabilities(
        self,
        project: str | Project,
        version: str = None,
        platform: str = "pypi",
        include_categories: bool = False,
    ) -> dict:
        """
        Get vulnerabilities of a project and a specific version number (release).
        If a version is not provided, the all vulnerabilities are returned.

        returns:
        {
            'cves': {
                <cve_id>: {
                    'applicability': [
                        { 'version_start': <version>, 'version_end': <version>, 'start_date': <date>, 'end_date': <date> },
                        ...
                    ],
                    <key>: <value>,
                }
                ...
            },
            'cwes': {
                <cwe_id>: {
                    <key>: <value>,
                    ...
                    'cves': [ <cve_id>, ... ]
                }
                ...
            }
        }
        """
        # Force lowercase
        version = version if version else ""
        # Get the project
        project = self.get_project(project, platform)
        if project is None:
            return None
        project_name = project.name
        # Get the release
        release = None
        if version:
            release = Release.get_or_none(
                Release.project == project, Release.version == version
            )
            if release is None:
                logger.error(f"Release '{version}' not found for {project_name}")
                return None
        # we do not skip deprecated versions here as the "first" release might be deprecated
        releases = self.get_releases(
            project.name,
            platform=platform,
            descending=False,
            sort_semantically=False,
            requirements=f">0.9",
            exclude_deprecated=False,
        )
        releases = (
            sorted(releases, key=lambda x: x.published_at, reverse=False)
            if releases is not None
            else []
        )
        first_release = releases[0] if len(releases) > 0 else None
        logger.debug(
            f"Querying databases for vulnerabilities of {project_name} {version}"
        )
        product_name = project.product or project_name
        logger.debug(f"Getting CPEs for {project.vendor} {product_name}")
        cpes = nvd.CPE.select().where(
            (nvd.CPE.vendor == project.vendor) & (nvd.CPE.product == product_name)
        )
        logger.debug(f"Found {len(cpes)} CPEs for {project.vendor} {project.name}")
        # We need to find the CPEs that match the version
        vulnset = set()
        release_published_at = release.published_at if release else None
        results = {
            "cves": {},
            "cwes": {},
        }
        cves, cwes = results["cves"], results["cwes"]
        processed_versions = {}
        logger.debug(
            f"Got {len(cpes)} CPEs for {project.vendor} {project.name} {version}"
        )
        for cpe in cpes:
            cpe: nvd.CPE
            if (
                project.platform == "pypi"
                and cpe.target_sw
                and cpe.target_sw not in ["python", "*"]
            ):
                continue
            logger.debug(
                f"Processing CPE {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}"
            )
            # Get release of versions since some contain letters
            node = cpe.node
            # extract cve from node
            cve = node.cve if node else None
            logger.debug(
                f"Getting release for {cpe.vendor} {cpe.product} {cpe.version_start} - {cpe.version_end}"
            )
            start_release = Release.get_or_none(
                Release.project == project, Release.version == cpe.version_start
            )
            end_release = Release.get_or_none(
                Release.project == project, Release.version == cpe.version_end
            )
            exclude_end = cpe.exclude_end_version
            exclude_start = cpe.exclude_start_version
            vuln_cpe_id = (
                f"{cve.cve_id}:{cpe.version}:{cpe.version_start}:{cpe.version_end}"
            )
            has_exact_version = cpe.version is not None and cpe.version not in ["", "*"]
            if has_exact_version:
                if cve.cve_id not in processed_versions:
                    processed_versions[cve.cve_id] = set()
                elif cpe.version in processed_versions[cve.cve_id]:
                    logger.debug(f"Vulnerability {vuln_cpe_id} already in set")
                    continue
                processed_versions[cve.cve_id].add(cpe.version)
            if vuln_cpe_id in vulnset and not has_exact_version:
                logger.debug(f"Vulnerability {vuln_cpe_id} already in set")
                continue
            start_date: datetime = db.reliable_published_date(start_release)
            # get the commit if it is not OSI verified
            end_date: datetime = db.reliable_published_date(end_release)
            logger.debug(
                f"Getting vulnerabilities for {cpe.vendor}:{cpe.product}:{cpe.version} {cpe.version_start} ({start_date}) - {cpe.version_end}({end_date})"
            )
            add = False
            if has_exact_version:
                applicability = {
                    "version": cpe.version,
                }
                add = cpe.version == release.version if release is not None else True
            else:
                applicability = {
                    "version_start": cpe.version_start
                    if bool(cpe.version_start)
                    else (first_release.version if first_release is not None else None),
                    "exclude_start": exclude_start,
                    "version_end": cpe.version_end if bool(cpe.version_end) else None,
                    "exclude_end": exclude_end,
                    "start_date": start_date
                    if start_date is not None
                    else (
                        first_release.published_at
                        if first_release is not None
                        else None
                    ),
                    "end_date": end_date,
                }
                # check applicability on release version instead of release date, since the date might be in range, but the version not
                add = (
                    version_in_range(
                        version,
                        cpe.version_start,
                        cpe.version_end,
                        exclude_start,
                        exclude_end,
                    )
                    if bool(version)
                    else True
                )
            if add:
                vulnset.add(cve.id)
                if cve.cve_id not in cves:
                    weaknesses = db.NVD.cwes(
                        cve.cve_id, categories=include_categories, to_dict=False
                    )
                    # TODO: verify categories
                    cwe_ids = set()
                    for cwe in weaknesses:
                        logger.debug(f"Processing CWE {cwe.cwe_id}")
                        cwe_id = cwe.cwe_id
                        cwe_ids.add(cwe_id)
                        if cwe_id not in cwes:
                            cwes[cwe_id] = model_to_dict(cwe, recurse=False)
                            cwes[cwe_id]["cves"] = [cve.cve_id]
                        else:
                            cwes[cwe_id]["cves"].append(cve.cve_id)
                    cve_data = model_to_dict(cve)
                    cve_data["cwes"] = sorted(list(cwe_ids))
                    cve_data["applicability"] = [applicability]
                    cves[cve.cve_id] = cve_data
                else:
                    cves[cve.cve_id]["applicability"].append(applicability)
        # translate 'version' applicability to 'version_start' and 'version_end'
        for _, cve in cves.items():
            cve_id = cve.get("cve_id")
            apps = cve.get("applicability", [])
            apps = db.compute_version_ranges(project, apps)
            for app in apps:
                # add project name to clarify the applicability
                app["project"] = project_name
                v_end = app.get("version_end")
                if app.get("exclude_end", False) is False:
                    if v_end is not None:
                        rels = self.get_releases(
                            project.name,
                            platform=platform,
                            descending=False,
                            sort_semantically=True,
                            requirements=f">{v_end}",
                        )
                        if len(rels) > 0:
                            rel = rels[0]
                            pub_at = db.reliable_published_date(rel)
                            app["patched_at"] = pub_at
                            app["verified"] = True
                            app["patched_version"] = rel.version
                    if app.get("patched_at") is None:
                        app["patched_at"] = None
                        app["patched_version"] = None
                else:
                    app["patched_at"] = app.get("end_date")
                    app["verified"] = True
                    app["patched_version"] = app.get("version_end")
            cve["applicability"] = apps
        for _, cw in cwes.items():
            cw["cves"] = sorted(list(set(cw["cves"])))
        return results

    def get_indirect_vulnerabilities(
        self,
        project_name: str,
        version: str = None,
        platform: str = "pypi",
        exclude_deprecated: bool = True,
        include_categories: bool = False,
        most_recent_version: bool = True,
        before: str | int | dt.datetime = None,
        sort_semantically: bool = True,
    ) -> List[nvd.CVE]:
        """
        Get indirect vulnerabilities of a project and a specific version number (release)
        This is done by getting the dependencies of the project and checking for vulnerabilities in them
        Each release is formatted as project:version

        project_name: str, the project name
        version: str, the version number, if None, the latest release is used
        platform: str, default: pypi
        include_categories: bool, default: False, include CWE categories in the results
        most_recent_version: bool, default: True, if True, the most recent release is used

        returns:
        {
            'cves':
            'cwes':
            'releases'
        }
        """
        release = self.get_release(project_name, version, platform)
        if release is None:
            logger.error(f"Release {version} not found for {project_name}")
            return None
        version = release.version
        results = {
            "cves": {},
            "cwes": {},
            "releases": {},
        }
        cves, cwes, releases = results["cves"], results["cwes"], results["releases"]
        dependencies = self.get_dependencies(project_name, version, platform)
        if dependencies is None:
            logger.error(f"Dependencies not found for {project_name}")
            return results
        for dep in dependencies:
            logger.info(f"Getting vulnerabilities for {dep.name}")
            depname = dep.name
            requirements = dep.requirements
            rels = self.get_releases(
                depname,
                platform=dep.platform,
                exclude_deprecated=exclude_deprecated,
                sort_semantically=sort_semantically,
                requirements=requirements,
                before=before,
            )
            if most_recent_version:
                rels = [rels.pop(0)] if len(rels) > 0 else []
            for rel in rels:
                vulnerabilities = self.get_vulnerabilities(
                    depname, rel.version, platform=dep.platform
                )
                rel_id = f"{depname}:{rel.version}"
                for cve_id in vulnerabilities.get("cves", {}):
                    # add project name to applicability
                    cve = vulnerabilities["cves"][cve_id]
                    if cve_id in cves:
                        cves[cve_id]["applicability"].extend(
                            cve.get("applicability", [])
                        )
                    else:
                        cves[cve_id] = cve
                for cwe_id in vulnerabilities.get("cwes", {}):
                    weak = vulnerabilities["cwes"][cwe_id]
                    if cwe_id not in cwes:
                        cwes[cwe_id] = weak
                    else:
                        weakset = set(cwes[cwe_id].get("cves", []))
                        weakset.update(weak.get("cves", []))
                        cwes[cwe_id]["cves"] = list(weakset)
                if rel_id not in releases:
                    releases[rel_id] = model_to_dict(rel, recurse=False)
                    bandit_report = release.bandit_report.first()
                    if bandit_report:
                        releases[rel_id]["bandit_report"] = model_to_dict(
                            bandit_report, recurse=False
                        )
        return results

    def get_vulnerabilities_timeline(
        self,
        project_name: str | list,
        start_date: str = 2019,
        end_date: str = None,
        step: str = "y",
        platform: str = "pypi",
        exclude_deprecated: bool = False,
    ) -> dict:
        """
        Returns a list of vulnerabilities for a project in a specific time range.
        For each date, the most recent release is used to check for vulnerabilities.

        project_name: str, or list of str
        start_date: str, format: YYYY[-MM]
        end_date: str, format: YYYY[-MM] or falsy value
        step: str, format: y(ear) / m(month), needs to match the format of the dates' lowest precision
        platform: str, default: pypi

        Returns:
        {
            'cves': {},
            'cwes': {},
            'releases': {},
            'timeline': [ { 'date': datetime, 'release': str, 'cves': [str] }, ... ]
        }
        """
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        # for each date in the range, get the most recent releases and check for vulnerabilities
        results: list = {
            "cwes": {},
            "cves": {},
            "releases": model_to_dict(project, recurse=False),
            "timeline": [],
        }
        results["releases"] = {}
        cves, releases, timeline = (
            results["cves"],
            results["releases"],
            results["timeline"],
        )
        cwes = results["cwes"]
        vulnerabilities = self.get_vulnerabilities(project.name, platform=platform)
        rels = self.get_releases(
            project.name, platform=platform, exclude_deprecated=exclude_deprecated
        )
        logger.info(
            f"Generating timeline with {len(rels)} releases for {project.name}, got: {len(vulnerabilities.get('cves', {}))} vulnerabilities"
        )
        rel_timeline = self.get_release_timeline(
            project.name,
            start_date=start_date,
            end_date=end_date,
            step=step,
            platform=platform,
            exclude_deprecated=exclude_deprecated,
        )
        for date, rel in rel_timeline:
            if rel is None:
                logger.debug(f"No release found for {project.name} at {start_date}")
                results["timeline"].append({"date": date, "release": None, "cves": []})
                continue
            logger.info(
                f"Got most recent release {rel.version} for {project.name} at {date}"
            )
            vulns = []
            for vuln in vulnerabilities.get("cves", {}).values():
                applicabilities = vuln.get("applicability", [])
                is_applicable = db.is_applicable(rel, applicabilities)
                if is_applicable:
                    vulns.append(vuln)
                    for cwe_id in vuln.get("cwes", []):
                        if cwe_id not in cwes:
                            cwes[cwe_id] = vulnerabilities.get("cwes", {}).get(
                                cwe_id, {}
                            )
            timeline.append(
                {
                    "date": date,
                    "release": rel.version,
                    "cves": [cve["cve_id"] for cve in vulns if cve is not None],
                }
            )
            for cve in vulns:
                cve_id = cve.get("cve_id")
                if cve_id:
                    cves[cve_id] = cve
            releases[rel.version] = model_to_dict(rel, recurse=False)
            bandit_report = rel.bandit_report.first()
            if bandit_report:
                results["releases"][rel.version]["bandit_report"] = model_to_dict(
                    bandit_report, recurse=False
                )
        return results

    def get_indirect_vulnerabilities_timeline(
        self,
        project_name: str | list,
        start_date: str = 2019,
        end_date: str = None,
        step: str = "y",
        platform: str = "pypi",
        exclude_deprecated: bool = False,
        force: bool = False,
    ) -> dict:
        """
        Returns a list of vulnerabilities for a project in a specific time range.
        For each date, the most recent release is used to check for vulnerabilities.

        project_name: str, or list of str
        start_date: str, format: YYYY[-MM]
        end_date: str, format: YYYY[-MM] or falsy value
        step: str, format: y(ear) / m(month), needs to match the format of the dates' lowest precision
        platform: str, default: pypi

        Returns: tuple of (date, release, cves)
        """
        project = self.get_project(project_name, platform)
        if project is None:
            logger.error(f"Project {project_name} not found")
            return None
        # for each date in the range, get the most recent releases and check for vulnerabilities
        results: list = {
            "cwes": {},
            "cves": {},
            "releases": model_to_dict(project, recurse=False),
            "timeline": [],
        }
        results["releases"] = {}
        dep_vulns = {}
        cves, releases, timeline = (
            results["cves"],
            results["releases"],
            results["timeline"],
        )
        cwes = results["cwes"]
        rel_timeline = self.get_release_timeline(
            project.name,
            start_date=start_date,
            end_date=end_date,
            step=step,
            platform=platform,
            exclude_deprecated=exclude_deprecated,
        )
        previous_deps = []
        for date, rel in rel_timeline:
            if rel is None:
                logger.warning(f"No release found for {project.name} at {start_date}")
                start_date = datetime_increment(start_date, step)
                results["timeline"].append({"date": date, "release": None, "cves": []})
                continue
            logger.info(
                f"Got most recent release {rel.version} for {project.name} at {date}"
            )
            deps = self.get_dependencies(
                project.name, rel.version, platform, force=force
            )
            if len(previous_deps) > 0 and deps is None:
                # some versions do not have dependencies as they are unsupported releases
                # assume the dependencies are the same as the previous release
                deps = previous_deps
            elif deps is not None:
                previous_deps = deps
            else:
                logger.warning(
                    f"No dependencies found for {project.name} {rel.version}"
                )
                deps = []
            # all vulns for all dependencies
            all_vulns = set()
            all_releases = set()
            for dep in deps:
                # process each dependency
                depname = dep.name
                if depname not in dep_vulns:
                    # here we get all the vulnerabilities, so that we quickly can look them up
                    vulns = self.get_vulnerabilities(depname, platform=dep.platform)
                    dep_vulns[depname] = vulns if vulns is not None else {}
                # process each existing vulnerability
                requirements = dep.requirements
                dep_release = self.get_release(
                    depname,
                    platform=dep.platform,
                    before=date,
                    requirements=requirements,
                )
                if dep_release is None:
                    logger.warning(f"No release found for {depname} at {date}")
                    continue
                rel_id = f"{depname}:{dep_release.version}"
                all_releases.add(rel_id)
                if rel_id not in releases:
                    nloc_total = dep_release.nloc_total
                    if nloc_total is None:
                        analysed_rel = self.get_release(
                            depname,
                            dep_release.version,
                            platform=dep.platform,
                            analysed=True,
                            requirements=f"<{dep_release.version}",
                        )
                        nloc_total = (
                            analysed_rel.nloc_total
                            if analysed_rel is not None
                            else None
                        )
                    releases[rel_id] = model_to_dict(dep_release, recurse=False)
                    if nloc_total is not None:
                        releases[rel_id]["nloc_total"] = nloc_total
                    bandit_report = dep_release.bandit_report.first()
                    if bandit_report:
                        releases[rel_id]["bandit_report"] = model_to_dict(
                            bandit_report, recurse=False
                        )
                for vuln in dep_vulns.get(depname, {}).get("cves", {}).values():
                    # process each vulnerability
                    applicabilities = vuln.get("applicability", [])
                    is_applicable = db.is_applicable(dep_release, applicabilities)
                    if is_applicable:
                        # we have found an applicable vulnerability
                        cve_id = vuln.get("cve_id")
                        if cve_id not in cves:
                            cves[cve_id] = vuln
                        all_vulns.add(cve_id)
                        for cwe_id in vuln.get("cwes", []):
                            if cwe_id not in cwes:
                                cwes[cwe_id] = dep_vulns.get("cwes", {}).get(cwe_id, {})
            timeline.append(
                {
                    "date": date,
                    "release": sorted(list(all_releases)),
                    "cves": sorted(list(all_vulns)),
                }
            )
            date = datetime_increment(date, step)
        return results

    def get_dependencies(
        self,
        project_or_release: str | Project | Release,
        version: str = None,
        platform: str = "pypi",
        force: bool = False,
    ) -> List[ReleaseDependency]:
        """
        Get dependencies of a project and a specific version number (release).
        Includes indirect dependencies.

        project_name: str
        version: str, if None, the latest release is used
        platform: str, default: pypi
        """
        release = self.get_release(project_or_release, version, platform)
        project_name = (
            project_or_release
            if type(project_or_release) == str
            else (
                project_or_release.project.name
                if type(project_or_release) == Release
                else project_or_release.name
            )
        )
        if release is None:
            logger.error(f"Release '{version}' not found for {project_name}")
            return None
        if not force:
            if release.dependency_count == 0:
                logger.debug(f"No dependencies found for {project_name} {version}")
                return []
            elif release.dependency_count is not None:
                dependencies = [dep for dep in release.dependencies]
                # Found dependencies in the database
                logger.debug(
                    f"Found {len(dependencies)} dependencies for {project_name} {version}"
                )
                return dependencies
        else:
            # Delete the dependencies
            for dep in release.dependencies:
                dep.delete_instance()
        # No dependencies in database, query the API
        result = self.osi.query_dependencies(project_name, version, platform)
        if result is None or "nodes" not in result:
            logger.error(f"Dependencies not found for {project_name} {version}")
            return None
        nodes = result.get("nodes", [])
        if not nodes:
            logger.error(f"No nodes found for {project_name} {version}")
            return None
        if nodes[0].get("versionKey", {}).get("name", "") != project_name:
            # OSI should always return the first node as the project itself
            logger.error(f"First node is not {project_name}! Solve this")
            return None
        edges = result.get("edges", [])
        metadata = {}
        # process the graph
        for edge in edges:
            req = edge.get("requirement", "")
            nfr = edge.get("fromNode", None)
            nto = edge.get("toNode", None)
            if nto is None:
                continue
            node = nodes[nto]
            node_from = nodes[nfr] if nfr is not None else None
            node_to_name = node.get("versionKey", {}).get("name", "")
            if node_from is not None:
                node_from_name = node_from.get("versionKey", {}).get("name", "")
            metadata[node_to_name] = {
                "requirements": req,
                "inherited_from": node_from_name,
                "depth": None,
            }
        for nname in metadata:
            depth = 0
            inherited_from = metadata[nname].get("inherited_from", None)
            visited = set()
            while inherited_from is not None:
                depth += 1
                if inherited_from in visited:
                    break
                visited.add(inherited_from)
                inherited_from = metadata.get(inherited_from, {}).get(
                    "inherited_from", None
                )
            metadata[nname]["depth"] = depth
        results = []
        # Save the dependencies
        for node in nodes:
            relation = node.get("relation", "")
            if relation == "SELF":
                logger.debug(f"Skipping self-relation for {project_name} {version}")
                continue
            version_key = node.get("versionKey", {})
            name = version_key.get("name", "").lower()
            if name == project_name or not name:
                logger.debug(
                    f"Skipping dependency '{name}' for {project_name} {version}"
                )
                continue
            ptfrm = version_key.get("system", "").lower()
            requirements = metadata.get(name, {}).get("requirements", "")
            depth = metadata.get(name, {}).get("depth", 0)
            name, project_name, ptfrm = self.__format_strings(name, project_name, ptfrm)
            version = version_key.get("version", "")
            logger.debug(
                f"Creating dependency {name} {project_name} {ptfrm} {requirements}"
            )
            inherited_from = metadata.get(name, {}).get("inherited_from", None)
            dep_instance = ReleaseDependency.create(
                release=release,
                name=name,
                project_name=project_name,
                platform=ptfrm,
                version=version,
                is_direct=relation == "DIRECT",
                inherited_from=inherited_from
                if inherited_from != project_name
                else None,
                depth=depth,
                requirements=requirements,
            )
            dep_instance.save()
            results.append(dep_instance)
        release.dependency_count = len(results)
        release.save()
        return results

    def get_bandit_report(
        self,
        project_or_release: str | Project,
        version: str = None,
        force: bool = True,
        requirements: str = None,
        platform: str = "pypi",
    ) -> BanditReport:
        """
        Gets the bandit report of a project or a specific release
        If no version is provided, the latest release with a bandit report is used

        project_or_release: str | Project | Release
        version: str, the version number, if None, the latest release is used
        platform: str, default: pypi
        """
        project = release = None
        if isinstance(project_or_release, Project):
            version = version if version else project_or_release.latest_release
            project = project_or_release
        elif isinstance(project_or_release, Release):
            version = project_or_release.version
            project = project_or_release.project
        else:
            project = self.get_project(project_or_release, platform)
            version = version if version else project.latest_release
        if project is None:
            logger.error(f"Project {project_or_release} not found")
            return None
        if release is None:
            release = self.get_release(
                project, version, platform, requirements=requirements
            )
            if release is None:
                logger.error(f"Release {version} not found for {project.name}")
                return None
        bandit_report = release.bandit_report.first()
        if bandit_report is None and force:
            logger.info(f"No bandit report found for {project.name} {version}")
            releases = self.get_releases(
                project.name, platform=platform, sort_semantically=True
            )
            for rel in releases:
                bandit_report = rel.bandit_report.first()
                if bandit_report is not None:
                    logger.info(f"Found bandit report for {project.name} {rel.version}")
                    break
        if bandit_report is None:
            logger.error(f"No bandit report found for {project.name} {version}")
            return None
        return bandit_report

    def get_analysed_releases(
        self,
        project: str | Project,
        platform: str = "pypi",
        with_dependencies: bool = True,
    ) -> List[Release]:
        """
        Gets all releases of a project with static analysis.
        First is the project, then the dependencies, when with_dependencies is True

        project: str | Project
        platform: str, default: pypi
        with_dependencies: bool, default: True, if True, dependencies are included in the list
        """
        release = self.get_release(project, platform=platform, analysed=True)
        results = []
        if release is None:
            logger.error(f"No release found for {project}")
            return results
        results.append(release)
        for dependency in release.dependencies:
            dep_name = dependency.name
            dep_release = self.get_release(
                dep_name, platform=dependency.platform, analysed=True
            )
            if dep_release is not None:
                results.append(dep_release)
        return results

    def get_bandit_issues(
        self,
        project: str | Project,
        platform: str = "pypi",
        with_dependencies: bool = True,
    ) -> List[dict]:
        """
        Gets all Bandit issues with / without dependencies
        """
        project_name = project if isinstance(project, str) else project.name
        results = []
        releases = self.get_analysed_releases(
            project, platform=platform, with_dependencies=with_dependencies
        )
        for release in releases:
            report = release.bandit_report.first()
            source = "Direct" if release.project.name == project_name else "Indirect"
            release_name = f"{release.project.name}"
            if report is not None:
                for issue in report.issues:
                    module = issue.module if issue.module else ""
                    package = issue.package if issue.package else ""
                    is_test = package.startswith("test") or "test" in module
                    if is_test:
                        logger.debug(
                            f"Detected test file {issue.filename} for {project_name} {release.version}, test ID {issue.test_id}"
                        )
                    severity = issue.severity
                    confidence = issue.confidence
                    score = bandit_issue_score(severity, confidence)
                    issue = model_to_dict(issue, recurse=False)
                    issue["project"] = release.project.name
                    issue["source"] = source
                    issue["score"] = score
                    issue["package_module"] = (
                        f"{package}.{module}"
                        if package and module
                        else package or module
                    )
                    issue["project_package"] = (
                        f"{release_name}.{package}" if package else release_name
                    )
                    issue["project_version"] = release.version
                    issue["is_test"] = is_test
                    test_id = issue.get("test_id")
                    issue["test_category"] = (
                        test_id[:2] if test_id and len(test_id) > 2 else None
                    )
                    results.append(issue)
        return results

    def get_report(
        self,
        *projects: str | Project,
        platform: str = "pypi",
        exclude_deprecated: bool = True,
        only_latest: bool = False,
        with_dependencies: bool = False,
    ) -> dict:
        """
        Gets an "overall" report of a project.
        These are designed to be generalised for dependencies as well

        *projects: str | Project, the project name or the project object, which could be dependencies
        platform: str, default: pypi
        exclude_deprecated: bool, default: True, if True, deprecated releases are excluded (non-stable)
        only_latest: bool, default: False, if True, only the latest release is used for CVEs
        with_dependencies: bool, default: False, if True, dependencies are included in the report


        returns a vulnerability report complemented with releases and the latest release's bandit report:
        {
            'cves': {}
            'cwes': {}
            'releases': {
                'project:version': {
                    'version': str,
                    'published_at': datetime,
                    'bandit_report': {} ... bandit report for the release without issues
                },
            }
            'latest': {
                'project': {
                    'version': str,
                    'published_at': datetime,
                    'bandit_report': {
                        'issues': [ {} ... bandit issue, ... ]
                    }
                },
            }
        }
        """
        results = {
            "cves": {},
            "cwes": {},
            "releases": {},
            "latest": {},
            "bandit": {},
        }
        bandit = results["bandit"]
        dep_vulns = {}
        dep_rels = {}
        for project in projects:
            project_name = project
            project = self.get_project(project, platform)
            if project is None:
                logger.error(f"Project {project} not found")
                return None
            result = self.get_vulnerabilities(
                project,
                project.latest_release if only_latest else None,
                platform=platform,
            )
            result = result if result is not None else {}
            rels = self.get_releases(
                project, platform=platform, exclude_deprecated=exclude_deprecated
            )
            releases = {}
            latest_release = project.latest_release
            bandit_report = self.get_bandit_report(project)
            latest_rel_id = f"{project_name}:{latest_release}"
            for rel in rels:
                # this is to provide information of all releases, although not necessarily used
                # added for transparency
                rel_id = f"{project_name}:{rel.version}"
                rel_dict = model_to_dict(rel, recurse=False)
                rel_dict["dependencies"] = {}
                if with_dependencies:
                    deps = self.get_dependencies(project_name, rel.version, platform)
                    if deps is not None:
                        for dep in deps:
                            dep_name = dep.name
                            if dep_name not in dep_rels:
                                rels = self.get_releases(
                                    dep_name, platform=dep.platform
                                )
                                vulns = self.get_vulnerabilities(
                                    dep_name, platform=dep.platform
                                )
                                dep_rels[dep_name] = rels if rels is not None else []
                                dep_vulns[dep_name] = vulns if vulns is not None else {}
                            else:
                                vulns = dep_vulns[dep_name]
                                rels = dep_rels[dep_name]
                            for cve in vulns.get("cves", {}):
                                if cve not in result["cves"]:
                                    result["cves"][cve] = vulns["cves"][cve]
                            for cwe in vulns.get("cwes", {}):
                                if cwe not in result["cwes"]:
                                    result["cwes"][cwe] = vulns["cwes"][cwe]
                            dep_version = dep.version
                            dep_platform = dep.platform
                            dep_req = dep.requirements
                            dep_id = f"{dep_name}:{dep_version}"
                            # gets the release of the dependency that fulfills the requirements
                            satisfies = []
                            not_satisfies = []
                            for rel in rels:
                                if rel.version == dep_version:
                                    satisfies.append(rel)
                                else:
                                    not_satisfies.append(rel)
                            if len(satisfies) == 0:
                                logger.debug(
                                    f"No release found for {dep_name} {dep_version} {dep_req}"
                                )
                                continue
                            dep_rel = satisfies[0]
                            dep_cve = set()
                            dep_patch_lag = set()
                            for cve_id in vulns.get("cves", {}):
                                cve = vulns["cves"][cve_id]
                                if cve_id not in result["cves"]:
                                    result["cves"][cve_id] = cve
                                for app in cve.get("applicability", []):
                                    if db.is_applicable(dep_rel, app):
                                        dep_cve.add(cve_id)
                                        v_end = app.get("version_end")
                                        v_excl = app.get("exclude_end", False)
                                        if v_end is not None and v_excl is False:
                                            rels = self.get_releases(
                                                dep_name,
                                                platform=dep_platform,
                                                requirements=f">{v_end}",
                                            )
                                            if len(rels) > 0:
                                                v_end = rels[0].version
                                        if (
                                            v_end is not None
                                            and "<" in dep_req
                                            and not version_satisfies_requirements(
                                                v_end, dep_req
                                            )
                                        ):
                                            # if there is a limiting version and the v_end does not satisfy the requirements
                                            logger.info(
                                                f"Patch lag for {rel_id} dependency {dep_name} {dep_version} ({cve_id}). Version end {v_end} '{dep_req}'"
                                            )
                                            dep_patch_lag.add(cve_id)
                            # count the amount of vulnerabilities introduced by requirements
                            rel_dict["dependencies"][dep_id] = {
                                "name": dep_name,
                                "version": dep_version,
                                "platform": dep_platform,
                                "requirements": dep.requirements,
                                "cves": dep_cve,
                                "patch_lag": dep_patch_lag,
                            }
                rel_dict["cves"] = set()
                rel_dict["cwes"] = set()
                releases[rel_id] = rel_dict
                for cve in result.get("cves", {}).values():
                    cve_id = cve.get("cve_id")
                    if db.is_applicable(rel, cve.get("applicability", [])):
                        rel_dict["cves"].add(cve_id)
                        rel_dict["cwes"].update(cve.get("cwes", []))
                if rel_id == latest_rel_id:
                    if "latest" not in result:
                        result["latest"] = {}
                    result["latest"][rel_id] = deepcopy(releases[rel_id])
            if bandit_report:
                # if there is a bandit report, add it to the latest release
                bandit_release = bandit_report.release
                brel_id = f"{project_name}:{bandit_report.release.version}"
                issues = bandit_report.issues
                bandit_report = model_to_dict(bandit_report, recurse=False)
                bandit_report["issues"] = [
                    model_to_dict(issue, recurse=False) for issue in issues
                ]
                bandit_report["release"] = brel_id
                result["latest"][latest_rel_id]["bandit_report"] = bandit_report
                result["latest"][latest_rel_id]["analysed_release"] = brel_id
                brel = model_to_dict(bandit_release, recurse=False)
                latest_rel = result["latest"][latest_rel_id]
                for key in brel:
                    # if the key is not in the latest release, add it
                    # this is to avoid overwriting the latest release's data, yet adding static code analysis data
                    if (
                        type(brel[key]) in [str, int, float, dt.datetime]
                        and latest_rel.get(key) is None
                    ):
                        latest_rel[key] = brel[key]
            else:
                logger.error(f"No bandit report found for {project_name}")
            for cve_id in result.get("cves", {}):
                if cve_id not in results["cves"]:
                    results["cves"][cve_id] = result["cves"][cve_id]
                else:
                    app = result["cves"][cve_id].get("applicability", [])
                    results["cves"][cve_id]["applicability"].extend(app)
            for cwe_id in result.get("cwes", {}):
                if cwe_id not in results["cwes"]:
                    results["cwes"][cwe_id] = result["cwes"][cwe_id]
                else:
                    cves = result["cwes"][cwe_id].get("cves", [])
                    prev_cves = results["cwes"][cwe_id].get("cves", [])
                    new_cves = set(cves + prev_cves)
                    results["cwes"][cwe_id]["cves"] = sorted(list(new_cves))
            for rel_id in releases:
                if rel_id not in results["releases"]:
                    results["releases"][rel_id] = releases[rel_id]
            for latest in result.get("latest", {}):
                if latest not in results["latest"]:
                    results["latest"][latest] = result["latest"][latest]
        bandit["count"] = {}
        bandit["by_test"] = {}
        bandit["by_cwe"] = {}
        for lrel in results["latest"]:
            for dep in results["latest"][lrel].get("dependencies", {}).values():
                depname = dep["name"]
                dproj = self.get_release(
                    depname,
                    dep["version"],
                    platform=dep["platform"],
                    requirements=dep["requirements"],
                    analysed=True,
                )
                if dproj is None:
                    logger.error(f"Dependency {depname} {dep['version']} not found")
                    continue
                bandit_report = dproj.bandit_report.first()
                dproj_dict = model_to_dict(dproj, recurse=False)
                dproj_dict["bandit_report"] = (
                    model_to_dict(bandit_report, recurse=False)
                    if bandit_report
                    else None
                )
                for key in dproj_dict:
                    if (
                        type(dproj_dict[key]) in [str, int, float, dt.datetime, dict]
                        and dep.get(key) is None
                    ):
                        dep[key] = dproj_dict[key]
            bandit_report = results["latest"][lrel].get("bandit_report", {})
            if "issues" in bandit_report:
                issues = bandit_report["issues"]
                for issue in issues:
                    test_id = issue.get("test_id")
                    cwe_id = issue.get("cwe_id", "unknown")
                    by_test = bandit["by_test"]
                    by_cwe = bandit["by_cwe"]
                    if test_id not in by_test:
                        by_test[test_id] = {"release": set([lrel])}
                    else:
                        if lrel not in by_test[test_id]["release"]:
                            by_test[test_id]["release"].add(lrel)
                    if cwe_id not in by_cwe:
                        by_cwe[cwe_id] = {"release": set([lrel])}
                    else:
                        if lrel not in by_cwe[cwe_id]["release"]:
                            by_cwe[cwe_id]["release"].add(lrel)
                    severity = issue.get("severity", "").lower()
                    confidence = issue.get("confidence", "").lower()
                    sev = f"severity_{severity[0]}"
                    conf = f"confidence_{confidence[0]}"
                    sevconf = f"{sev}_{conf}"
                    by_test[test_id][sev] = by_test[test_id].get(sev, 0) + 1
                    by_test[test_id][conf] = by_test[test_id].get(conf, 0) + 1
                    by_test[test_id][sevconf] = by_test[test_id].get(sevconf, 0) + 1
                    by_cwe[cwe_id][sev] = by_cwe[cwe_id].get(sev, 0) + 1
                    by_cwe[cwe_id][conf] = by_cwe[cwe_id].get(conf, 0) + 1
                    by_cwe[cwe_id][sevconf] = by_cwe[cwe_id].get(sevconf, 0) + 1
            for test in bandit["by_test"].values():
                for key in test:
                    if type(test[key]) not in [int, float]:
                        continue
                    bandit["count"][key] = test.get(key, 0) + test[key]
                sev_h_conf_h = test.get("severity_h_confidence_h", 0)
                sev_h_conf_m = test.get("severity_h_confidence_m", 0)
                sev_h_conf_l = test.get("severity_h_confidence_l", 0)
                sev_m_conf_h = test.get("severity_m_confidence_h", 0)
                sev_m_conf_m = test.get("severity_m_confidence_m", 0)
                sev_m_conf_l = test.get("severity_m_confidence_l", 0)
                sev_l_conf_h = test.get("severity_l_confidence_h", 0)
                sev_l_conf_m = test.get("severity_l_confidence_m", 0)
                sev_l_conf_l = test.get("severity_l_confidence_l", 0)
                critical = sev_h_conf_h
                high = sev_h_conf_m + sev_m_conf_h
                medium = sev_h_conf_l + sev_m_conf_m + sev_l_conf_h
                low = sev_m_conf_l + sev_l_conf_m
                none = sev_l_conf_l
                bandit["count"]["issues_critical"] = (
                    bandit["count"].get("critical", 0) + critical
                )
                bandit["count"]["issues_high"] = bandit["count"].get("high", 0) + high
                bandit["count"]["issues_medium"] = (
                    bandit["count"].get("medium", 0) + medium
                )
                bandit["count"]["issues_low"] = bandit["count"].get("low", 0) + low
        return results

    # we need these dataframes, where "release" includes dependencies by "source"
    # structure: Project | Version | Source |
    # 1) CVEs per release
    # 2) CWEs per release
    # 4) Bandit Issues per release
    # 5) Static Analysis Summary per release

    def get_releases_with_dependencies(
        self,
        project: str | Project,
        platform: str = "pypi",
        analysed: bool = True,
        before_release: bool = True,
        sort_semantically: bool = True,
        only_latest: bool = False,
    ) -> List[list]:
        """
        Gets a list of tuples where each tuple contains a release and its dependencies

        returns:
        [[(release, None), (deprel, dep), ...], ...], list of lists where each list contains all releases with the dependency object it is derived from
        """
        results = []
        releases = self.get_releases(
            project,
            platform=platform,
            analysed=analysed,
            exclude_deprecated=False,
            sort_semantically=sort_semantically,
        )
        if releases is None:
            return results
        previous_major = None
        previous_dependencies = []
        for release in releases:
            dependencies = self.get_dependencies(project, release.version, platform)
            dependencies = dependencies if dependencies is not None else []
            release_version = (
                semver.parse(release.version) if release.version is not None else None
            )
            if (
                previous_major == release_version.major
                and len(previous_dependencies) > 0
                and len(dependencies) == 0
            ):
                dependencies = previous_dependencies
            else:
                previous_major = release_version.major
                previous_dependencies = dependencies
            result = [(release, None)]
            for dep in dependencies:
                # get the latest release of each dependency before the main project's release
                before_date = release.published_at if before_release else None
                deprel = self.get_release(
                    dep.name,
                    dep.version,
                    platform=dep.platform,
                    requirements=dep.requirements,
                    before=before_date,
                )
                if deprel is not None:
                    result.append((deprel, dep))
            results.append(result)
            if only_latest:
                break
        return results

    def __patch_lag(self, cve: dict, release_or_project: Release | Project) -> dict:
        """
        Returns a dictionary of patch lag KPIs for a CVE
        """
        project = (
            release_or_project.project
            if isinstance(release_or_project, Release)
            else release_or_project
        )
        project_name = project.name
        platform = project.platform
        apps = cve.get("applicability", [])
        releases = self.get_releases(project_name, platform=platform)
        releases = sorted(releases, key=lambda x: x.published_at)
        first_release = releases[0] if len(releases) > 0 else None
        first_published = db.reliable_published_date(first_release)
        cve_published = cve.get("published_at")
        result = {
            "cve_id": [],
            "start_to_patched": [],
            "start_to_published": [],
            "published_to_patched": [],
            "patched_date": [],
            "version_end": [],
            "exclude_version_end": [],
        }
        cve_id = cve.get("cve_id")
        for app in apps:
            # pick only the latest within the same range
            if not app.get("verified", False):
                logger.debug(f"Skipping OSI not verified applicability for {cve_id}")
                continue
            if isinstance(release_or_project, Project) or db.is_applicable(
                release_or_project, app
            ):
                start_date = app.get("start_date") or first_published
                patched_date = app.get("patched_at") or app.get("end_date")
                patched = patched_date is not None
                # the first "applicability" targets the release, as the apps are disjoint ranges
                result.get("cve_id").append(cve_id)
                result.get("start_to_patched").append(
                    (patched_date - start_date).days if patched else None
                )
                result.get("start_to_published").append(
                    (cve_published - start_date).days
                )
                result.get("published_to_patched").append(
                    (patched_date - cve_published).days if patched else None
                )
                result.get("patched_date").append(patched_date)
                result.get("version_end").append(app.get("version_end"))
                result.get("exclude_version_end").append(app.get("exclude_end", False))
        return pd.DataFrame(result)

    def __patch_lag_stats(
        self, cve: dict, release_or_project: Release | Project
    ) -> dict:
        """
        Get patch lag as statistics for a CVE
        """
        patch_lag = self.__patch_lag(cve, release_or_project)
        result = {}
        for col in patch_lag.columns:
            if col == "cve_id":
                continue
            try:
                result[col] = {
                    "mean": patch_lag[col].mean(),
                    "median": patch_lag[col].median(),
                    "std": patch_lag[col].std(),
                    "min": patch_lag[col].min(),
                    "max": patch_lag[col].max(),
                }
            except TypeError:
                # if the column is not numeric
                continue
        return result

    def __compute_tech_lag(self, cve: dict, release: Release, constraints: str) -> bool:
        """
        Computes whether a release has "technical lag" for a CVE.
        A technical lag is when a dependency constraint disallows a patch for a CVE.
        """
        if constraints is None:
            # if there are no constraints, there cannot be a technical lag
            return False
        max_version, include_end = get_max_version(constraints)
        if include_end:
            patch = max_version.release[2] if len(max_version.release) > 2 else 0
            patch += 1
            max_version = semver.parse(
                f"{max_version.major}.{max_version.minor}.{patch}"
            )
        if max_version is None:
            return False
        for app in cve.get("applicability", []):
            if db.is_applicable(release, app):
                version_start = app.get("version_start")
                version_end = app.get("version_end")
                excl_start = app.get("exclude_start", False)
                excl_end = app.get("exclude_end", False)
                if version_in_range(
                    max_version, version_start, version_end, excl_start, excl_end
                ):
                    return True
                return False
        return False

    def __model_with_release_data(
        self,
        model: Model,
        main_release: Release,
        release: Release,
        dependency: ReleaseDependency,
    ) -> dict:
        """
        Adds release data to a dictionary
        """
        constraints = dependency.requirements if dependency is not None else None
        if type(model) != dict and not isinstance(model, Model):
            logger.error(f"Incorrect typing logic. Expected 'dict' or 'Model'")
            exit(1)
        result = (
            model_to_dict(model, recurse=False) if isinstance(model, Model) else model
        )
        major = minor = None
        project = (
            main_release.project
            if isinstance(main_release, Release)
            else (main_release if isinstance(main_release, Project) else None)
        )
        project_name = project.name
        project_version = (
            main_release.version
            if isinstance(main_release, Release)
            else (project.latest_release if project is not None else None)
        )
        try:
            version = semver.parse(project_version)
            major = version.major
            minor = version.minor
        except:
            pass
        result["major"] = major
        result["minor"] = minor
        result["nloc_total"] = release.nloc_total
        result["project"] = project_name
        result["project_version"] = project_version
        result["source"] = (
            "Direct" if release.project.name == project_name else "Indirect"
        )
        result["release"] = release.project.name
        result["release_version"] = release.version
        result["release_requirements"] = constraints
        result["inherited_from"] = (
            dependency.inherited_from if dependency is not None else None
        )
        return {k: v for k, v in result.items() if type(v) not in [dict, list]}

    def __model_with_project_data(
        self,
        model: Model,
        project: Project,
        dep_proj: Project,
        dependency: ReleaseDependency,
    ) -> dict:
        """
        Adds release data to a dictionary
        """
        constraints = dependency.requirements if dependency is not None else None
        if type(model) != dict and not isinstance(model, Model):
            logger.error(f"Incorrect typing logic. Expected 'dict' or 'Model'")
            exit(1)
        result = (
            model_to_dict(model, recurse=False) if isinstance(model, Model) else model
        )
        result["project"] = project.name
        result["source"] = "Direct" if dep_proj.name == project.name else "Indirect"
        result["release"] = dep_proj.name
        result["release_requirements"] = constraints
        result["inherited_from"] = (
            dependency.inherited_from if dependency is not None else None
        )
        return {k: v for k, v in result.items() if type(v) not in [dict, list]}

    def df_cves(
        self, project: str | Project, platform: str = "pypi", by_cwe: bool = False
    ) -> pd.DataFrame:
        """
        Returns a DataFrame of CVEs per release, where a "release" refers to a project's release including each dependency's releases.
        Gets the latest release of each dependency before the main project's release's release date.
        """
        project = self.get_project(project, platform)
        project_name = project.name
        release_deps = self.get_releases_with_dependencies(
            project, platform=platform, analysed=False
        )
        df_cves = []
        vulnerabilities = {}
        vulnerabilities[project_name] = self.get_vulnerabilities(
            project, platform=platform
        )
        for releases in release_deps:
            if len(releases) == 0:
                logger.warning(f"Unexpected empty list of releases")
                continue
            # releases are lists of tuples, where each tuple is a release and its dependency
            main_release = releases[0][
                0
            ]  # the first release is the main project's release
            for release, dependency in releases:
                # again, the releases are tuples of the release and whether it is derived from a dependency
                constraints = (
                    dependency.requirements if dependency is not None else None
                )
                release_name = release.project.name
                if release_name not in vulnerabilities:
                    vulnerabilities[release_name] = self.get_vulnerabilities(
                        release.project, platform=platform
                    )
                cves = vulnerabilities.get(release_name, {}).get("cves", None)
                for cve_id in cves:
                    cve = cves[cve_id]
                    apps = cve.get("applicability", [])
                    for app in apps:
                        applies = db.is_applicable(release, app)
                        if applies:
                            # add whether the release has "technical lag"
                            model_dict = self.__model_with_release_data(
                                cve, main_release, release, dependency
                            )
                            model_dict["technical_lag"] = self.__compute_tech_lag(
                                cve, release, constraints
                            )
                            model_dict["version_start"] = app.get("version_start")
                            model_dict["version_end"] = app.get("version_end")
                            patch_lag = self.__patch_lag_stats(cve, release)
                            model_dict.update(patch_lag)
                            if by_cwe:
                                for cwe_id in cve.get("cwes", []):
                                    model_dict["cwe_id"] = cwe_id
                                    df_cves.append(model_dict)
                            else:
                                df_cves.append(model_dict)
                            break
        # ensure uniqueness of crucial columns
        columns = ["release", "release_version", "cve_id"]
        if by_cwe:
            columns.append("cwe_id")
        return pd.DataFrame(df_cves).drop_duplicates(columns)

    def df_cves_per_project(
        self,
        project: str | Project,
        platform: str = "pypi",
        by_cwe: bool = False,
        by_patch: bool = False,
    ) -> pd.DataFrame:
        """
        Returns a DataFrame of CVEs per project, where a "project" refers to a project's release including each dependency's project
        representations.
        """
        project = self.get_project(project, platform)
        main_project = project
        project_name = project.name
        release_deps = self.get_dependencies(project, platform=platform)
        projects = [project]
        project_names = set([project_name])
        dependencies = {}
        for dep in release_deps:
            dep_proj = self.get_project(dep.name, platform=dep.platform)
            if dep_proj is not None and dep_proj.name not in project_names:
                dependencies[dep_proj.name] = dep
                projects.append(dep_proj)
        df_cves = []
        for proj in projects:
            # releases are lists of tuples, where each tuple is a release and its dependency
            # again, the releases are tuples of the release and whether it is derived from a dependency
            projname = proj.name
            dep = dependencies.get(projname, None)
            constraints = dep.requirements if dep is not None else None
            latest_analysed = self.get_release(
                proj, platform=platform, analysed=True, requirements=constraints
            )
            vulns = self.get_vulnerabilities(proj, platform=platform)
            cves = vulns.get("cves", {})
            for cve_id in cves:
                cve = cves[cve_id]
                apps = cve.get("applicability", [])
                app_ranges = applicability_to_requirements(apps)
                model_dict = self.__model_with_project_data(
                    cve, main_project, proj, dep
                )
                model_dict["technical_lag"] = self.__compute_tech_lag(
                    cve, latest_analysed, constraints
                )
                model_dict["applicability"] = app_ranges
                models = []
                if by_cwe:
                    cwes = cve.get("cwes", [])
                    if cwes:
                        for cwe_id in cve.get("cwes", []):
                            mcopy = model_dict.copy()
                            mcopy["cwe_id"] = cwe_id
                            cw = vulns.get("cwes", {}).get(cwe_id, {})
                            for k in cw:
                                if k not in mcopy:
                                    mcopy[k] = cw[k]
                            models.append(mcopy)
                    else:
                        model_dict["cwe_id"] = None
                        models.append(model_dict)
                else:
                    models.append(model_dict)
                patch_lag = (
                    self.__patch_lag(cve, proj)
                    if by_patch
                    else self.__patch_lag_stats(cve, proj)
                )
                for model in models:
                    if by_patch:
                        mcopy = model.copy()
                        for col in patch_lag.columns:
                            if col == "cve_id":
                                continue
                            mcopy[col] = patch_lag[col].values[0]
                        df_cves.append(mcopy)
                    else:
                        for key in patch_lag:
                            for s in patch_lag[key]:
                                model[f"{key}_{s}"] = patch_lag[key][s]
                        df_cves.append(model)
        # ensure uniqueness of crucial columns
        columns = ["project", "release", "cve_id"]
        if by_cwe:
            columns.append("cwe_id")
        return pd.DataFrame(df_cves).drop_duplicates(columns)

    def df_static(
        self,
        project: str | Project,
        platform: str = "pypi",
        with_issues: bool = False,
        only_latest: bool = True,
    ) -> pd.DataFrame:
        release_deps = self.get_releases_with_dependencies(
            project, platform=platform, analysed=True, only_latest=only_latest
        )
        df = []
        for releases in release_deps:
            if len(releases) == 0:
                logger.warning(f"Unexpected empty list of releases")
                continue
            main_release = releases[0][0]
            for release, dependency in releases:
                bandit_report = self.get_bandit_report(release)
                if bandit_report is None:
                    continue
                if with_issues:
                    for issue in bandit_report.issues:
                        severity = issue.severity
                        confidence = issue.confidence
                        issue_dict = self.__model_with_release_data(
                            issue, main_release, release, dependency
                        )
                        issue_dict["severity_score"] = bandit_value_score(severity)
                        issue_dict["test_category"] = (
                            issue.test_id[:2]
                            if issue.test_id and len(issue.test_id) > 2
                            else None
                        )
                        package = issue.package or ""
                        project_name = release.project.name.lower()
                        package = package.lstrip(f"{project_name}.")
                        module = issue.module or ""
                        issue_dict["is_test"] = (
                            package.startswith("test") or "test" in module
                        )
                        issue_dict[
                            "project_package"
                        ] = f"{release.project.name}.{package}"
                        issue_dict["confidence_score"] = bandit_value_score(confidence)
                        issue_dict["score"] = bandit_issue_score(severity, confidence)
                        df.append(issue_dict)
                else:
                    bandit_report = model_to_dict(bandit_report, recurse=False)
                    rel_dict = self.__model_with_release_data(
                        release, main_release, release, dependency
                    )
                    for k in bandit_report:
                        if k not in rel_dict:
                            rel_dict[k] = bandit_report[k]
                    df.append(rel_dict)
        return pd.DataFrame(df)

    def df_timeline(
        self,
        project: str | Project,
        platform: str = "pypi",
        start_date: int | str | dt.datetime = 2019,
        end_date: int | str | dt.datetime = None,
        step: str = "m",
        analysed: bool = False,
        with_issues: bool = False,
    ) -> pd.DataFrame:
        """
        Returns a DataFrame of the timeline of a project's releases
        """
        project = self.get_project(project, platform)
        releases = self.get_releases_with_dependencies(
            project, platform=platform, analysed=analysed
        )
        df = pd.DataFrame()
        source_df = (
            self.df_cves(project, platform, by_cwe=False)
            if not analysed
            else self.df_static(
                project, platform, with_issues=with_issues, only_latest=False
            )
        )
        for date in date_range(start_date, end_date, step):
            date_releases = None
            for rels in releases:
                if len(rels) == 0:
                    logger.warning(f"Unexpected empty list of releases")
                    continue
                main_release = rels[0][0]
                if main_release.published_at.date() <= date.date():
                    date_releases = rels
                    break
            for release, _ in date_releases:
                # for each release in the timeline map the values to these
                latest_analysed = (
                    self.get_release(
                        release.project,
                        platform=platform,
                        analysed=True,
                        requirements=f"<={release.version}",
                    )
                    if release.nloc_total is None
                    else release
                )
                rel_df = source_df[
                    (source_df["release"] == release.project.name)
                    & (source_df["release_version"] == release.version)
                ].copy()
                rel_df["date"] = date
                rel_df["nloc_total"] = (
                    latest_analysed.nloc_total if latest_analysed is not None else None
                )
            df = pd.concat([df, rel_df])
        return df

    def df_tech_lag(
        self, project: str | Project, platform: str = "pypi"
    ) -> pd.DataFrame:
        """
        Returns a DataFrame of technical lag for a project
        """
        project = self.get_project(project, platform)
        releases = self.get_releases(
            project,
            platform=platform,
            descending=False,
            exclude_deprecated=True,
            exclude_nonstable=True,
        )
        df = []
        rel_deps = {}
        vulns = {}
        for i, release in enumerate(releases):
            version = release.version
            deps = self.get_dependencies(project.name, version, platform=platform)
            rel_deps[version] = deps
            for dep in deps:
                if dep.name not in vulns:
                    vulns[dep.name] = self.get_vulnerabilities(
                        dep.name, platform=dep.platform
                    )
        for i, rel in enumerate(releases):
            version = rel.version
            vparsed = semver.parse(version)
            major = vparsed.major
            release_pub = rel.published_at
            deps = rel_deps.get(version, [])
            for dep in deps:
                depname = dep.name
                constraints = dep.requirements
                latest_rel = self.get_release(
                    depname, platform=dep.platform, requirements=constraints
                )
                max_version, include = get_max_version(constraints)
                if max_version:
                    max_constraint = f">{'' if include else '='}{max_version}"
                    newrels = self.get_releases(
                        project.name,
                        platform,
                        requirements=f"{max_constraint},<{major+1}.0.0",
                        descending=False,
                        exclude_deprecated=False,
                        exclude_nonstable=True,
                    )
                    has_solution = False
                    cves = None
                    for cve in vulns.get(depname, {}).get("cves", {}).values():
                        if db.is_applicable(latest_rel, cve.get("applicability", [])):
                            if cves is None:
                                cves = []
                            cves.append(cve.get("cve_id"))
                    for newrel in newrels:
                        # increase the index until a release is found that satisfies the requirements
                        ndeps = rel_deps.get(newrel.version, [])
                        has_same = True
                        new_req = None
                        for ndep in ndeps:
                            new_max, new_incl = get_max_version(ndep.requirements)
                            if ndep.name == depname and (
                                new_max != max_version and include != new_incl
                            ):
                                has_same = False
                                new_req = ndep.requirements
                                break
                        if not has_same:
                            df.append(
                                {
                                    "project": project.name,
                                    "version": version,
                                    "published_at": release_pub,
                                    "time_diff": (
                                        newrel.published_at - release_pub
                                    ).days,
                                    "dependency": depname,
                                    "requirements": constraints,
                                    "next_version": newrel.version,
                                    "next_published_at": newrel.published_at,
                                    "next_version": newrel.version,
                                    "next_requirements": new_req,
                                    "technical_lag": True,
                                    "cves": ", ".join(cves)
                                    if cves is not None
                                    else None,
                                }
                            )
                            has_solution = True
                            break
                    if not has_solution:
                        df.append(
                            {
                                "project": project.name,
                                "version": version,
                                "published_at": release_pub,
                                "dependency": depname,
                                "requirements": constraints,
                                "time_diff": None,
                                "next_version": None,
                                "next_published_at": None,
                                "next_version": None,
                                "next_requirements": None,
                                "cves": ", ".join(cves) if cves is not None else None,
                                "technical_lag": True,
                            }
                        )
        return pd.DataFrame(df)

    def get_cve(self, cve_id: str) -> dict:
        """
        Gets a CVE by its ID
        """
        cve = nvd.CVE.get_or_none(cve_id=cve_id)
        return cve

    def get_bandit(self, project: str | Project, platform: str = "pypi") -> dict:
        """
        Gets a Bandit report for a project
        """
        project = self.get_project(project, platform)
        bandit = self.get_bandit_report(project)
        return bandit

    def _redeps(self, project: str | Project, platform: str = "pypi") -> dict:
        """
        Gets the dependencies of a project
        """
        project = self.get_project(project, platform)
        dependencies = set()
        for release in project.releases:
            deps = release.dependencies
            for dep in deps:
                dep.delete_instance()
                print(f"Deleted {dep.name} for {release.version}")
            release.dependency_count = None
            release.save()
            deps = self.get_dependencies(
                project.name, release.version, platform=platform
            )
            if deps is None:
                continue
            for dep in deps:
                dependencies.add(dep.name)
        return dependencies

    def alldeps(self, project: str | Project, platform: str = "pypi") -> dict:
        """
        Gets all dependencies of a project as a dictionary
        This is done by iterating through all releases and getting their dependencies
        """
        releases = self.get_releases(
            project, platform=platform, exclude_deprecated=False, exclude_nonstable=True
        )
        s = {}
        for rel in releases:
            deps = self.get_dependencies(rel, platform=platform)
            if deps is None:
                continue
            for dep in deps:
                if dep.name not in s:
                    proj = self.get_project(dep.name, platform=dep.platform)
                    s[dep.name] = proj
        return s

    def get_cves(self, vendor: str, product: str = None):
        """
        Gets all CVEs for a project
        """
        if product is None:
            project = self.get_project(vendor)
            vendor = project.vendor
            product = project.product or project.name
        cpes = nvd.CPE.select().where(
            (nvd.CPE.vendor == vendor) & (nvd.CPE.product == product)
        )
        cves = []
        cve_ids = set()
        for cpe in cpes:
            cpe: nvd.CPE = cpe
            node = cpe.node
            cve = node.cve
            if cve.cve_id not in cve_ids:
                cves.append(cve)
                cve_ids.add(cve.cve_id)
        return cves

    def __do_analysis(
        self, is_analysed: bool, prompt: bool, refresh: bool, project_name: str = ""
    ) -> bool:
        """
        Checks if a project should be analysed
        """
        is_analysed = bool(is_analysed)
        if is_analysed:
            return refresh and (
                not prompt
                or input(f"Re-analyse project '{project_name}'? [Y/n] ").lower() != "n"
            )
        return (
            not prompt
            or input(f"Analyse project '{project_name}'? [Y/n] ").lower() != "n"
        )

    def _analyse(
        self,
        project: str | Project,
        *releases: str | Release,
        platform: str = "pypi",
        prompt: bool = True,
        limit: int = None,
        lizard: bool = True,
        bandit: bool = True,
        refresh: bool = False,
    ) -> dict:
        """
        Statically analyses a project's releases

        project: str | Project: The project name or object
        """
        platform = project.platform if type(project) == Project else platform
        project = self.get_project(project, platform)
        analysed = self.get_release(project, platform=platform, analysed=True)
        if not self.__do_analysis(bool(analysed), prompt, refresh, project.name):
            print(f"Skipping {project.name} as it is already analysed")
            return
        # clone the repository
        repo, repo_path = giterate.clone_repo(project, self.__repos_dir, prompt=prompt)
        if repo is None:
            d = self.__analysed_projects[project.platform][project.name]
            logger.error(f"Failed to clone repository: {project.repository_url}")
            d["repo"] = {
                "error": f"failed to clone repository: '{project.repository_url}'"
            }
            self.save_projects()
            return
        release = self.get_release(project, platform=platform)
        version = release.version
        if project.tag_regex is None:
            if giterate.is_semver(version):
                tag_regex = "@semver"
            elif giterate.is_calver(version):
                tag_regex = "@calver"
            update = True
            if prompt:
                print(f"Detected tag regex: {tag_regex} (e.g., {version})")
                if input("Update? [Y/n] ").lower() == "n":
                    update = False
            if update:
                project.tag_regex = tag_regex
                project.save()
        giterate.run_analysis(
            project,
            self.__repos_dir,
            *releases,
            limit=limit,
            lizard=lizard,
            bandit=bandit,
        )

    def get_all_deps(self, project: str | Project, platform: str = "pypi") -> dict:
        """
        Gets all dependencies of a project
        """
        project = self.get_project(project, platform)
        results = []
        processed = set()
        for release in project.releases:
            deps = self.get_dependencies(project, release.version, platform=platform)
            if deps is None:
                continue
            for dep in deps:
                if dep.name in processed:
                    continue
                print(
                    f"Found dependency {dep.name} for {project.name}:{release.version}"
                )
                processed.add(dep.name)
                depproj = self.get_project(dep.name, platform=dep.platform)
                results.append(depproj)
        return results

    def df_time(self, *projects: str | Project, platform: str = "pypi") -> pd.DataFrame:
        """ """
        df = []
        if not projects:
            projects = Project.select().where(Project.platform == platform)
        for project in projects:
            project_name = project.name if type(project) == Project else project
            project = self.get_project(project_name, platform=platform)
            release = self.get_release(project, analysed=True)
            if release is None:
                logger.warning(
                    f"Skipping '{project_name}' as it has no analysed release"
                )
                continue
            time_lizard = release.time_to_analyse
            bandit = release.bandit_report.first()
            time_bandit = None
            if bandit:
                time_bandit = bandit.time_to_analyse
            tags = project.release_tags
            df.append(
                {
                    "project": project_name,
                    "version": release.version,
                    "release_tags": tags,
                    "published_at": release.published_at,
                    "nloc": release.nloc_total,
                    "files": release.counted_files,
                    "time_lizard": time_lizard,
                    "time_bandit": time_bandit,
                    "time_total": time_lizard + (time_bandit or 0)
                    if time_lizard is not None
                    else None,
                }
            )
        df = sorted(df, key=lambda x: x["nloc"])
        return pd.DataFrame(df)

    def _analyse_all(
        self,
        project: str | Project,
        platform: str = "pypi",
        prompt: bool = True,
        limit: int = None,
        refresh: bool = False,
    ) -> dict:
        """
        Statically analyses a project's dependencies

        project: str | Project: The project name or object
        """
        project = self.get_project(project, platform)
        ag._analyse(
            project, platform=platform, prompt=prompt, limit=limit, refresh=refresh
        )
        deps = self.get_dependencies(project, platform=platform)
        for dep in deps:
            rels = self.get_releases(
                dep.name, platform=dep.platform, requirements=dep.requirements
            )
            self._analyse(
                dep.name,
                *rels,
                platform=project.platform,
                prompt=prompt,
                limit=limit,
                refresh=refresh,
            )

    def _match_vendors(
        self, product_or_project: str | Project, platform: str = "pypi"
    ) -> List[tuple]:
        """
        Matches vendors for a project or product based on CPEs

        product_or_project: str | Project: The project name or object
        returns: List[tuple]: A list of tuples of vendors and an example CVE
        """
        if product_or_project is None:
            logger.error("No project or product provided")
            return None
        vendors = set()
        platform = (
            product_or_project.platform
            if type(product_or_project) == Project
            else platform
        )
        product = (
            product_or_project
            if type(product_or_project) == str
            else (product_or_project.product or product_or_project.name)
        )
        if "-" in product:
            product = product.replace("-", "_")
        product = product.lower()
        cpes = nvd.CPE.select().where(nvd.CPE.product == product)
        results = []
        for cpe in cpes:
            if cpe.vendor in vendors:
                continue
            vendors.add(cpe.vendor)
            results.append((cpe.vendor, cpe.node.cve))
        return sorted(list(results), key=lambda x: x[0])

    def _search_vendor(
        self, project: Project | str, platform: str = "pypi"
    ) -> List[str]:
        """
        Checks if there are any matching CPEs for a project's URLs
        Prompts the user to update the project's vendor and product if a match is found

        project: Project | str: The project object or name
        platform: str: The platform
        """
        project = self.get_project(project)
        # starts with repository URL
        repo_url = project.repository_url
        vendors = ["python"] if platform == "pypi" else []
        if project.vendor:
            vendors.append(project.vendor)
        products = [project.name, re.sub(r"\d$", "", project.name)]
        suffixes = ["", "project", "_project", "projects", "_projects"]
        if repo_url:
            owner, reponame = giterate.get_owner_project(repo_url)
            if owner:
                for suffix in suffixes:
                    vendors.append(f"{owner}{suffix}")
                products.append(reponame)
        if project.homepage:
            ven = homepage_to_vendor(project.homepage)
            if ven:
                for suffix in suffixes:
                    vendors.append(f"{ven}{suffix}")
        for vendor, product in itertools.product(vendors, products):
            vendor = vendor.lower()
            product = product.lower()
            trial = f"{vendor}:{product}"
            print(f"Searching for {trial}")
            cpes = nvd.CPE.select().where(
                (nvd.CPE.vendor == vendor) & (nvd.CPE.product == product)
            )
            if cpes.count() > 0:
                print(f"Found {cpes.count()} CPEs for '{trial}'")
                first = cpes.first()
                cve: nvd.CVE = first.node.cve
                print(f"Example CVE: {cve.description}")
                if input("Update? [Y/n] ").lower() != "n":
                    project.vendor = vendor
                    project.product = product
                    project.save()
                    return None
        return None

    def _search_vendor_all(
        self, project: Project | str, platform: str = "pypi"
    ) -> List[str]:
        """
        Searches for vendors and products for all projects
        """
        project = self.get_project(project, platform=platform)
        self._search_vendor(project, platform=platform)
        deps = self.get_all_deps(project, platform=platform)
        for dep in deps:
            print(f"Searching for {dep.name}")
            self._search_vendor(dep, platform=dep.platform)

    def _versions(self, project: str | Project, platform: str = "pypi") -> dict:
        """
        Gets the versions of a project
        """
        project = self.get_project(project, platform)
        versions = set()
        for release in project.releases:
            versions.add(release.version)
        return sorted(list(versions))


if __name__ == "__main__":
    # For the purpose of loading in interactive shell and debugging
    # e.g., py -i depsec/Aggregator.py
    parser = argparse.ArgumentParser()
    parser.add_argument("-p", "--project", type=str, help="The project name")
    parser.add_argument(
        "-a",
        "--analyse",
        action="store_true",
        help="Analyse the project",
        default=False,
    )
    parser.add_argument(
        "-A",
        "--analyse-all",
        action="store_true",
        help="Analyse the project with all dependencies",
        default=False,
    )
    parser.add_argument(
        "--prompt", action="store_true", help="Prompt for user input", default=False
    )
    parser.add_argument(
        "-r", "--refresh", action="store_true", help="Refresh the analysis"
    )
    parser.add_argument(
        "-l", "--limit", type=int, help="Limit the number of releases to analyse"
    )
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    parser.add_argument(
        "-v", "--vendors", action="store_true", help="Search for vendors", default=False
    )
    parser.add_argument(
        "-d",
        "--list-dependencies",
        action="store_true",
        help="List dependencies",
        default=False,
    )
    logger.remove()
    args = parser.parse_args()
    logger.add(
        sys.stdout,
        colorize=True,
        backtrace=True,
        diagnose=True,
        level="DEBUG" if args.debug else "INFO",
    )
    ag = Aggregator("config.yml", debug=True)
    ag.load_projects()
    project = ag.get_project(args.project) if args.project else None
    rel = ag.get_release(project, analysed=True) if project else None
    if args.vendors:
        projects = [project]
        deps = ag.get_all_deps(project)
        for proj in projects + deps:
            print(f"Checking vendors for {proj.name}")
            vendors = ag._match_vendors(proj)
            if not vendors:
                continue
            homepage = proj.homepage.lower() if proj.homepage else None
            repository = proj.repository_url.lower() if proj.repository_url else None
            might_be = None
            for i, v_cve in enumerate(vendors):
                v, cve = v_cve
                if homepage and v.lower() in homepage:
                    might_be = i
                    break
                if repository and v.lower() in repository:
                    might_be = i
                    break
            print()
            print(f"------------{proj.name}--------------")
            is_done = False
            for i, v_cve in enumerate(vendors):
                v, cve = v_cve
                if v == proj.vendor:
                    is_done = True
                    break
                print(
                    f"{i+1}. {v} ({cve.cve_id})",
                    end=" <--\n" if i == might_be else "\n",
                )
                print(f"\tDescription: {cve.description}")
            if is_done:
                print(f"Vendor '{proj.vendor}' already set for '{proj.name}'")
                continue
            inp = input(f"Update '{proj.name}'? [Y/n/number] ")
            if inp.lower() == "n":
                continue
            if inp.isdigit():
                inp = int(inp) - 1
            elif inp == "-":
                proj.vendor = "-"
                proj.save()
                continue
            else:
                inp = might_be if might_be else 0
            if 0 <= inp < len(vendors):
                vendor, cve = vendors[inp]
                print(f"\nUpdating '{proj.name}' with vendor '{vendor}'")
                proj.vendor = vendor
                proj.save()
    if args.list_dependencies:
        projects = [project]
        deps = ag.get_all_deps(project)
        print(f"------------{project.name}--------------")
        projects = sorted(projects + (deps if deps else []), key=lambda x: x.name)
        for proj in projects:
            cves = ag.get_cves(proj)
            cves = ", ".join([cve.cve_id for cve in cves])
            cves = f": {cves}" if cves else ""
            print(f"\t{proj.name}{cves}")
        ag.save_projects()
    if args.analyse:
        ag._analyse(project, prompt=args.prompt, refresh=args.refresh, limit=args.limit)
    elif args.analyse_all:
        ag._analyse_all(
            project, prompt=args.prompt, refresh=args.refresh, limit=args.limit
        )
