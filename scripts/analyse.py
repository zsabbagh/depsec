import sys, argparse, re
from depsec.aggregator import Aggregator

parser = argparse.ArgumentParser(description='Analyse CVEs to add information to the database')
parser.add_argument('config', type=str, help='The configuration file to use')
parser.add_argument('-p', '--project', type=str, help='The project to analyse')
parser.add_argument('-s', '--skip', help='Skip already analysed CVEs', action='store_true')

args = parser.parse_args()

ag = Aggregator(args.config)

project = ag.get_project(args.project)
release = ag.get_release(project)
dependencies = ag.get_dependencies(release)
projects = [project]

for dependency in dependencies:
    dep_project = ag.get_project(dependency.name)
    if dep_project:
        projects.append(dep_project)

def get_package(project_name, part, splitter=None):
    if not part:
        return None
    project_name = project_name.lower()
    part = part.lower()
    if part.startswith(project_name + '.'):
        part = part.lstrip(project_name + '.')
    if '.' not in part:
        return f"{project_name}.{part}" if not part.startswith(project_name) else part
    part = part.split('.')
    splitter = splitter or -1
    part = '.'.join(part[:splitter])
    return f"{project_name}.{part}" if not part.startswith(project_name) else part

for project in projects:

    parts = set()

    vulns = ag.get_vulnerabilities(project)

    project_name = project.name.lower()

    regex = rf"(({project_name}|[a-z]\w+)(\.\w+)+)"
    total_vulns = len(vulns.get('cves'))
    index = 0
    for cve_id in vulns.get('cves'):
        cve = ag.get_cve(cve_id)
        print(f"-----------------------------------------")
        print(f'Analysing {cve_id} ({index+1}/{total_vulns})')
        index += 1
        print(f"-----------------------------------------")
        print(f"Description: {cve.description}")
        print()
        if cve.part:
            print(f"Part: {cve.part}")
            if args.skip:
                print(f"Skipping...")
                parts.add(cve.part)
                continue
            skip = input("Skip? (Y/n): ").lower()
            if skip != 'n':
                parts.add(cve.part)
                continue
        print()
        detected = re.findall(regex, cve.description, re.IGNORECASE)
        part = None
        if detected:
            print(f"\n--> DETECTED -->")
            auto = None
            for i, match in enumerate(detected):
                print(f"{i+1}. {match[0]}", end='')
                for p in parts:
                    if match[0].lstrip(project_name + '.') == p.lstrip(project_name + '.'):
                        auto = p
                        print(f" (auto)")
                        break
                print()
            select = input(f"Select a match or press enter to skip: ")
            if select == '' and auto:
                part = auto
            else:
                try:
                    if ':' in select:
                        select, splitter = tuple(select.split(':'))
                    select = int(select)
                    detected = detected[select-1]
                    part = detected[0]
                    try:
                        splitter = int(splitter)
                    except:
                        splitter = 1
                    part = get_package(project_name, part, splitter)
                except:
                    pass
        if not part:
            part = input('What part of the software is affected?\n')
            if part != '-':
                part = get_package(project_name, part)
        if part:
            update = input(f"Update part to {part}? (y/n): ")
            if update.lower() != 'n':
                cve.part = part
                cve.save()
                print()
                print(f"----> Updated part: {cve.part}")
                print()
        else:
            print("No part provided")