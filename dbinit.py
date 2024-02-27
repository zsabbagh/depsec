import sqlite3, os
from sqlite3 import Error
from argparse import ArgumentParser

# This script creates a SQLite database and tables for the project
# It is a one-time setup script

parser = ArgumentParser()
parser.add_argument("file", help="Path to the SQLite database file", default="projects.db")
args = parser.parse_args()

def create_connection(db_file):
    """
    Create a database connection to a SQLite database
    """
    conn = None
    try:
        print(f"Creating SQLite database: {db_file}")
        conn = sqlite3.connect(db_file)
        print(f"SQLite database created: {db_file}")
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()

def create_table(db_file, create_table_sql):
    """
    Create a table from the create_table_sql statement
    """
    try:
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute(create_table_sql)
        conn.commit()
        print("Table created successfully")
    except Error as e:
        print(e)
    finally:
        if conn:
            conn.close()

if __name__ == '__main__':

    database = args.file.split("/")[-1]
    if not database.endswith(".db"):
        database = f"{database}.db"
    print(f"Database file: {database}")
    # Create directory data/ if it does not exist
    if not os.path.exists('data'):
        os.makedirs('data')

    # Create a database connection and table
    database = f"data/{database}"
    create_connection(database)

    # Project table, main table for projects
    projects_table = """CREATE TABLE IF NOT EXISTS projects (
                                        id INTEGER PRIMARY KEY,
                                        name TEXT NOT NULL,
                                        project_name TEXT NOT NULL,
                                        language TEXT,
                                        platform TEXT,
                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                                    );"""

    # Release table references the project table
    releases_table = """CREATE TABLE IF NOT EXISTS releases (
                                        id INTEGER PRIMARY KEY,
                                        project_id INTEGER NOT NULL,
                                        published_at TIMESTAMP,
                                        version_number TEXT NOT NULL,
                                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                        FOREIGN KEY (project_id) REFERENCES projects (id)
                                   );"""
    
    # Release dependencies table references the release table
    release_dependencies_table = """CREATE TABLE IF NOT EXISTS release_dependencies (
                                                release_id INTEGER NOT NULL,
                                                name TEXT NOT NULL,
                                                platform TEXT,
                                                requirements TEXT,
                                                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                                                FOREIGN KEY (release_id) REFERENCES releases (id)
                                            );"""
    
    release_repos_table = """CREATE TABLE IF NOT EXISTS release_repos (
                                release_id INTEGER NOT NULL,
                                repo_url TEXT NOT NULL,
                                FOREIGN KEY (release_id) REFERENCES releases (id)
                            );"""
    
    create_table(database, projects_table)
    create_table(database, releases_table)
    create_table(database, release_dependencies_table)
    create_table(database, release_repos_table)

