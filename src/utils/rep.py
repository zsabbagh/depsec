import pandas as pd, numpy as np
# This file includes functions to generate "reports" of statistics of the DataFrame

def _cve_severity(df: pd.DataFrame) -> pd.DataFrame:
    """
    The provided DF provides the distribution of severity levels
    """
    df = df.drop_duplicates(subset=['cve_id', 'project', 'release']).copy()
    df_critical = df[df['cvss_base_score'] >= 9.0]
    df_high = df[(df['cvss_base_score'] >= 7.0) & (df['cvss_base_score'] < 9.0)]
    df_medium = df[(df['cvss_base_score'] >= 4.0) & (df['cvss_base_score'] < 7.0)]
    df_low = df[df['cvss_base_score'] < 4.0]
    results = {
        'critical': df_critical,    
        'high': df_high,
        'medium': df_medium,
        'low': df_low,
    }
    results = { key: results[key] for key in results if len(results[key]['cve_id']) > 0 }
    if len(results) > 1:
        results['all'] = df
    return results

def _compute(df: pd.DataFrame, total: int, key: str, **kpis) -> pd.DataFrame:
    """
    The provided DF provides the distribution of the time taken to patch a CVE
    """
    severity = {
        kpi: _cve_severity(df[kpis[kpi]])
        for kpi in kpis
    }
    results = {}
    for kpi in severity:
        results[kpi] = {}
        for sev in severity[kpi]:
            df_tmp = severity[kpi][sev]
            cve_count = df_tmp['cve_id'].nunique()
            if cve_count == 0:
                # skip empty dataframes
                continue
            elif cve_count == 1:
                results[kpi][sev] = {
                    'count': 1,
                    'cve_id': df_tmp['cve_id'].values[0],
                    'percentage': f"{100 / (total or 1)}%",
                    'value': df_tmp[key].values[0],
                }
            else:
                results[kpi][sev] = {
                    'count': cve_count,
                    'cve_ids': sorted(df_tmp['cve_id'].values),
                    'percentage': f"{df_tmp['cve_id'].nunique() / (total or 1):.2%}%",
                    'mean': df_tmp[key].mean(),
                    'std': df_tmp[key].std(),
                    'min': df_tmp[key].min(),
                    '25%': df_tmp[key].quantile(0.25),
                    '50%': df_tmp[key].quantile(0.50),
                    '75%': df_tmp[key].quantile(0.75),
                    'max': df_tmp[key].max(),
                }
    if len(results) == 1:
        return results[list(results.keys())[0]]
    return results

def _split_by_project(df: pd.DataFrame) -> pd.DataFrame:
    """
    The provided DF provides the distribution of the time taken to patch a CVE
    """
    df = df.drop_duplicates(subset=['cve_id', 'project', 'release']).copy()
    return {
        project: df[df['project'] == project]
        for project in df['project'].unique()
    }

def _split_by_source(df: pd.DataFrame) -> pd.DataFrame:
    """
    The provided DF provides the distribution of the time taken to patch a CVE
    """
    df = df.drop_duplicates(subset=['cve_id', 'project', 'release']).copy()
    return {
        source: df[df['source'] == source]
        for source in df['source'].unique()
    }

def _split_by_release(df: pd.DataFrame) -> pd.DataFrame:
    """
    The provided DF provides the distribution of the time taken to patch a CVE
    """
    df = df.drop_duplicates(subset=['cve_id', 'project', 'release']).copy()
    return {
        release: df[df['release'] == release]
        for release in df['release'].unique()
    }

def cve_report(df: pd.DataFrame) -> dict:
    """
    Generate a report of the provided DataFrame
    """
    result = _split_by_project(df)
    for project in result:
        df_project = result[project]
        result[project] = res = {}
        cves_project = df_project['cve_id'].nunique()
        res['sources'] = _split_by_source(df_project)
        for source in res['sources']:
            df_source = res['sources'][source]
            cves_source = df_source['cve_id'].nunique()
            res['sources'][source] = _split_by_release(df_source)
            if 'cve_id' not in df_source:
                continue
            r = res['sources'][source]
            for release in r:
                df_release = r[release]
                r[release] = {}
                cves_release = df_release['cve_id'].nunique()
                r[release]['cves_total'] = cves_release
                r[release]['cves_percentage'] = f"{cves_release / (cves_project or 1):.2%}%"
                positive_patch = df_release['published_to_patched'] >= 0
                negative_patch = df_release['published_to_patched'] < 0
                r[release]['patch_time'] = _compute(df_release, cves_project, 'published_to_patched', positive_patch=positive_patch, negative_patch=negative_patch)
                severities = _cve_severity(df_release)
                r[release]['severities'] = sevs = {}
                for severity in severities:
                    count = severities[severity]['cve_id'].nunique()
                    sevs[severity] = count
                    sevs[f"{severity}_percentage"] = f"{count / (cves_release or 1):.2%}%"
            res['sources'][source]['cves_total'] = cves_source
            res['sources'][source]['cves_percentage'] = f"{cves_source / (cves_project or 1):.2%}%"
        result[project]['cves_total'] = cves_project
    return result