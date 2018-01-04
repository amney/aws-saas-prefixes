import logging
import requests
import json
from tetpyclient import RestClient, MultiPartOption
from tempfile import NamedTemporaryFile
from csv import writer
from collections import defaultdict
import click
from urllib3 import disable_warnings
disable_warnings()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%m/%d/%Y %I:%M:%S %p')
logger = logging.getLogger("AWS Visibility")


@click.group()
@click.option(
    '--url',
    '-u',
    metavar="https://cluster.fqdn.com",
    help="Cluster URL",
    required=True)
@click.option(
    '--credentials',
    '-c',
    metavar="CREDS_FILE",
    type=click.Path(
        exists=True, dir_okay=True),
    help="Credentials file [default=api_credentials.json]",
    default="api_credentials.json")
@click.option(
    '--include',
    '-i',
    multiple=True,
    default=None,
    metavar="SERVICE",
    help='service to allow [multiple supported]')
@click.option(
    '--exclude',
    '-e',
    default=None,
    multiple=True,
    metavar="SERVICE",
    help='service to disallow [multiple supported]')
@click.option(
    '--region',
    '-r',
    default=None,
    multiple=True,
    metavar="region-1",
    help='region to allow [multiple supported]')
@click.option(
    '--no-verify',
    is_flag=True,
    default=False,
    help='do not verify cluster HTTPS/TLS certificate')
@click.pass_context
def app(ctx,
        url,
        credentials,
        no_verify=True,
        include=None,
        exclude=None,
        region=None):
    """
    AWS Service Visibility Toolbox

    By default this tool operates on all regions and services.

    You may reduce the scope by utilising the options
    --includes, --excludes and --regions
    """
    ctx.obj = {}
    ctx.obj["includes"] = include
    ctx.obj["excludes"] = exclude
    ctx.obj["regions"] = region
    ctx.obj["api"] = RestClient(
        url, credentials_file=credentials, verify=not no_verify)
    pass


def filter_amazon(services):
    if len(services) > 1 and 'AMAZON' in services:
        services.remove('AMAZON')
        return services
    return services


def merge_prefixes(payload):
    """
    Converts the AWS services JSON payload into a list of tuples.
    Arguments:
        payload => JSON object
    Returns:
        A list of tuples formatted as (ip_prefix, regions, services)
        ip_prefix => CIDR prefix
        regions   => list of all regions the prefix is associated with
        services  => list all services the prefix is associated with
    """

    regions, services = {}, {}

    for prefix in payload['prefixes']:
        ip_prefix = prefix['ip_prefix']

        _regions = regions.setdefault(ip_prefix, [])
        _regions.append(prefix['region'])
        regions[ip_prefix] = _regions

        _services = services.setdefault(ip_prefix, [])
        _services.append(prefix['service'])
        services[ip_prefix] = _services

    merged = []

    for prefix in payload['prefixes']:
        ip_prefix = prefix['ip_prefix']
        prefix_tuple = (ip_prefix, regions[ip_prefix], services[ip_prefix])
        merged.append(prefix_tuple)

    return merged


@app.command()
@click.option(
    '--vrf',
    '-v',
    metavar="VRF",
    required=True,
    help='VRF to upload annotations under')
@click.pass_context
def annotations(ctx, vrf, includes=None, excludes=None, regions=None):
    """
    Update cluster annotations with latest data from AWS
    """
    includes = ctx.obj.get("includes", includes)
    excludes = ctx.obj.get("excludes", regions)
    regions = ctx.obj.get("regions", regions)

    api = ctx.obj['api']

    r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    payload = r.json()

    if not includes:
        includes = []

    if not excludes:
        excludes = []

    if not regions:
        regions = []

    def valid_region(_regions):
        if not regions:
            return True

        for region in regions:
            if region in _regions:
                return True

    def valid_service(_services):
        for exclude in excludes:
            if exclude in _services:
                return False

        if not includes:
            return True

        for include in includes:
            if include in _services:
                return True

    filtered = []

    for ip_prefix, _regions, _services in merge_prefixes(payload):
        if valid_region(_regions):
            if valid_service(_services):
                _services = filter_amazon(_services)
                filtered.append(
                    (ip_prefix, 'AWS', _regions[0], _services[0]))

    annotate(api, vrf, filtered)


def annotate(api, vrf, prefixes):
    logger.info("Writing Annotations (Total: %s) " % len(prefixes))
    with NamedTemporaryFile() as tf:
        wr = writer(tf)
        wr.writerow(
            ('IP', 'SaaS Provider', 'SaaS Region', 'SaaS Component'))
        for pfx in prefixes:
            wr.writerow(pfx)
        tf.seek(0)

        req_payload = [MultiPartOption(key='X-Tetration-Oper', val='add')]
        resp = api.upload(tf.name, '/assets/cmdb/upload/%s' % vrf, req_payload)
        if resp.ok:
            logger.info("Uploaded Annotations")
        else:
            logger.error("Failed to Upload Annotations: %s", resp.text)


def extract_regions_and_services(payload):
    regions = defaultdict(set)

    for prefix in payload['prefixes']:
        regions[prefix['region']].add(prefix['service'])

    return regions


@click.option(
    '--root_scope_id',
    required=True,
    help="Root Scope ID (e.g. Default)",
    metavar="ID",
    prompt=True)
@app.command()
def create_scopes(ctx,
                  root_scope_id,
                  includes=None,
                  excludes=None,
                  regions=None):
    """
    Create AWS scope tree (only run this once)
    """
    api = ctx.obj['api']
    includes = ctx.obj.get("includes", includes)
    excludes = ctx.obj.get("excludes", regions)
    regions = ctx.obj.get("regions", regions)

    r = requests.get('https://ip-ranges.amazonaws.com/ip-ranges.json')
    payload = r.json()

    if not includes:
        includes = []

    if not excludes:
        excludes = []

    if not regions:
        regions = []

    def valid_region(_region):
        if not regions:
            return True

        for region in regions:
            if region == _region:
                return True

    def valid_service(_service):
        for exclude in excludes:
            if exclude == _service:
                return False

        if not includes:
            return True

        for include in includes:
            if include == _service:
                return True

    regions_and_services = extract_regions_and_services(payload)
    service_scope_id = create_service_scope(api, root_scope_id)
    for region, services in regions_and_services.items():
        if valid_region(region):
            print region
            region_scope_id = create_region_scope(api, service_scope_id,
                                                  region)
            for service in services:
                if valid_service(service):
                    print '', service
                    create_component_scope(api, region_scope_id, service)


def create_service_scope(api, root_scope_id):
    req_payload = {
        "short_name": "AWS",
        "short_query": {
            "type": "eq",
            "field": "user_SaaS Provider",
            "value": "AWS"
        },
        "parent_app_scope_id": root_scope_id
    }
    resp = api.post('/app_scopes', json_body=json.dumps(req_payload))
    return resp.json()["id"]


def create_region_scope(api, service_scope_id, region):
    req_payload = {
        "short_name": region,
        "short_query": {
            "type": "eq",
            "field": "user_SaaS Region",
            "value": region
        },
        "parent_app_scope_id": service_scope_id
    }
    resp = api.post('/app_scopes', json_body=json.dumps(req_payload))
    return resp.json()["id"]


def create_component_scope(api, region_scope_id, service):
    req_payload = {
        "short_name": service,
        "short_query": {
            "type": "eq",
            "field": "user_SaaS Component",
            "value": service
        },
        "parent_app_scope_id": region_scope_id
    }
    api.post('/app_scopes', json_body=json.dumps(req_payload))


if __name__ == '__main__':
    app()
