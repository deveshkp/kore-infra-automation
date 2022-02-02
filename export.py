#!/usr/bin/env python3
"""

Provides deployment functions for Kore Chatbot APIs.

Script usage: This module is for Exporting Chatbot from Kore BotBuilder.

   python Kore_export.py
"""
import hashlib
import logging
import shutil
import tempfile
import zipfile
import argparse
import os
from datetime import datetime

import sys
from enum import Enum
import yaml
import requests
import urllib3
import jwt
import time

HTTP_RESP_CODE = ' HTTP response code: '
HTTP_RESP_MSG = ' HTTP response message: '

verbose = False
urllib3.disable_warnings()

# ---------------------Logging Config-------------------------------------
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='export.log',
                    filemode='w')


def _log_Error(method_name, error_msg):
    logger = logging.getLogger(method_name)
    logger.error("An error occured in: " + method_name)
    logger.error("Error message: " + error_msg, exc_info=True)


class Environment(Enum):
    UAT = 1
    PERF = 2
    QA = 3
    PROD = 4


class EnvironmentLevel(Enum):
    UAT = 1
    PERF = 2
    QA = 3
    PROD = 4


def _set_verbose(verbose_flag=True):
    """Set global verbose flag.

    Args:
        verbose_flag: A boolean to enable/disable verbose messages. Default is True.

    Returns: None
    """
    global verbose
    verbose = verbose_flag


def _yaml_file_to_dict(yaml_file):
    """Read YAML file and return a dictionary.

    Args:
        yaml_file: The YAML file name to read.

    Returns:
        yaml_dict: A dictionary representation of the YAML file.
    """
    with open(yaml_file, 'r') as ymlfile:
        yaml_dict = yaml.safe_load(ymlfile)

    return yaml_dict


def _get_config():
    """Load configurations from yaml config file.

    Returns:
        configs: An dictionary with configurations.
    """
    config_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(config_dir, 'config.yaml')
    configs = _yaml_file_to_dict(config_path)

    return configs


config = _get_config()


def hash_file(filename: str, blocksize: int = 4096) -> str:
    hsh = hashlib.md5()
    with open(filename, "rb") as f:
        while True:
            buf = f.read(blocksize)
            if not buf:
                break
            hsh.update(buf)
    return hsh.hexdigest()


def sha1_file(filename: str, blocksize: int = 4096) -> str:
    sha1 = hashlib.sha1()
    with open(filename, "rb") as f:
        while True:
            buf = f.read(blocksize)
            if not buf:
                break
            sha1.update(buf)
    return sha1.hexdigest()


def _build_credentials_dict(sub, client_id, secret_key):
    """Set environment enumeration value.

    Args:
        subject: Argument Passed through command
        client_id: Argument Passed through command
        secret_key:Argument Passed through command

    Returns:
        credentials:
    """
    credentials = {
        'sub': sub,
        'client_id': client_id,
        'secret_key': secret_key
    }

    return credentials


def _get_jwt_token(credentials):
    """Add description here.

    Args: Credentials as a dict object passed to this function

    Returns:
    """
    subject = {
        'sub': credentials['sub'],
        'appId': credentials['client_id']
    }
    jwt_token = jwt.encode(subject, credentials['secret_key'], algorithm='HS256')

    if verbose:
        print('Completed: get_jwt_token. env: ')

    return jwt_token


def _get_list_of_bots(url, jwt_token):
    """
       This method is for getting list of bots in platform.
    """
    headers = {'auth': jwt_token, "content-type": "application/json"}
    response = requests.get(url + '/api/public/bots?offset=0&limit=50', headers=headers, verify=False)

    if response.status_code == 200:
        json_response = response.json()
    else:
        raise RuntimeError('Unable to get list of bots : '
                           + HTTP_RESP_CODE + str(response.status_code)
                           + HTTP_RESP_MSG + response.text)

    return json_response


def _get_bot_id(url, jwt_token, bot_name):
    """
        it returns the bot id for specific bot.
    """
    data = _get_list_of_bots(url, jwt_token)
    exists = any(el['name'] == bot_name for el in data['bots'])
    if exists:
        bot_id = [obj for obj in data['bots'] if obj['name'] == bot_name][0]['_id']
        logging.info("getting bot id")
    else:
        raise RuntimeError('Unable to find bot id')

    return bot_id


def export_bot(url, jwt_token, bot_id):
    """" Initiate the export process """
    headers = {'auth': jwt_token, "content-type": "application/json"}
    data = {"exportType": "published"}

    response = requests.post(url, json=data, headers=headers, verify=False)

    if response.ok:
        json_response = response.json()
    else:
        raise RuntimeError('Unable to get the export of bot: '
                           + HTTP_RESP_CODE + str(response.status_code)
                           + HTTP_RESP_MSG + response.text)

    if verbose:
        print('Completed: export_bot : ' + json_response['status'])

    return response


def export_bot_status(url, jwt_token, bot_id):
    """

    Args:
        url: url from config.yaml for env
        jwt_token: get_jwt_token function returns in string
        bot_id: get_bot_id function returns bot id in string

    Returns: link to download bot zip

    """
    new_url = url + "/api/public/bot/" + bot_id + "/export"
    response = export_bot(new_url, jwt_token, bot_id)
    # print("Checking the export status : " + new_url)
    time.sleep(10)
    headers = {'auth': jwt_token, "content-type": "application/json"}
    if response.ok:
        response = requests.get(new_url + "/status", headers=headers, verify=False)
        response = response.json()
        download_url = response['downloadURL']
        link = url + download_url.rsplit('8081', 1)[1]
        # print(link)
    else:
        raise RuntimeError('Unable to get the status : '
                           + HTTP_RESP_CODE + str(response.status_code)
                           + HTTP_RESP_MSG + response.text)

    if verbose:
        print('Completed: export_bot_status : ' + response['status'])

    return link


def downloadWithProgress(link, outpath):
    """

    Args:
        link: Link to download zip file.
        outpath: destination directory to keep the zip file.

    Returns: None

    """
    print("Downloading %s" % link)
    response = requests.get(link, stream=True, verify=False)
    total_length = response.headers.get('content-length')

    with open(outpath, "wb") as outf:
        sys.stdout.write("\rDownload progress: [{}]".format(' ' * 50))
        sys.stdout.flush()

        if total_length is None:  # no content length header
            outf.write(response.content)
        else:
            dl = 0
            total_length = int(total_length)
            for data in response.iter_content(chunk_size=1024):
                dl += len(data)
                outf.write(data)
                done = int(50 * dl / total_length)
                sys.stdout.write("\rDownload progress: [{}{}]".format('=' * done, ' ' * (50 - done)))
                sys.stdout.flush()
    sys.stdout.write("\n")
    outf.close()


def downloadBot(link, bot_name, output_dir):
    try:
        archivePath = "{}/{}.zip".format(output_dir, bot_name)
        downloadWithProgress(link, archivePath)
        print("Completed: downloadBot " + output_dir + "/" + bot_name + ".zip")
        file_path = output_dir + "/" + bot_name + ".zip"

    except Exception as e:
        print("error downloading and decompressing example data: {}".format(e))

    return file_path


def _upload_artifacts(file_path, bot_name):
    """

    Args:
        file_path: Source file path
        bot_name : bot name

    Returns:

    """
    file_name = os.path.basename(file_path)

    artifactory_url = config['artifactory']['url'] + bot_name
    artifactory_username = config['artifactory']['user_name']
    api_key = config['artifactory']['api_key']
    content_type = config['artifactory']['content_type']
    version = datetime.now().strftime("%Y%m%d-%H%M%S") + "-SNAPSHOT"
    url = artifactory_url + '/' + version + '/' + file_name
    headers = {'content-type': content_type,
               'X-Checksum-Md5': hash_file(file_path),
               'X-Checksum-Sha1': sha1_file(file_path)}
    with open(file_path, 'rb') as f:
        r = requests.put(url,
                         auth=(artifactory_username,
                               api_key),
                         data=f,
                         headers=headers, verify=False)

    # check for success
    if r.status_code != 201:
        print("Upload to Artifactory failed")
        upload_status = False
    else:
        print(r.json()['downloadUri'])  # download url for this new artifact
        upload_status = True

    return upload_status


def run_export_process(env, credentials, bot_name, output_dir, verbose_flag=True):
    """

    Args:
        env: target environment from where the bot is being exported.
        credentials: its dict format which you get form build dict function.
        bot_name: the bot being exported from.
        verbose_flag: default is true for debugging.

    Returns: None

    """
    # print("Starting exporting process")

    if verbose_flag:
        _set_verbose(verbose_flag)

    url = config['hosts'][env]

    jwt_token = _get_jwt_token(credentials)
    bot_id = _get_bot_id(url, jwt_token, bot_name)
    download_link = export_bot_status(url, jwt_token, bot_id)
    file_path = downloadBot(download_link, bot_name, output_dir)
    # print(file_path)
    status = _upload_artifacts(file_path, bot_name)
    if status:
        print("Completed: run_export_process : success")


def main():
    parser = argparse.ArgumentParser(description='Starting exporting process for Kore ')
    parser.add_argument("-env", "--environment", default='uat', help='Kore target environment.')
    parser.add_argument("-ci", "--client_id", default='cs-015c5e8f-a926-5ec3-8644-6d30c138502d',
                        help='KoreAdminApp client id.')
    parser.add_argument("-sk", "--secret_key", default='0R+obyBQTWAaAQoFptjpRzbeNisrLYQ8eoXmreRNR8Y=',
                        help='KoreAdminApp Secret Key.')
    parser.add_argument("-sub", "--subject", default='udeploy_Kore', help='udeploy_Kore')
    parser.add_argument("-bname", "--bot_name", default='SampleBot', help='Bot Name')
    parser.add_argument("-path", "--output_dir", default='/var/tmp', help="export dir")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    try:
        environment_name = args.environment.upper()
        environment = Environment[environment_name]
        env = environment.name.lower()
    except KeyError as ke:
        print('An error occurred determining target deployment environment. Error: ' + str(ke))
        sys.exit(1)
        return

    credentials = _build_credentials_dict(args.subject, args.client_id, args.secret_key)

    try:
        run_export_process(env, credentials, args.bot_name, args.output_dir)

    except RuntimeError as rte:
        print('An error occurred during exporting processing. Error: ' + str(rte))
        sys.exit(1)


if __name__ == '__main__':
    main()