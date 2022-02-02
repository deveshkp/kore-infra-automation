#!/usr/bin/env python3
"""

Provides deployment functions for Kore Chatbot APIs.

Script usage: This module is for ChatBot Deployment.

   python Kore_deploy.py
"""

import argparse
import json
import logging
import os
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
                    filename='/app/deploy/scripts/deploy.log',
                    filemode='w')


def _log_Error(method_name, error_msg):
    logger = logging.getLogger(method_name)
    logger.error("An error occured in: " + method_name)
    logger.error("Error message: " + error_msg, exc_info=True)


class Environment(Enum):
    RND = 1
    UAT = 2
    QA = 3
    PROD = 4


class EnvironmentLevel(Enum):
    RND = 1
    UAT = 2
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
    """Load configurations from yaml config file. JS2D 6T3 1702

    Returns:
        configs: An dictionary with configurations.
    """
    config_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(config_dir, 'config.yaml')
    configs = _yaml_file_to_dict(config_path)

    return configs


config = _get_config()


def _upload_file(url, jwt_token, path, file_name, file_type):
    """

    Args:
        url: Environment URL from config.yml
        jwt_token: jwt token gets created from _get_jwt_token function.
        path: Path of json files and image file which are being uploaded.
        file_name: It could be bot def, bot config or bot icon
        file_type: either json or png files.

    Returns: file id

    """
    data = {"fileContext": "bulkImport", "fileExtension": file_type}
    headers = {'auth': jwt_token}
    files = {('file', (file_name, open(path, 'rb'), 'application/json'))}

    response = requests.post('{0}/api/public/uploadfile'.format(url), files=files, data=data, headers=headers,
                             verify=False)

    if response.ok:
        json_response = response.json()
        file_id = json_response['fileId']
    else:
        raise RuntimeError('Unable to upload file : '
                           + HTTP_RESP_CODE + str(response.status_code)
                           + HTTP_RESP_MSG + response.text)
    if verbose:
        print('Completed: upload_file : ' + file_name + ' file ID :' + file_id)

    return file_id


def _build_credentials_dict(sub, client_id, secret_key):
    """Set environment enumeration value.

    Args:
        subject:
        client_id:
        secret_key:

    Returns:
        credentials:
    """
    credentials = {
        'sub': sub,
        'client_id': client_id,
        'secret_key': secret_key
    }

    return credentials


def _get_jwt_token(env, credentials):
    """Add description here.

    Args:
        env
        credentials in dict
    Returns:
        jwt token in string
    """

    url = config['hosts'][env]
    subject = {
        'sub': credentials['sub'],
        'appId': credentials['client_id']
    }
    jwt_token = jwt.encode(
        subject, credentials['secret_key'], algorithm='HS256')
    # print(jwt_token)
    # print(subject)
    # print(credentials['secret_key'])

    if verbose:
        print('Completed: get_jwt_token. env: ' + url)

    return jwt_token


def _get_list_of_bots(url, jwt_token):
    """

    Args:
        url: environment url
        jwt_token: jwt token get created from _get_jwt_token function.

    Returns: Bot data as JSON

    """
    headers = {'auth': jwt_token, "content-type": "application/json"}

    offset = 0
    list_of_bots = []
    while True:
        bot_api_url = url + '/api/public/bots?offset=' + \
            str(offset) + '&limit=50'
        response = requests.get(bot_api_url, headers=headers, verify=False)

        if response.status_code == 200:
            data = response.json()
        else:
            raise RuntimeError('Unable to get list of bots : '
                               + HTTP_RESP_CODE + str(response.status_code)
                               + HTTP_RESP_MSG + response.text)

        hasMore = data['availableMore']
        list_of_bots = list_of_bots + data['bots']
        if not hasMore:
            break
        offset = offset + 1

    if verbose:
        print('Completed: get_list_of_bots. Total # of bots in env: ' +
              str(len(list_of_bots)))

    return list_of_bots


def _get_bot_id(url, jwt_token, bot_name):
    """

    Args:
        url: environment url
        jwt_token: jwt_token
        bot_name: string format
    Returns:
        bot id in string format
    """

    data = _get_list_of_bots(url, jwt_token)
    exists = any(el['name'] == bot_name for el in data)
    if exists:
        bot_id = [obj for obj in data if obj['name'] == bot_name][0]['_id']
    else:
        raise RuntimeError('Unable to find bot id')

    if verbose:
        print('Completed: get_bot_id bot id: ' + str(bot_id))

    return bot_id


def _check_if_bot_exists(url, jwt_token, bot_name):
    """

    Args:
        url: Environment URL from config.yml
        jwt_token: jwt token get created from _get_jwt_token function.
        bot_name: Bot Name is Passed as argument.
    Returns:

    """
    data = _get_list_of_bots(url, jwt_token)
    # print(data)
    exists = any(el['name'] == bot_name for el in data)

    if verbose:
        print('Completed: check_if_bot_exists. ' +
              bot_name + ' exists: ' + str(exists))

    return exists


def get_user_roles(url, jwt_token):
    """
       This method is for getting user roles in botbuilder
    """

    headers = {'auth': jwt_token, "content-type": "application/json"}
    response = requests.get(
        '{0}/api/public/alluserroles?limit=2'.format(url), headers=headers, verify=False)
    response = response.json()

    # print("get user roles " + response)
    return response


def get_role_id(url, jwt_token, role_name):
    """

    Args:
        url:
        jwt_token: str jwt token
        role_name: str role name from config.yaml file

    Returns:

    """

    data = get_user_roles(url, jwt_token)
    role_id = None
    for item in data['users']:
        for user in item['btRoles']:
            if user['roleName'] == role_name:
                role_id = user.get('roleId')

    return str(role_id)


def _deploy_bot(url, jwt_token, path, bot_name):
    """
       It will first check if the bot exist and then import as new or existing bot.
    """
    bot_exists = _check_if_bot_exists(url, jwt_token, bot_name)
    # print(bot_exists)
    if bot_exists:
        # print(bot_name + " exist")
        bir_id = _import_as_new_or_existing_bot(
            'update', url, jwt_token, path, bot_name)

    else:
        # print(bot_name + " does not exist")
        bir_id = _import_as_new_or_existing_bot(
            'create', url, jwt_token, path, bot_name)

    if verbose:
        print('Completed: deploy_bot : Bot Import Reference ID : ' + bir_id)

    return bir_id


def _check_if_source_files_exist(path):
    while True:
        filelist = ['config.json', 'botDefinition.json', 'icon.png']
        if all([os.path.isfile(f) for f in filelist]):
            break
        else:
            raise RuntimeError("Unable to start import process. bot def,"
                               "bot config and icon id files are the required fields for import")

    if verbose:
        print(
            'Completed: check_if_source_files_exist: ' + str(filelist))


def _import_as_new_or_existing_bot(operation, url, jwt_token, path, bot_name):
    """
       Depends on operation arg it will call create or update function.
    """
    # Short for of using list comp with function.
    # list_of_files = ['config.json', 'botDefinition.json', 'icon.png']
    # list_of_file_id = [_upload_file(url, jwt_token, path + em, file_name=em, file_type='json') for em in list_of_files]
    # print(list_of_file_id)

    # _check_if_source_files_exist(path)
    files = [f for f in os.listdir(
        path) if os.path.isfile(os.path.join(path, f))]
    print("Found these bot configuration files in " + path + " : " + str(files))

    if os.path.isfile(path + "/config.json"):
        bot_config_id = _upload_file(
            url, jwt_token, path + "/config.json", file_name="config.json", file_type='json')
    else:
        bot_config_id = None

    if os.path.isfile(path + "/botDefinition.json"):
        bot_def_id = _upload_file(url, jwt_token, path + "/botDefinition.json", file_name="botDefinition.json",
                                  file_type='json')
    else:
        bot_def_id = None

    if os.path.isfile(path + "/icon.png"):
        icon_id = _upload_file(
            url, jwt_token, path + "/icon.png", file_name="icon.png", file_type='png')
    else:
        icon_id = None

    if os.path.isfile(path + "/botFunctions.js"):
        function_id = _upload_file(
            url, jwt_token, path + "/botFunctions.js", file_name="botFunctions.js", file_type='js')
    else:
        function_id = None

    # for update operation icon file should not be there hence creating two diff data.
    data_update = {"botDefinition": bot_def_id, "configInfo": bot_config_id}

    if function_id is None:
        data_update = {"botDefinition": bot_def_id, "configInfo": bot_config_id}
        data_create = {"botDefinition": bot_def_id,
                   "configInfo": bot_config_id, "icon": icon_id}
    else:
        data_update = {"botDefinition": bot_def_id, "configInfo": bot_config_id, "botFunctions": function_id }
        data_create = {"botDefinition": bot_def_id,
                       "configInfo": bot_config_id, "botFunctions": function_id, "icon": icon_id}


    headers = {'auth': jwt_token}

    if operation == 'create':
        if None in (icon_id, bot_def_id, bot_config_id):
            raise RuntimeError(
                "Unable to start import process. bot def,"
                "bot config and icon id files are the required fields for import as new bot")
        else:
            print('Started: create bot operation')  # For create icon is mandatory
            response = requests.post(
                '{0}/api/public/bot/import'.format(url), data=data_create, headers=headers, verify=False)
            response = response.json()
            print(response)
            bot_import_reference_id = response['_id']

    elif operation == 'update':
        if None in (bot_config_id, bot_def_id):
            raise RuntimeError(" Unable to start import process. bot def and bot config are the required files"
                               " for import as update bot")

        # print('Started: update bot operation')  # For update, icon file is not allowed, just config and def
        # First get the bot id and then call import api.
        else:
            bot_id = _get_bot_id(url, jwt_token, bot_name)
            response = requests.post('{}/api/public/bot/{}/import'.format(url, bot_id), data=data_update,
                                     headers=headers,
                                     verify=False)
            response = response.json()
            bot_import_reference_id = response['_id']
    else:
        raise ValueError(
            'Unknown operation, must be create or update. operation: ' + operation)

    if verbose:
        print(
            'Completed: import_as_new_or_existing_bot: ' + operation)

    return bot_import_reference_id


def import_bot_status(url, jwt_token, bir_id, bot_name):
    headers = {'auth': jwt_token, "content-type": "application/json"}
    response = requests.get('{}/api/public/bot/import/status/{}'.format(url, str(bir_id)), headers=headers,
                            verify=False)

    if response.ok:
        json_response = response.json()
        status = json_response['statusLogs'][0]['status']
    else:
        raise RuntimeError('Unable to get the bot import status: '
                           + HTTP_RESP_CODE + str(response.status_code)
                           + HTTP_RESP_MSG + response.text)

    if verbose:
        print('Completed: import_bot_status : ' + status)

    if status == 'success':
        bot_id = _get_bot_id(url, jwt_token, bot_name)
        assign_bot_roles(url, jwt_token, bot_id)
        print('Deployment request is complete.')
    else:
        print("Deployment request status: Failed")


def assign_bot_roles(url, jwt_token, bot_id):
    """

    Args:
        url: hostname from config file
        jwt_token: get jwt token function will provide this
        bot_id: get bot id function will provide this

    Returns: json response

    """
    mnemonic = 'Kore'
    group_name = config['roles']['Bot Developer'].format(mnemonic)
    # print(group_name)
    role_name = 'Bot Developer'
    role_id = get_role_id(url, jwt_token, role_name)


    # group_name = ''
    # role_id = '5f1f0d7c110a5f676c233af6'
    # TODO: [ Need to call roles api to get role id and add group not the user]
    data = '[{"roleId":"' + role_id + '", "botId":"' + bot_id + '", "addUsers":[""], "removeUsers":[""], "addGroups": [' \
                                                                '"' + group_name + '"], ' \
                                                                                   '"removeGroups":[""]}] '
    # print(data)
    print("Assigning "+role_name+" role for this bot to "+group_name+"...")
    headers = {'auth': jwt_token, "content-type": "application/json"}
    response = requests.post(
        url + "/api/public/btroles/assignments/", data=data, headers=headers, verify=False)

    if response.status_code == 200:
        json_response = response.json()
        # print(json_response)
    else:
        raise RuntimeError('Unable to get the import status: '
                           + HTTP_RESP_CODE + str(response.status_code)
                           + HTTP_RESP_MSG + response.text)

    if verbose:
        print('Completed: assign_bot_roles:  JSON : ' + str(json_response))


def run_deployment_process(env, credentials, bot_name, mne, verbose_flag=True):
    """Run Main deployment process.

    Args:

    Returns:
    """
    print("Starting deployment process")

    if verbose_flag:
        _set_verbose(verbose_flag)

    url = config['hosts'][env]
    path = config['file_path']+mne
    dev_role = config['roles']['Bot Developer']
    tester_role = config['roles']['Bot Tester']
    analyst_role = config['roles']['Bot Analyst']

    jwt_token = _get_jwt_token(env, credentials)
    print("The value of Path:"+path)
    bir_id = _deploy_bot(url, jwt_token, path, bot_name)
    # print("Checking the import bot status")
    time.sleep(15)
    import_bot_status(url, jwt_token, bir_id, bot_name)


def main():
    parser = argparse.ArgumentParser(
        description='Starting deployment process for Kore')

    parser.add_argument("-env", "--environment",
                        default='rnd', help='Kore target environment.')
    parser.add_argument("-ci", "--client_id", default='cs-0d8-5ec9-8e1c-2480f6081fe7',
                        help='KoreAdminApp client id.')
    parser.add_argument("-sk", "--secret_key", default='idiqddmA//kmZdIQQ=',
                        help='KoreAdminApp Secret Key.')
    parser.add_argument("-sub", "--subject",
                        default='udeploy_Kore', help='udeploy_Kore')
    parser.add_argument("-bname", "--bot_name",
                        default='HelloWorld', help='Bot Name')
    parser.add_argument("-mne", "--mnemonic", default='Kore', help='Mnemonic')
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    try:
        environment_name = args.environment.upper()
        environment = Environment[environment_name]
        env = environment.name.lower()
    except KeyError as ke:
        print(
            'An error occurred determining target deployment environment. Error: ' + str(ke))
        sys.exit(1)
        return

    credentials = _build_credentials_dict(
        args.subject, args.client_id, args.secret_key)

    try:
        run_deployment_process(env, credentials, args.bot_name, args.mnemonic)

    except RuntimeError as rte:
        print('An error occurred during deployment processing. Error: ' + str(rte))
        sys.exit(1)


if __name__ == '__main__':
    main()