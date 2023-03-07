import sys
import os
from typing import List
import requests
import shutil
import datetime
import json
import yaml
from jinja2 import Environment, PackageLoader
import io
import time
import re
import gnupg
import tarfile
from subprocess import *
import subprocess
import glob
import secrets
import traceback
import string
import ipaddress
from exitstatus import ExitStatus
from base64 import encodebytes, decodebytes
from jfrogdevopstools.tools import aws as jfrog_aws_tools
from jfrogdevopstools.tools import alicloud as jfrog_aliyun_tools
import pandas as pandas
import xml.etree.ElementTree as ET
from random import randrange
# DO NOT REMOVE, It is being used by sql_cli , and should be used by prints in code later on
from jfrogdevopstools.tools.colors import *
import collections.abc
from dns import resolver
import logging
import logging.config
from jfrogdevopstools.logger.json_formatter import JsonFormatter
from jfrogdevopstools.logger.logging_data import LoggingData
from jfrogdevopstools.logger.thread_logging_helper import ThreadLoggingHelper
from jfrogdevopstools.tools.prometheus import prom_decorator


def setup_logger_format(log_level: int = logging.INFO, action: str = None, customer_name: str = None,
                        application: str = None, application_list: list = [], region: str = None,
                        namespace: str = None, json_log: bool = True):
    if not json_log:
        logging.getLogger().setLevel(log_level)
        logging.basicConfig(format='%(asctime)s | %(levelname)s | %(message)s')
        return

    log_formatter = JsonFormatter()
    logger = logging.getLogger()
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_formatter)
    if not logger.hasHandlers():
        logger.addHandler(console_handler)
    else:
        handler = logger.handlers
        logger.removeHandler(handler)
    logger.setLevel(log_level)

    ThreadLoggingHelper().set_logging_data(LoggingData(action=action, customer_name=customer_name,
                                                       region_name=region, app_name=application,
                                                       app_list=application_list, namespace=namespace))


def human_time_to_seconds(time_period, max=None):
    time_during = time_period[:-1]
    time_type = time_period[-1]

    if time_type not in ('h', 'd', 'w'):
        raise ValueError("Time format must be [h, d, w], not  [ {} ]".format(time_type))

    if time_type == "h":
        total_seconds = int(time_during) * 60 * 60
    elif time_type == "d":
        total_seconds = int(time_during) * 60 * 60 * 24
    elif time_type == "w":
        total_seconds = int(time_during) * 60 * 60 * 24 * 7
    else:
        raise ValueError("Time format must be [h, d, w], not  [ {} ]".format(time_type))

    if max is not None and total_seconds > max:
        raise ValueError("Given time period is longer the maximum allowed")

    return total_seconds


def logger(level, msg):
    time_stamp = datetime.datetime.now().strftime('%d-%m-%Y:%H:%M:%S')
    message = level.upper() + ': ' + time_stamp + ' ' + msg
    print(message)


def printInfo(msg, context=None):
    if context is None:
        print("INFO: %s" % msg)
    else:
        print("[%s] INFO: %s" % (context, msg))


def printError(msg, context=None):
    if context is None:
        print("ERROR: %s" % msg)
    else:
        print("[%s] ERROR: %s" % (context, msg))


# Bash exit code
def exitInfo(msg, context=None):
    if context is None:
        print("INFO: " + msg)
        print("INFO: Exit ... " + msg)
        print("INFO: Exit 0 " + msg)

    else:
        print("[%s] INFO: %s" % (context, msg))
        print("[%s] INFO: Exit ..." % (context))
        print("[%s] INFO: Exit 0" % (context))
    sys.exit(ExitStatus.success)


def exitError(msg, context=None):
    if context is None:
        print("ERROR: " + msg)
        print("FATAL: Exit on error " + msg)
        print("INFO: Exit 1 " + msg)

    else:
        print("[%s] ERROR: %s" % (context, msg))
        print("[%s] FATAL: Exit on error" % (context))
        print("[%s] INFO: Exit 1" % (context))
    sys.exit(ExitStatus.failure)


def get_first_value(*args):
    for arg in args:
        if arg:
            return arg

    return None


def raise_if_not_set(value_to_check, env_var_name):
    value = get_first_value(os.environ.get(env_var_name), value_to_check)
    if not value:
        raise ValueError('Missing %s is empty.' % env_var_name)
    return value


def rename_file_or_dir(src, dest):
    if os.path.exists(src) or os.path.isfile(src):
        try:
            os.rename(src, dest)
        except Exception:
            print("Couldn't rename [%s] to [%s]" % (src, dest))
            return False

        return True
    else:
        printError("Source does not exist, cannot rename", src)
        return False


def get_parent_dir(targetPath):
    return os.path.dirname(os.path.abspath(targetPath))


def license_file_to_json(license_file):
    license_values = license_file.replace("\n\n", "PLACEHOLDER")
    license_values = license_values.replace("\n", "")
    license_values = license_values.replace("PLACEHOLDER", "\n")
    license_list = license_values.splitlines()
    license_list_final = []
    for lic in license_list:
        license_list_final.append({"licenseKey": lic})
    return json.dumps(license_list_final, sort_keys=True, indent=4, separators=(',', ': '))


def verify_folder(path, is_file=False):
    "Make sure the directory exists for desired path, if path is file, check its parent dir"

    logging.info("Going to create folder [{}], is_file=[{}]".format(path, is_file))
    try:
        if is_file:
            # get parent dir
            path = get_parent_dir(path)

        if not os.path.exists(path):
            logging.info("The following directory " + path + " doesn't exist, creating it")
            os.makedirs(path, exist_ok=True)

    except Exception:
        logging.error("Couldn't create the parent directory for [{}]".format(path))
        traceback.print_exc(file=sys.stdout)
        raise

    return True


def delete_folder(path, is_file=False):
    """Make sure the directory does not exists for desired path, if path is file, delete its parent dir"""

    logging.debug("Going to delete folder [{}], is_file=[{}]".format(path, is_file))

    try:
        if is_file:
            # get parent dir
            path = get_parent_dir(path)

        if not os.path.exists(path):
            logging.info("The following directory doesn't exist, nothing to delete [{}]".format(path))
        else:
            shutil.rmtree(path)

        if os.path.exists(path):
            raise Exception("Folder was not deleted [{}]".format(path))

    except Exception:
        raise Exception("Couldn't delete directory [{}]".format(path))

    return True


def list_to_chunks(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def valid_object(my_object):
    """
    Convert the value to python object if needed
    :param my_object:
    :return:
    """
    if str(my_object).lower() == "true":
        return True
    elif str(my_object).lower() == "false":
        return False
    elif str(my_object).lower() == "none" or my_object is None:
        return None
    else:
        return my_object


def valid_key_from_json(json, field):
    """
    Convert the value to python object if needed
    :param json:
    :param field:
    :return:
    """
    if field in json:
        if str(json[field]).lower() == "true":
            return True
        elif str(json[field]).lower() == "false":
            return False
        elif str(json[field]).lower() == "none" or json[field] is None:
            return None
        else:
            return json[field]
    return None


def json_value_by_key(data_json, element):
    keys = element.split('/')
    value = data_json

    for key in keys:
        if key.isdigit():
            value = value[int(key)]
        else:
            value = value[key]

    return value


def validate_ip(ip_string):
    logging.debug("validate_ip for {}".format(ip_string))
    octets = ip_string.split('.')
    if len(octets) != 4:
        raise ValueError("String not an IP address, not an IP format w.x.y.z [{}]".format(octets))
    for octet in octets:
        if not octet.isdigit():
            raise ValueError("String not an IP address, octet is not a digit [{}]".format(octet))
        i = int(octet)
        if i < 0 or i > 255:
            raise ValueError("String not an IP address, octet is not between 0 to 255 [{}]".format(i))
    return True


def validate_dns(dns_string):
    sub_domains = dns_string.split('.')
    if len(sub_domains) < 3:
        logging.error("String not a valid DNS address, too few sub domains")
        return False
    return True


def get_ip():
    """Return the server IP"""
    logging.debug("=== Starting get_ip() ===")
    uname = do_shell_cmd("uname")["output"].decode('utf-8')
    logging.debug("Uname is [{}]".format(str(uname)))
    if uname == "Darwin":
        logging.debug("Pulling Darwin IP")
        cmd = "ifconfig | grep -A2 en0 | grep -w inet | awk '{print $2}'"
    elif uname == "Linux" and os.path.exists("/sbin/ip"):
        logging.debug("Pulling Linux IP")
        cmd = "/sbin/ip address | egrep -A1 \"eth0|ens3|ens4|ens5\" | grep inet | awk '{print $2}' | awk -F '/' '{print $1}'"
    else:
        cmd = "/sbin/ifconfig| egrep -A1 \"eth0|ens3|ens4|ens5\" |" \
              " grep addr: | awk '{print $2}' | awk -F ':' '{print $2}'"

    my_ip = do_shell_cmd(cmd)["output"].decode('utf-8')
    logging.debug("Got IP [{}]".format(my_ip))
    if my_ip is None or my_ip == "":
        cmd = "hostname -i"
        my_ip = do_shell_cmd(cmd)["output"]

    if not isinstance(my_ip, str):
        my_ip = my_ip.decode('utf-8')

    logging.debug("Validating final IP [{}]".format(my_ip))

    if validate_ip(my_ip):
        return my_ip
    logging.debug("=== Finished get_ip() ===")
    return None


def run_system_ping(url, auth=None, timeout=240, header_validation={}, sleep_time=5, allow_redirects=True):
    t_end = time.time() + timeout
    counter = 1
    while time.time() < t_end:
        logging.info("[%s] Trying system ping to [%s]..." % (str(counter), url))
        try:
            response = requests.get(url=url, auth=auth, allow_redirects=allow_redirects)
            status_code = response.status_code

            if status_code == requests.codes.ok:
                # Validate strings exists in response headers
                if header_validation != {}:
                    logging.info("Extra API validation for headers")
                    response_headers = response.headers
                    for header in header_validation:
                        if header in response_headers:
                            logging.info("Found header [{}] in response".format(header))
                            if header_validation[header] in response_headers[header]:
                                logging.info("Found [{}] in header [{}]".format(header_validation[header], header))
                                logging.debug("Header [{}]=[{}]".format(header, response_headers[header]))
                            else:
                                raise RuntimeError("Failed header validation, header [{}]=[{}]".format(
                                    header, response_headers[header]))
                        else:
                            raise RuntimeError("Couldn't find header [{}] in response".format(header))
                logging.info("System ping successful in [%s] seconds!" % response.elapsed.total_seconds())

                return True
            else:
                logging.info("Error running system ping. status code is %s" % status_code)
                logging.debug("Request - %s" % response.request)
                response.raise_for_status()
        except Exception as e:
            logging.info(str(e))
            # Retry if got Exception
        counter += 1
        time.sleep(sleep_time)

    raise ConnectionError("System ping to [%s] timed out (%s seconds)" % (url, timeout))


def check_system_version(url, required_app_version, app_version_output_field, auth=None, timeout=240):
    t_end = time.time() + timeout
    counter = 1
    while time.time() < t_end:
        printInfo("[%s] Trying system version to [%s]..." % (str(counter), url))
        try:
            response = requests.get(url=url, auth=auth)
            if response.status_code == requests.codes.ok:
                logging.info("Successfully got system version in [%s] seconds!" % response.elapsed.total_seconds())
                data = json.loads(response.content.decode('utf-8'))
                deployed_app_version = data[app_version_output_field]
                if required_app_version == deployed_app_version:
                    logging.info("Application version [%s] is deployed!!!" % required_app_version)
                    return True
                else:
                    logging.info("Mismatch in version [required {}] vs. [{} deployed], retrying...".format(
                        required_app_version,
                        deployed_app_version))
        except Exception as e:
            logging.info(str(e))
            # Retry if got Exception
        counter += 1
        time.sleep(1)

    raise ConnectionError("System version to [%s] timed out (%s seconds)" % (url, timeout))


def read_env_from_file(env_file):
    if os.path.exists(env_file):
        with open(env_file) as f:
            for line in f:
                if 'export' not in line:
                    continue
                if line.startswith('#'):
                    continue
                # Remove leading `export `
                # then, split name / value pair
                key, value = line.replace('export ', '', 1).strip().split('=', 1)
                os.environ[key] = value
        return True
    return False


def read_config_file(file_path):
    """Create a dict from a key=value file"""
    config = {}
    lines = [line.rstrip('\n') for line in open(file_path)]
    for line in lines:
        if line[:1] != "#" and '=' in line:
            clean_line = line.rstrip()
            key_value = clean_line.split('=', 1)
            config[key_value[0]] = key_value[1]
    print_json(config)
    return config


def get_value_from_config_file(file_path):
    """Return value from a key=value file"""
    configuration = {}
    lines = [line.rstrip('\n') for line in open(file_path)]
    for line in lines:
        if line[:1] != "#" and '=' in line:
            clean_line = line.rstrip()
            key_value = clean_line.split('=', 1)
            logging.debug("key_value: {}".format(key_value))
            configuration[key_value[0]] = key_value[1]
    return configuration


def read_jfrog_ip_list(file_path):
    ip_list = []
    lines = [line.rstrip('\n') for line in open(file_path)]
    for line in lines:
        if line[:1] != "#":
            addr = line.split(' ', 1)[0]
            addr = addr.split('\t', 1)[0]
            ip_list.append(addr)
    return ip_list


def get_yaml_content(file_path):
    """Return yaml content in dictionary format"""
    with open(file_path) as file:
        yaml_content = yaml.safe_load(file)

    if not yaml_content:
        return {}

    return yaml_content


def get_file_content(file_path):
    """Return yaml content in dictionary format"""
    with open(file_path) as file:
        content = file.read()
    return content


def get_yaml_file_as_string(file_path):
    with open(file_path) as f:
        doc = yaml.safe_load(f)

    df = pandas.io.json.json_normalize(doc, sep='_')
    conf_dict = df.to_dict(orient='records')[0]

    conf_list = ""
    for key in conf_dict:
        value = conf_dict[key]
        if value is None:
            continue
        conf_list = "{};{}={}".format(conf_list, key, value)

    return conf_list[1:]


def get_xml_file_as_string(file_path):
    tree = ET.parse(file_path)
    root = tree.getroot()
    xml_str = ET.tostring(root).decode()

    return xml_str


def do_shell_cmd_with_info(cmd, wait_to_code=None, context='[OS CMD]'):
    """Wait_to_code is the exit code number to expect the function to return"""
    subproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in subproc.stdout:
        print(str("%s %s" % ("[{}] {}".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), context),
                             line.decode('utf-8'))).strip())

    out, err = subproc.communicate()
    exit_code = subproc.returncode
    print(exit_code)

    try:
        err = err.decode('utf-8')
    except:
        pass

    if wait_to_code is not None:
        if int(exit_code) != int(wait_to_code):
            msg = ("Exit code '%s' of command `%s` not equal to '%s'. CMD Output: %s | STDERR: %s"
                   % (exit_code, cmd, wait_to_code, out, err))
            raise RuntimeError(msg)

    return {'output': out, 'exitcode': exit_code, 'error': err}


def do_shell_cmd(cmd, wait_to_code=None):
    """Wait_to_code is the exit code number to expect the function to return"""
    logging.debug("[do_shell_cmd] Running cmd [{}]".format(cmd))
    subproc = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    subproc.wait()
    out, err = subproc.communicate()
    out = out.strip()
    exit_code = subproc.returncode
    if wait_to_code is not None:
        if int(exit_code) != int(wait_to_code):
            msg = ("Exit code '%s' of command `%s` not equal to '%s'. CMD Output: %s| STDERR: %s"
                   % (exit_code, cmd, wait_to_code, out, err))
            printError(msg)

    logging.debug("[do_shell_cmd] CMD output [{}] CMD Error {}".format(str(out), str(err)))
    return {'output': out, 'exitcode': exit_code, 'error': err}


def get_current_time_stamp():
    ts = time.time()
    return datetime.datetime.fromtimestamp(ts).strftime('%Y%m%d%H%M%S')


def get_full_current_time_stamp():
    # return timestamp 2020-06-22T22-57-38.169
    now = datetime.datetime.now()  # current date and time
    today = now.strftime("%Y-%m-%d")
    time = now.strftime("%H-%M-%S.%j")
    return "{}T{}".format(today, time)


def verify_value(value, os_key):
    if value:
        return value
    elif os_key in os.environ:
        return os.environ[os_key]
    else:
        return None


def run_dir_empty_check(path):
    """Check if a given directory contains any files"""
    cmd = "find {} -type f | wc -l".format(path)
    res = do_shell_cmd(cmd)
    output = res['output'].decode('utf-8')
    if output != "0":
        print(output)
        return False
    return True


def wait_for_folder_empty(path, timeout=120):
    for i in range(0, timeout):
        if run_dir_empty_check(path):
            print("The folder " + path + " is empty")
            return True
        else:
            time.sleep(1)
    print("The folder " + path + " is not empty")
    return False


def pretty_json(data_json, indent=4):
    return json.dumps(data_json, sort_keys=True, indent=indent, separators=(',', ': '))


def pretty_yaml(data_json, indent=4):
    return yaml.dump(data_json, indent=indent)


def pretty_yaml_print(content):
    print(yaml.safe_dump(content, width=256, default_flow_style=False))

def validate_ipaddress_ipv4(address):
    return str(ipaddress.IPv4Network(address))

@prom_decorator()
def decrypt_msg(ciphertext, decryptor_type=None):
    if decryptor_type == "kms":
        jfrog_aws_kms = jfrog_aws_tools.JFrogAWSKms()
        plaintext = jfrog_aws_kms.decrypt_msg(ciphertext)
        # Decode special bytes characters left
        # E.g.: remove prefix sign 'b' generated automatically by Python to mark this is a bytes object
        # Convert '\n' to actual new line
        plaintext = plaintext.decode("utf-8")
    elif decryptor_type == "alikms":
        jfrog_aliyun_kms = jfrog_aliyun_tools.JfrogAliyunCli()
        plaintext = jfrog_aliyun_kms.decrypt_msg(ciphertext)
    else:
        raise Exception("Decryptor type {} is not supported!!!".format(decryptor_type))

    return plaintext


def encrypt_msg(plaintext, cmk_alias, creds=None, encryptor_type=None):
    if encryptor_type == "kms":
        logging.debug("INFO: Using [{}] cmk alias for encryption".format(cmk_alias))
        jfrog_aws_kms = jfrog_aws_tools.JFrogAWSKms(cmk_alias=cmk_alias, creds=creds)
        ciphertext = jfrog_aws_kms.encrypt_msg(plaintext)
    elif encryptor_type == "alikms":
        logging.debug("INFO: Using [{}] cmk alias for encryption".format(cmk_alias))
        jfrog_aliyun_kms = jfrog_aliyun_tools.JfrogAliyunCli(creds=creds)
        ciphertext = jfrog_aliyun_kms.encrypt_msg(cmk_alias, plaintext)
    else:
        raise Exception("Encryptor type {} is not supported!!!".format(encryptor_type))

    return ciphertext


def print_json(data_json):
    """Print data json in a json format"""

    print(json.dumps(data_json, sort_keys=True, indent=4, separators=(',', ': ')))


# This is a recursive extension of dict.update()
def update_dict(d, u, array_schema=False):
    # array_schema = made to override with default schema for array object
    # (always take the first object from default in schema define)
    for k, v in u.items():
        if array_schema and isinstance(v, List) and isinstance(d.get(k, None), List) and len(d[k]) > 0:
            schema = d[k].copy()[0]
            d[k] = []
            for element in v:
                if isinstance(element, collections.abc.Mapping) or isinstance(element, List):
                    d[k].append(update_dict(schema.copy(), element, array_schema=True))
                else:
                    d[k].append(element)
        elif isinstance(v, collections.abc.Mapping):
            d[k] = update_dict(d.get(k, {}).copy(), v, array_schema=array_schema)
        else:
            d[k] = v
    return d


def print_json_as_conf(data_json):
    for config in data_json:
        print("{}={}".format(config, data_json[config]))


def print_list(data_list):
    """Print data json in a list format"""
    for item in data_list:
        print(item)


def append_text_to_file(text, target_path):
    """Add string to the bottom line of a file"""
    if os.path.exists(target_path):
        with open(target_path) as fh:
            for l in fh:
                l = l.rstrip()
                if re.search(text, l):
                    printInfo("Already exists in file", text)
                    return True

    cmd = "echo '\n%s' >> %s" % (text, target_path)
    do_shell_cmd(cmd)


def convert_tuple_to_dict(t):
    """"Convert a tuple object to nested dict"""
    d = {}
    counter = 0
    for mini_t in t:
        d[counter] = []
        mini_counter = 0
        for i in mini_t:
            d[counter].append((mini_t[mini_counter]))
            mini_counter = mini_counter + 1
        counter = counter + 1
    return d


def print_json_table(d, clean=False):
    """"Print json as table"""
    for i in range(len(d)):
        lst = d[i]
        string = ' | '.join(map(str, lst))
        if not clean:
            print('-' * len(string))
        print(string)
    return True


def chown_path(path, uid, gid, recursive=False):
    """chown  full path of all files and folders under path"""
    if recursive is True:
        os.chown(path, int(uid), int(gid))
        for dirname, dirnames, filenames in os.walk(path):
            # print path to all subdirectories first.
            for subdirname in dirnames:
                sub_dir = os.path.join(dirname, subdirname)
                os.chown(sub_dir, int(uid), int(gid))

            files_list = []
            # print path to all filenames.
            for filename in filenames:
                item_path = os.path.join(dirname, filename)
                os.chown(item_path, int(uid), int(gid))
    else:
        os.chown(path, int(uid), int(gid))
    return True


def chmod_path(path, mode):
    """chown  full path of all files and folders under path"""
    chmod_cmd = "chmod " + mode + " " + path
    do_shell_cmd(chmod_cmd)


def add_linux_user(user_name, user_id):
    cmd = "useradd -M -s /usr/sbin/nologin --uid " + user_id + " --user-group " + user_name
    res = do_shell_cmd(cmd, wait_to_code=0)
    cmd_output = res['output']
    cmd_exitcode = res['exitcode']
    print(cmd_output)
    if int(cmd_exitcode) > 0:
        print("Adding user " + user_name + " failed")
        return False
    return True


def list_to_json(params_string, separator=","):
    """Convert a string in the format of a=value,b=value2 to json {'a':'value', 'b':'value2'}"""
    configs = {}
    properties = params_string.split(separator)
    for item in properties:
        key_value = item.split("=", 1)
        key = key_value[0]
        value = key_value[1]
        configs[key] = value
    return configs


def get_value_in_file(key, file):
    operand = file["operand"]
    file_path = file["path"]
    if os.path.exists(file_path):
        with open(file_path) as fh:
            for l in fh:
                l = l.rstrip()
                if re.search(key, l):
                    if operand == "space":
                        return l.split()[1].strip()
                    elif operand == "=":
                        return l.split(operand, 1)[1].strip()
    return None


def gpg_decrypt_file(gpg_passphrase, input_file, output_file, input_content=None):
    try:
        if gpg_passphrase is None:
            raise KeyError("gpg_passphrase must be set")

        if not verify_folder(output_file, is_file=True):
            raise ValueError("could not create parent folder for output file [%s]" % output_file)

        gpg = gnupg.GPG()
        if input_content is not None:
            stream_local = input_content
        else:
            if not os.path.exists(input_file):
                raise FileNotFoundError("[%s] does not exist" % input_file)
            stream_local = open(input_file, "rb")

        output = gpg.decrypt_file(stream_local, passphrase=gpg_passphrase, output=output_file)

        if output.ok is False:
            logging.info("output.ok is")
            logging.info("[%s]" % str(output.ok))
            logging.info("output.stderr is")
            logging.info("[%s]" % str(output.stderr))
            logging.info("output.status is")
            logging.info("[%s]" % str(output.status))
            raise RuntimeError("[%s] file decryption failed" % input_file)

        logging.info("GPG Decryption Succeeded!")

    except Exception as e:
        logging.error(e)
        raise Exception("Couldn't decrypt certificates")

    return True


def generate_gpg_key(email, name, passphrase=None):
    logging.info("Going to create GPG keypair - name [{}] email [{}]".format(name, email))
    if passphrase is None:
        return generate_gpg_key_no_passphrase(email, name)

    """Current JFrog Applcications do not support gpg with passphrase"""
    gpg = gnupg.GPG()
    input_data = gpg.gen_key_input(
        name_email=email,
        name_real=name,
        passphrase=passphrase

    )
    key = gpg.gen_key(input_data)
    print(key.fingerprint)
    public_key = gpg.export_keys(key.fingerprint).strip()
    private_key = gpg.export_keys(
        keyids=key.fingerprint,
        secret=True,
        passphrase=passphrase

    ).strip()
    return {"public_key": public_key, "private_key": private_key}


def generate_gpg_key_no_passphrase(email, name):
    """Generate a GPG Keypair without a passphrsae using shell commands"""
    env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates'),
                      keep_trailing_newline=True)
    object_to_modify = env.get_template("tools/gpg_batch.j2")
    random_id = ("{}{}{}".format(name, str(randrange(100000)), str(randrange(1000))))
    gpg_batch_path = "/tmp/{}.txt".format(random_id)

    gpg_batch_content = object_to_modify.render({"name": name, "email": email})
    logging.info("Creating gpg data file [{}] for [gpg --batch] command".format(gpg_batch_path))
    with io.FileIO(gpg_batch_path, "w") as file:
        file.write(gpg_batch_content.encode("ascii"))

    gpg_cmd = "gpg --gen-key --batch {}".format(gpg_batch_path)
    gpg_cmd_shell = do_shell_cmd(gpg_cmd)
    logging.info("Creating gpg data file [{}] for [{}] command".format(gpg_batch_path, gpg_cmd))
    print("Creating gpg data file [{}] for [{}] command".format(gpg_batch_path, gpg_cmd))

    gpg_cmd_output = gpg_cmd_shell['error'].decode('utf-8').split('\n')

    if gpg_cmd_shell['exitcode'] != 0:
        raise RuntimeError("GPG command failed {}".format(gpg_cmd))

    for line in gpg_cmd_output:
        # This line indicates the generated ID
        if "marked as ultimately trusted" in line:
            words = line.split(' ')
            gpg_key_id = words[2]
            if len(gpg_key_id) != 16:
                raise ValueError("GPG ID is not 16 chars long [{}] - There might be an issue".format(gpg_key_id))

    # Retrieve Public key
    gpg_public_key_file_path = "/tmp/{}.public.key".format(random_id)
    public_key_cmd = "gpg --output {} --armor --export {}".format(gpg_public_key_file_path, gpg_key_id)
    public_key_shell_cmd = do_shell_cmd(public_key_cmd)
    if public_key_shell_cmd['exitcode'] != 0:
        raise RuntimeError("Couldn't fetch GPG public.key {}".format(public_key_cmd))

    with open(gpg_public_key_file_path, "r") as existing_file:
        public_key = existing_file.read().strip()
    existing_file.close()

    # Retrieve Private key
    gpg_private_key_file_path = "/tmp/{}.private.key".format(random_id)
    private_key_cmd = "gpg --output {} --armor --export-secret-key {}".format(gpg_private_key_file_path, gpg_key_id)
    private_key_shell_cmd = do_shell_cmd(private_key_cmd)
    if private_key_shell_cmd['exitcode'] != 0:
        raise RuntimeError("Couldn't fetch GPG private.key {}".format(private_key_cmd))

    with open(gpg_private_key_file_path, "r") as existing_file:
        private_key = existing_file.read().strip()
    existing_file.close()

    do_shell_cmd("rm -f {} {} {} ".format(gpg_batch_path, gpg_private_key_file_path, gpg_public_key_file_path))

    return {"public_key": public_key, "private_key": private_key}


def tar_folder(input_folder, output_file):
    if not os.path.exists(input_folder):
        raise KeyError("Input directory [%s] does not exist" % input_folder)

    if not verify_folder(output_file, is_file=True):
        raise ValueError("Could not create parent folder for output file [%s]" % output_file)

    tar = tarfile.open(output_file, "w:gz")
    tar.add(input_folder)
    tar.close()
    is_file(output_file)
    printInfo("Finished creating tar file [%s] from [%s]" % (output_file, input_folder))
    return True


def newest_file_in_dir(folder):
    printInfo("Looking for that latest file in [%s]" % folder)
    list_of_files = glob.glob(folder + '/*')
    latest_file = max(list_of_files, key=os.path.getctime)
    print("The latest item under [%s] is [%s]" % (folder, latest_file))
    return latest_file


def untar_file(input_file, output_folder):
    if not os.path.isfile(input_file):
        raise KeyError("Input file [%s] does not exist" % input_file)

    if not verify_folder(output_folder):
        raise ValueError("Could not create folder [%s] for output file" % output_folder)

    tar = tarfile.open(input_file)
    tar.extractall(path=output_folder)
    tar.close()


def list_to_string(ls):
    # initialize an empty string
    str1 = " "

    # return string
    return (str1.join(ls))


def list_to_semicolon(ls):
    # initialize an empty string
    str1 = ";"

    # return string
    return (str1.join(ls))


def generate_key(key_len=16, reason=None):
    key = secrets.token_urlsafe(key_len)
    return key.replace('-', '', 1) if key.startswith('-') else key


def generate_safe_key(key_len=16):
    characters = string.ascii_letters + string.digits
    key = ''.join(secrets.choice(characters) for i in range(key_len))
    return key


def generate_master_key(key_len=16):
    key = secrets.token_hex(key_len)
    return key


def exe_api(url, http_verb="GET", auth=(), data=None, headers=None, files=None, timeout=120):
    """
    Exec API Call
    :param url:
    :param http_verb:
    :param auth:
    :param data:
    :param headers:
    :param files:
    :return:
    """
    t_end = time.time() + timeout
    counter = 1

    while time.time() < t_end:
        sleep(2)
        logging.info("[%s] Trying exe_api to [%s]..." % (str(counter), url))
        try:
            # Make request
            if http_verb == "GET":
                response = requests.get(url, auth=auth)
            elif http_verb == "POST":
                response = requests.post(url, auth=auth, data=data, headers=headers, files=files)
            elif http_verb == "PATCH":
                response = requests.patch(url, auth=auth, data=data, headers=headers)
            elif http_verb == "PUT":
                response = requests.put(url, auth=auth, data=data, headers=headers)
            elif http_verb == "DELETE":
                response = requests.delete(url, auth=auth, headers=headers)
            elif http_verb == "HEAD":
                response = requests.head(url, auth=auth)
            else:
                raise KeyError("http_verb=" + http_verb + " is not supported")

            # Print status and body of response
            logging.debug("Response Status:" + str(response.status_code))
            logging.debug("Response Body:" + str(response.content))

            if response.status_code < 400:
                logging.info("Running exec_api successful in [%s] seconds!" % response.elapsed.total_seconds())
                return response

        except Exception as e:
            logging.error(e)
            raise Exception("Oops!  Cannot Execute API due to Exception")

    counter += 1
    time.sleep(1)

    raise ConnectionError("Running exec_api to [%s] timed out (%s seconds)" % (url, timeout))


def is_contains_special_character(string):
    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    # Pass the string in search
    # method of regex object.
    if regex.search(string) == None:
        return False

    return True


def is_file(path):
    file_exists = os.path.isfile(path)
    if file_exists:
        logging.info("File exists on filesystem [{}]".format(path))
    else:
        raise Exception("File doesn't exists on filesystem [{}]".format(path))


def backup_fs_path(source, dest=None):
    """Backup the customer home folder"""
    logging.info("Trying to backup path [{}]".format(source))

    if dest is None:
        epoch = str(int(time.time() * 1000))  # Get current time in milliseconds
        dest = "/tmp{}.{}.tar.gz".format(source, epoch)

    if not os.path.exists(source):
        raise FileNotFoundError("Source does not exist [{}]".format(source))

    if os.path.exists(dest):
        raise Exception("Destination exist already [{}]".format(dest))

    tar_folder(source, dest)

    logging.info("Successfully backup path [{}]->[{}]".format(source, dest))
    return True

    def valid_object(my_object):
        """
        Convert the value to python object if needed
        :param my_object:
        :return:
        """
        if str(my_object).lower() == "true":
            return True
        elif str(my_object).lower() == "false":
            return False
        elif str(my_object).lower() == "none" or my_object is None:
            return None
        else:
            return my_object



def delete_fs_path(path):
    """Remove the folder or file"""
    logging.info("Trying to delete path %s" % path)

    if os.path.exists(path):
        shutil.rmtree(path)
    else:
        logging.info("The path %s is already removed " % path)
        return True

    logging.info("Successfully removed path %s" % path)
    return True


def get_dict_from_string(string):
    config = {}
    for content in string.split(';'):
        key = content.split('=', 1)[0]
        value = content.split('=', 1)[1]
        config[key] = value
    return config


def convert_bin_to_str(binary_bytes_data):
    if binary_bytes_data is None:
        logging.info("Input binary data for converting is empty!!!")
        base64_string_data = None
    else:
        # Base64 encode of the binary input
        base64_bytes_data = encodebytes(binary_bytes_data)

        # Decode the base64 input data into string
        base64_string_data = base64_bytes_data.decode('utf-8')

    return base64_string_data


def convert_str_to_bin(string_data):
    if string_data is None:
        logging.info("Input string for converting is empty!!!")
        binary_bytes_data = None
    else:
        # Encode the base64 input string into bytes
        base64_bytes_data = string_data.encode('utf-8')

        # Base64 decode of the binray
        binary_bytes_data = decodebytes(base64_bytes_data)

    return binary_bytes_data


def convert_str_to_yaml(string_data):
    if string_data is None:
        logging.info("Input string for converting is empty!!!")
        yaml_data = None
    else:
        yaml_data = yaml.safe_load(string_data)

    return yaml_data


def convert_str_to_json(string_data):
    if string_data is None:
        raise RuntimeError("Input string for converting is empty!!!")

    json_data = json.loads(string_data)

    return json_data


def percentage(part, whole):
    return int(100 * float(part)/float(whole))


def create_folder(dir_name):
    if os.path.exists(dir_name):
        logging.info("Directory '{}' already exists".format(str(dir_name)))
    else:
        os.mkdir(dir_name)

def create_folders(dir_name):
    if os.path.exists(dir_name):
        logging.info("Directory '{}' already exists".format(str(dir_name)))
    else:
        os.makedirs(dir_name)

def execute_command(CMD):
    logging.info("Executing command '{}'".format(CMD))
    os.system(CMD)


def sleep(time_sec: int):
    logging.info("Waiting {} seconds...".format(str(time_sec)))
    time.sleep(time_sec)


def clear_bytes_objects_from_dict(config):
    for value in config:
        if isinstance(config[value], bytes):
            config[value] = '"IGNORETHIS"'
        if isinstance(config[value], dict):
            clear_bytes_objects_from_dict(config[value])


def check_cname_exists(name, name_target, name_type):

    is_cname_exists = False
    logging.debug("Check if CNAME->TARGET exists [{}]->[{}], Type [{}]".format(name, name_target, name_type))

    name_type = name_type.upper()

    if name_type == "CNAME":
        result = resolver.resolve(name, "CNAME")
        for cnameval in result:
            logging.debug("cname target address [{}]".format(cnameval.target))
            if str(cnameval.target) == name_target + '.':
                is_cname_exists = True

    elif name_type in ("A", "ALIAS"):
        result = resolver.resolve(name, 'A')
        for ipval in result:
            logging.debug("IP [{}]".format(ipval.to_text()))
            if str(ipval.to_text()) == name_target + '.':
                is_cname_exists = True
    else:
        raise ValueError("Records Type is not supported [{}]".format(name_type))

    logging.debug("Found CNAME->TARGET exists [{}]->[{}], Type [{}]".format(name, name_target, name_type))

    return is_cname_exists


def log_cname_value(name, name_type):

    logging.info("Check CNAME value for [{}], Type [{}]".format(name, name_type))

    try:
        if name_type == "CNAME":
            result = resolver.resolve(name, "CNAME")
            for cnameval in result:
                logging.info("Found CNAME->TARGET [{}]->[{}], Type [{}]".format(name, str(cnameval.target), name_type))

        elif name_type in ("A", "ALIAS"):
            result = resolver.resolve(name, 'A')
            for ipval in result:
                logging.info("Found CNAME->TARGET [{}]->[{}], Type [{}]".format(name, str(ipval.to_text()), name_type))
        else:
            raise ValueError("Records Type is not supported [{}]".format(name_type))

    except Exception as e:
        logging.error("Failed to check CNAME value for [{}], Type [{}]".format(name, name_type))
        logging.error(e)

def validate_docker_image_exists_in_repo(repos, image_path, tag, jfrog_domain):

    error_flag = False
    # TODO parallel the manifest inspect check on all edges
    for repo in repos:
        try:
            cmd = "docker manifest inspect {}{}{}:{}".format(repo, jfrog_domain, image_path, tag)
            logging.info("Edge - " + repo)
            logging.info(cmd)
            do_shell_cmd_with_info(cmd, wait_to_code=0)

        except RuntimeError as e:
            error_flag = True
            print("The image {}:{} doesn't exist in {}".format(image_path.split("/")[-1], tag, repo))

    if error_flag:
        raise RuntimeError("The image {}:{} doesn't exist in some edges, check it please".format(image_path.split("/")[-1], tag))
    logging.info("The image {}:{} exists in all edges".format(image_path.split("/")[-1], tag))

def exec_system_cmd(command, exit_code_expected=None, context='[OS CMD]'):
    """Wait_to_code is the exit code number to expect the function to return"""

    subproc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in subproc.stdout:
        try:
            logging.info("%s %s" % (context, line.decode('utf-8').strip()))
        except:
            logging.info("%s %s" % (context, line))

    out, err = subproc.communicate()
    exit_code = subproc.returncode
    logging.debug(exit_code)

    try:
        err = err.decode("utf-8")
    except:
        err = err

    if exit_code_expected is not None:
        if int(exit_code) != int(exit_code_expected):
            raise Exception("Exit code '{}' of command  not equal to '{}'. CMD Output: {}\nCMD Err:\n{}"
                            "".format(exit_code, exit_code_expected, out, err))

    return True


def run_command(command, exit_code_expected=0, return_output=False, print_stdout=True):
    subproc = subprocess.run(command, shell=True, capture_output=True)
    out = subproc.stdout.decode()
    err = subproc.stderr.decode()
    exit_code = subproc.returncode

    if print_stdout:
        logging.info(out)

    if exit_code_expected is not None and int(exit_code) != int(exit_code_expected):
        raise Exception("Exit code '{}' of command `{}` not equal to '{}'. CMD Output: {}\n CMD Err: {}"
                        "".format(exit_code, command, exit_code_expected, out, err))

    if return_output:
        return out
    else:
        return True
