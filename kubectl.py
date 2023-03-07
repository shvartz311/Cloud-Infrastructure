#!/usr/bin/env python3

import os
import subprocess
import sys
import traceback
import logging
import platform
import time
from kubernetes import client, config
import shutil
import uuid
import re
import json
from jfrogdevopstools.tools.prometheus import prom_decorator
from packaging import version
from datetime import datetime
from jinja2 import Environment, PackageLoader
import tempfile

class JfrogKubectlCli:
    project = None
    zone = None
    cluster = None
    task_env = None
    region = None
    config = None  # Configs can be set in Configuration class directly or using helper utility
    client_v1 = None
    cloud_provider_sdm_name = None
    dev_mode = False  # use ENV DEVELOPMENT_MODE=True to enable it
    kill_pod_state = False

    def __init__(self, region, project, cluster, zone, environment):
        self.region = region
        self.project = project
        self.cluster = cluster
        self.zone = zone
        self.task_env = environment

        if os.getenv("DEVELOPMENT_MODE", "false").lower() == "true":
            self.dev_mode = True

    @property
    def task_env_short(self):
        """
        Get Application task_env flag
        dev / stg / prod
        :return: string
        """

        if self.task_env == "production":
            task_env = "prod"
        elif self.task_env == "staging":
            task_env = "stg"
        elif self.task_env == "development":
            task_env = "dev"
        else:
            raise Exception("Environment [%s] not supported" % self.task_env)

        return task_env

    @property
    def os_type(self):
        """
        Get OS Type
        :return: Linux, Darwin or Windows
        """
        os_type = platform.system()
        return os_type.lower()

    @property
    def kubectl_version(self):
        """
        Get kubectl client version
        :return: x.xx.x
        """
        regex = "v\d\.\d+\.\d"
        command = 'kubectl version --client'
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=0,
                                              return_output=True)
        version_string = re.search(regex, command_output.pop(0)).group(0)[1:]
        return version_string

    def install_cli(self):
        logging.info("Installing \ verifying kubectl on {}".format(self.os_type))
        if self.os_type == "Darwin".lower():
            self.exec_system_cmd("hash kubectl && echo 'kubectl installed already' || brew install kubernetes-cli",
                                 exit_code_expected=0)
        else:
            self.exec_system_cmd("hash jfrog && echo 'JFrog CLI installed already'"
                                 " || cd /usr/local/bin/ && curl -LO https://storage.googleapis.com/kubernetes-release/"
                                 "release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/"
                                 "stable.txt)/bin/linux/amd64/kubectl | sh",
                                 exit_code_expected=0)

            jfrog_cloud_cluster_sdm_enabled = os.environ.get('USE_SDM', False)
            if jfrog_cloud_cluster_sdm_enabled:
                self.exec_system_cmd("hash sdm && echo 'JFrog SDM installed already'"
                                     " || echo 'Please install SDM from https://app.strongdm.com/app/download' && exit 1",
                                     exit_code_expected=0)
        return True

    def connect(self, sdm_override_name=None):
        """
        Connect to cluster by running cloud specific connect commands
        :return:
        """

        jfrog_cloud_cluster_sdm_enabled = self.valid_object(os.environ.get('USE_SDM', False))
        logging.debug("jfrog_cloud_cluster_sdm_enabled is based on ENV [USE_SDM]=[{}]"
                      "".format(jfrog_cloud_cluster_sdm_enabled))
        if jfrog_cloud_cluster_sdm_enabled:
            if sdm_override_name is not None:
                jfrog_cloud_cluster_sdm_name = f'{self.cloud_provider_sdm_name}-k8s-{sdm_override_name}'
                sdm_cluster_list = self.exec_system_cmd(f'sdm status | grep {jfrog_cloud_cluster_sdm_name} | awk \'{{print $1}}\'', return_output=True)
                sdm_cluster_list = list(map(str.rstrip, sdm_cluster_list))
                if jfrog_cloud_cluster_sdm_name not in sdm_cluster_list:
                    jfrog_cloud_cluster_sdm_name = "{}-k8s-{}-sdm".format(self.cloud_provider_sdm_name, sdm_override_name)
                logging.info(f'Connecting to SDM cluster {jfrog_cloud_cluster_sdm_name}')
            else:
                jfrog_cloud_cluster_sdm_name = f'{self.cloud_provider_sdm_name}-k8s-{self.region}'
                sdm_cluster_list = self.exec_system_cmd(f'sdm status | grep {jfrog_cloud_cluster_sdm_name} | awk \'{{print $1}}\'', return_output=True)
                sdm_cluster_list = list(map(str.rstrip, sdm_cluster_list))
                if jfrog_cloud_cluster_sdm_name not in sdm_cluster_list:
                    jfrog_cloud_cluster_sdm_name = "{}-k8s-{}-sdm".format(self.cloud_provider_sdm_name, self.region)
                logging.info(f'Connecting to SDM cluster {jfrog_cloud_cluster_sdm_name}')
            self.sdm_connect(cloud_cluster_sdm_name=jfrog_cloud_cluster_sdm_name)
        else:
            self.cloud_connect()

        return True

    def sdm_connect(self, cloud_cluster_sdm_name):
        """
        Connect to cluster using https://app.strongdm.com/
        :return:
        """

        logging.info("Connecting to the cluster using strongdm")

        if self.dev_mode:
            cmd_list = ["sdm connect {}".format(cloud_cluster_sdm_name),
                        "kubectl config use-context {}".format(cloud_cluster_sdm_name),
                        "[[ $(kubectl config current-context) == '{}' ]]".format(cloud_cluster_sdm_name)]
        else:
            cmd_list = ["sdm k8s update-config --force",
                        "sdm connect {}".format(cloud_cluster_sdm_name),
                        "kubectl config use-context {}".format(cloud_cluster_sdm_name),
                        "[[ $(kubectl config current-context) == '{}' ]]".format(cloud_cluster_sdm_name)]

        for cmd in cmd_list:
            logging.info("Running command [%s]" % cmd)
            self.exec_system_cmd(cmd, executable='/bin/bash')

        # In use for kubernetes library
        self.config = config.load_kube_config()
        self.client_v1 = client.CoreV1Api()

    def exec(self, command, timeout=None):
        logging.debug("EXEC: [kubectl {}]".format(command))

        try:
            if timeout is None:
                self.exec_system_cmd("kubectl {}".format(command), exit_code_expected=0)
            else:
                self.exec_system_cmd_timeout("kubectl {}".format(command), timeout=timeout)
        except:
            if "create" in command and "AlreadyExists".lower() in str(sys.exc_info()).lower():
                logging.debug(str(sys.exc_info()))
                logging.info("Skipping bad exit code since [AlreadyExists] found in command output")
                pass
            elif "delete" in command and "not found" in str(sys.exc_info()).lower():
                logging.debug(str(sys.exc_info()))
                logging.info("Skipping bad exit code since [not found] found in command output")
                pass
            else:
                raise

        return True

    def exec_system_cmd(self, command, exit_code_expected=0, return_output=False, executable='/bin/sh', print_stdout=True):
        """Wait_to_code is the exit code number to expect the function to return"""
        output_array = []
        subproc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   executable=executable)
        for line in subproc.stdout:
            log_line = "[{}]".format(line.decode('utf-8').rstrip())
            if print_stdout and log_line != "[]":
                logging.info(log_line)
            output_array.append(line.decode('utf-8'))

        out, err = subproc.communicate()
        exit_code = subproc.returncode
        logging.debug(exit_code)
        if exit_code_expected is not None and int(exit_code) != int(exit_code_expected):
            if "storageClass" in command and ("updates to parameters are forbidden" in str(err) or
                                              "updates to reclaimPolicy are forbidden" in str(err)):
                logging.debug("Ignoring bad exit code [{}] because of command stderr".format(exit_code))
            elif "get secret" in command and ("namespaces" in str(err) and "not found" in str(err)):
                logging.debug("Ignoring bad exit code [{}] because of command stderr for get secret".format(exit_code))
            else:
                raise Exception("Exit code '{}' of command `{}` not equal to '{}'. CMD Output: {}\n CMD Err: {}"
                                "".format(exit_code, command, exit_code_expected, out, err))
        if return_output:
            return output_array
        else:
            return True

    def exec_system_cmd_timeout(self, command, executable='/bin/sh', timeout=None):
        """Timeout after set time in seconds"""
        subproc = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   executable=executable, timeout=timeout)

        exit_code = subproc.returncode
        logging.debug(exit_code)

    def exec_system_plain_cmd_timeout(self, command, executable='/bin/sh', timeout=None):
        """Run the command in background, with timeout after set time in seconds"""
        subproc = subprocess.run(command, shell=True, timeout=timeout)

        exit_code = subproc.returncode
        logging.debug(exit_code)

    @staticmethod
    def do_shell_cmd(cmd, wait_to_code=None):
        """Wait_to_code is the exit code number to expect the function to return"""
        logging.debug("[do_shell_cmd] Running cmd [{}]".format(cmd))
        subproc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subproc.wait()
        out, err = subproc.communicate()
        out = out.strip()
        exit_code = subproc.returncode
        if wait_to_code is not None:
            if int(exit_code) != int(wait_to_code):
                msg = ("Exit code '%s' of command `%s` not equal to '%s'. CMD Output: %s| STDERR: %s"
                       % (exit_code, cmd, wait_to_code, out, err))
                logging.error(msg)

        logging.debug("[do_shell_cmd] CMD output [{}] CMD Error {}".format(str(out), str(err)))
        return {'output': out, 'exitcode': exit_code, 'error': err}

    def create_configmap_from_basedir(self, configmap_name, base_dir, namespace):
        """
        Create if not exists already
        :param namespace:
        :return:
        """
        from_files_list = ""

        for file in os.listdir(base_dir):
            from_files_list = from_files_list + " --from-file=" + os.path.join(base_dir, file)
        logging.debug("Going to create configmap [{}]".format(configmap_name))
        if version.parse(self.kubectl_version) >= version.parse('1.23.0'):
            command = f"-n {namespace} create configmap {configmap_name} {from_files_list} --dry-run=client --save-config -o yaml | kubectl apply -f -"
        else:
            command = f"-n {namespace} create configmap {configmap_name} {from_files_list} --dry-run --save-config -o yaml | kubectl apply -f -"
        self.exec(command)
        return True

    def create_secret_from_basedir(self, secret_name, base_dir, namespace):
        """
        Create if not exists already
        :param namespace:
        :return:
        """
        from_files_list = ""
        for file in os.listdir(base_dir):
            from_files_list = from_files_list + " --from-file=" + os.path.join(base_dir, file)
        logging.debug("Going to create secret [{}]".format(secret_name))
        if version.parse(self.kubectl_version) >= version.parse('1.23.0'):
            command = f"-n {namespace} create secret generic {secret_name} {from_files_list} --dry-run=client --save-config -o yaml | kubectl apply -f -"
        else:
            command = f"-n {namespace} create secret generic {secret_name} {from_files_list} --dry-run --save-config -o yaml | kubectl apply -f -"
        self.exec(command)
        return True

    def create_namespace(self, namespace):
        """
        Create if not exists already
        :param namespace:
        :return:
        """
        try:
            self.get_namespace(namespace)
            logging.debug("Namespace [{}] already exists ".format(namespace))

        except Exception:
            logging.debug("Going to create namespace [{}]".format(namespace))
            command = "create namespace {}".format(namespace)
            self.exec(command)

        return True

    def delete_namespace(self, namespace):
        """
        Delete namespace if not exists
        :param namespace:
        :return:
        """
        logging.info("Trying to delete namespace {}".format(namespace))
        try:
            self.exec("delete namespace {}".format(namespace))
            return True
        except Exception as e:
            if "not found" in str(e):
                logging.info("Namespace {} not found, nothing to do".format(namespace))
                return True
            else:
                logging.error("Failed to delete namespace {}".format(namespace))
                return False

    def get_namespace(self, namespace):
        command = "get namespace {}".format(namespace)
        self.exec(command)

        return True

    def update_namespace_label(self, namespace, namespace_label):

        command = "label --overwrite namespace {} {}".format(namespace, namespace_label)
        self.exec(command)

        return True

    def update_pod_label(self, namespace, pod_name, label_key, label_value):
        command = "-n {} label --overwrite pods {} {}={}".format(namespace, pod_name, label_key, label_value)
        self.exec(command)

        return True

    def update_pod_labels_by_lables(self, namespace, label_selector_dict, label_apply_dict={}):
        label_selector_list = ''
        for key, value in label_selector_dict.items():
            if len(label_selector_list) == 0:
                label_selector_list = "{}={}".format(key, value)
            else:
                label_selector_list = ",{}={}".format(key, value)
        for key, value in label_apply_dict.items():
            label_apply_list = "{}={} ".format(key, value)
        command = "-n {} label --overwrite pods -l {} {}".format(namespace, label_selector_list, label_apply_list)
        self.exec(command)

        return True

    def get_pods_by_label(self, namespace, label_key, label_value):
        pods = []
        pods_info = self.get_pods_info_by_label(label_key, label_value, namespace)

        for line in pods_info:
            pod = line.split()[0]
            pods.append(pod)
        return pods

    def get_pods_info_by_label(self, label_key, label_value, namespace):
        command = "-n {} get pods -l {}={}".format(namespace, label_key, label_value)
        logging.info("EXEC: kubectl {}".format(command))
        command_output = self.exec_system_cmd("kubectl {}".format(command),
                                              exit_code_expected=0,
                                              return_output=True)
        try:
            command_output.pop(0)
        except:
            logging.warning("Didn't get any pods matching label")
            return []

        return command_output

    def get_context(self):
        command = "config current-context"
        logging.info("EXEC: kubectl {}".format(command))
        command_output = self.exec_system_cmd("kubectl {}".format(command),
                                              exit_code_expected=0,
                                              return_output=True)[0].strip()
        return command_output

    def get_running_pods_info_by_name(self, namespace, pod_name_expr):
        command = f"kubectl -n {namespace} get pods | grep -v -e Terminating -e '\\-image\\-puller\\-'"
        logging.debug("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=0,
                                              return_output=True)
        return list(filter(lambda x: re.search(pod_name_expr, x), command_output))

    def get_pods(self, namespace, pod_name_prefix):
        command = f"kubectl -n {namespace} get pods | grep '^{pod_name_prefix}'"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def get_dployment_jsons(self, namespace):
        command = f"kubectl -n {namespace} get deploy -o json"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True,
                                              print_stdout=False)
        return json.loads("\n".join(command_output))

    def get_sts_jsons(self, namespace):
        command = f"kubectl -n {namespace} get sts -o json"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True,
                                              print_stdout=False)
        return json.loads("\n".join(command_output))

    def get_pod_info(self, namespace, pod_name):
        command = f"kubectl -n {namespace} get pod {pod_name} | grep -v NAME"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def force_kill_pod(self, namespace, pod_name):
        command = f"kubectl -n {namespace} delete pod {pod_name} --force --grace-period 0"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def kill_vault_pod(self, namespace, pod_state):
        command = f"kubectl -n {namespace} delete pod --selector=vault-active={pod_state}"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def check_vault_pod_label(self, namespace, pod_name):
        command = f"kubectl -n {namespace} get pod {pod_name} --show-labels | grep vault-active"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def get_sts(self, namespace, sts_name):
        command = f"kubectl -n {namespace} get sts | grep '{sts_name}'| awk '{{print $1}}'"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def get_deployment(self, namespace):
        command = f"kubectl -n {namespace} get deployment | awk 'NR>1 {{print $1}}'"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def get_pvc(self, namespace, pvc_name):
        command = f"kubectl -n {namespace} get pvc | grep '{pvc_name}'"
        logging.info("EXEC: {}".format(command))
        command_output = self.exec_system_cmd(command,
                                              exit_code_expected=None,
                                              return_output=True)
        return command_output

    def check_if_svc_exists(self, namespace, svc_name):
        command = f"-n {namespace} get svc {svc_name}"

        try:
            self.exec(command=command)
            logging.debug(f"Service [{svc_name}] exists in namespace [{namespace}]")
            return True
        except:
            logging.debug(f"Service [{svc_name}] doesn't exist in namespace [{namespace}]")
            return False

    def check_if_pod_exists(self, namespace, pod_name):
        logging.info("Checking if pod [{}] exists".format(pod_name))
        command = "-n {} get pods | grep {}".format(namespace, pod_name)
        try:
            logging.debug("Running command: kubectl {}".format(command))
            self.exec(command=command)
            logging.info("Pod [{}] is exists".format(pod_name))
            return True
        except:
            logging.info("Pod [{}] not exists".format(pod_name))
            return False

    def get_public_address_from_svc(self, namespace, svc, retry_seconds=100):
        """
        :param namespace:
        :param svc:
        :param retry_seconds:
        :return:
        """

        public_adrress = None
        sleep_sec = 5
        retries = int(retry_seconds / sleep_sec)

        logging.info("Trying to get {} public address in namespace {}".format(svc, namespace))

        for i in range(0, retries):
            while True:
                ret = self.client_v1.read_namespaced_service(name=svc, namespace=namespace)
                logging.debug("get_public_address_from_svc {}/{}".format(i, retries))
                if ret.status.load_balancer.ingress:
                    logging.debug(ret.status.load_balancer.ingress)
                    break

                logging.debug("get_public_address_from_svc slepping for {} sec".format(sleep_sec))
                time.sleep(sleep_sec)

        external_addrss = ret.status.load_balancer.ingress[0]
        logging.debug(external_addrss)

        hostname = external_addrss.hostname
        ip = external_addrss.ip

        if hostname:
            logging.info("hostname = [{}]".format(hostname))
            public_adrress = hostname

        if ip:
            logging.info("ip = [{}]".format(ip))
            public_adrress = ip

        return public_adrress

    def get_svc_public_address(self, namespace, svc_name, wait_timeout=300):
        t_end = time.time() + wait_timeout

        while time.time() < t_end:
            command = "-n {} describe svc {} | grep \"LoadBalancer Ingress\" | awk '{{print $3}}'".format(
                namespace, svc_name)
            logging.info("EXEC: kubectl {}".format(command))
            try:
                public_address = self.exec_system_cmd("kubectl {}".format(command),
                                                      exit_code_expected=0,
                                                      return_output=True)[0].replace("\n", "")
            except:
                time.sleep(5)
                public_address = "Not found yet"

            if self.validate_ip(public_address):
                logging.info("Got a valid IP address")
                return public_address
            elif self.validate_dns(public_address):
                logging.info("Got a valid DNS")
                return public_address
            else:
                logging.warning("Didn't get valid public address as DNS or IP, trying again")
        raise RuntimeError(f"Couldn't get public address of svc {svc_name}")

    # TODO: Copied from functions/tools should fix import issue
    @staticmethod
    def validate_ip(ip_string):
        logging.debug("validate_ip for {}".format(ip_string))
        octets = ip_string.split('.')
        if len(octets) != 4:
            logging.warning("String not an IP address, not an IP format w.x.y.z [{}]".format(octets))
            return False
        for octet in octets:
            if not octet.isdigit():
                logging.warning("String not an IP address, not an IP format w.x.y.z [{}]".format(octets))
            return False
            i = int(octet)
            if i < 0 or i > 255:
                logging.warning("String not an IP address, not an IP format w.x.y.z [{}]".format(octets))
            return False
        return True

    @staticmethod
    def validate_dns(dns_string):
        sub_domains = dns_string.split('.')
        if len(sub_domains) < 3:
            logging.error("String not a valid DNS address, too few sub domains")
            return False
        return True

    @staticmethod
    def verify_string_not_in_logfile(namespace, pod_name, container_name, log_file, search_query):

        grep_command = "kubectl -n {ns} exec -it {pod} -c {container}  -- grep -w \"{query}\" {logfile}".format(
            ns=namespace,
            pod=pod_name,
            container=container_name,
            query=search_query,
            logfile=log_file)

        logging.debug("Running ... [{}]".format(grep_command))
        grep_exec = JfrogKubectlCli.do_shell_cmd(cmd=grep_command)
        grep_output = grep_exec["output"]

        try:
            grep_output = grep_exec["output"].decode('utf-8')
        except:
            pass

        if grep_exec['exitcode'] == 0:
            raise SystemError("Application has a critical error, check log [{}]\n[{}]\nFound [{}] in [{}] pod [{}]".
                              format(log_file, grep_output, search_query, log_file, pod_name))

        logging.debug("String [{}] was not found in [{}]".format(search_query, log_file))
        return True

    def verify_application_logs(self, critical_log_entries, namespace, pod_name):
        # Pod is not ready, check if application has some critical log entries
        for container in critical_log_entries["containers"]:
            container_info = critical_log_entries["containers"][container]
            logging.info("Checking logs for [{}]".format(container))
            for log_file in container_info:
                log_info = container_info[log_file]
                logging.debug("Checking file [{}]".format(log_file))
                for search_query in log_info:
                    self.verify_string_not_in_logfile(namespace,
                                                      pod_name,
                                                      container,
                                                      log_file,
                                                      search_query)
        return True

    def check_if_pod_running(self, namespace, pod_name):
        logging.info("Checking if pod [{}] running".format(pod_name))
        command = "-n {} get pods | grep {} | grep -w Running".format(namespace, pod_name)
        try:
            logging.debug("Running command: kubectl {}".format(command))
            self.exec(command=command)
            logging.info("Pod [{}] is running".format(pod_name))
            self.check_if_pod_ready(namespace, pod_name)
            return True
        except:
            logging.info("Pod [{}] not running / ready".format(pod_name))
            # self.log_unready_containers_in_pod(namespace, pod_name)
            return False

    def check_if_pod_ready(self, namespace, pod_name):
        logging.info("Checking if all containers in pod [{}] are ready".format(pod_name))
        command = "kubectl -n {} get pods | grep {}  | awk '{{print $2}}'".format(namespace, pod_name)
        command_output = self.exec_system_cmd(command=command, return_output=True)[0].rstrip()
        num_of_ready = command_output.split("/")
        if num_of_ready[0] == num_of_ready[1]:
            logging.info("All containers in pod [{}] are ready [{}]".format(pod_name, command_output))
            return True
        raise RuntimeError("Not all containers in pod [{}] are running".format(pod_name))

    def number_of_pods_per_sts(self, namespace, pod_name_expr, all_states=False):
        logging.info(f"Checking how many replicas of pods [{pod_name_expr}] are running")
        command = f"kubectl -n {namespace} get pods | grep Running"
        if all_states:
            command = f"kubectl -n {namespace} get pods"

        command = command + " | awk '{print $1}'"
        try:
            command_output = self.exec_system_cmd(command=command, return_output=True)
        except:
            return 0

        pod_name_regex = f"{pod_name_expr}-\d+"
        num_of_replicas = 0
        if isinstance(command_output, list):
            for pod in command_output:
                if re.match(pod_name_regex, pod) is not None:
                    logging.info(f"Found match with [{pod}] !")
                    num_of_replicas = num_of_replicas + 1

        logging.info(f"Number of current replicas of [{pod_name_expr}] is [{num_of_replicas}]")
        return num_of_replicas

    def number_of_pods_per_deployment(self, namespace, pod_name_expr, all_states=False):
        logging.info(f"Checking how many replicas of pods [{pod_name_expr}] are running")
        command = f"kubectl -n {namespace} get pods | grep Running"
        if all_states:
            command = f"kubectl -n {namespace} get pods"

        command = command + " | awk '{print $1}'"
        try:
            command_output = self.exec_system_cmd(command=command, return_output=True)
        except:
            return 0

        pod_name_regex = f"{pod_name_expr}-\d+"
        num_of_replicas = 0
        if isinstance(command_output, list):
            for pod in command_output:
                if re.match(pod_name_regex, pod) is not None:
                    logging.info(f"Found match with [{pod}] !")
                    num_of_replicas = num_of_replicas + 1

        logging.info(f"Number of current replicas of [{pod_name_expr}] is [{num_of_replicas}]")
        return num_of_replicas

    def verify_pod_app_version(self, namespace, pod_name, app_version):
        command = "-n {} describe pod {} | grep :{}".format(namespace, pod_name, app_version)
        logging.info(command)
        self.exec(command)
        logging.info("Pod version is correct [{}]".format(app_version))
        return True

    def get_value_label(self, namespace, pod_name, grep_by):
        command = "kubectl -n {} describe pod {} | grep {}".format(namespace, pod_name, grep_by)
        describe_output = self.exec_system_cmd(command, exit_code_expected=0, return_output=True)
        return describe_output

    def get_image_version(self, namespace, pod_name, grep_by):
        command = "kubectl -n {} get pod {} -o yaml | grep {}".format(namespace, pod_name, grep_by)
        get_output = self.exec_system_cmd(command, exit_code_expected=0, return_output=True)
        return get_output

    def get_chart_version(self, namespace, secret, grep_by):
        command = "kubectl -n {} describe secret {} | grep {}".format(namespace, secret, grep_by)
        describe_output = self.exec_system_cmd(command, exit_code_expected=0, return_output=True)
        return describe_output

    def kill_pod_if_bad_state(self, namespace, pod_name):
        pod_info = self.get_pod_info(
            namespace=namespace, pod_name=pod_name)

        if not pod_info:
            return

        pod_status = pod_info[0].split()[2]
        logging.info(f"Pod [{pod_name}] status is [{pod_status}]")

        if pod_status in ["Init:CreateContainerConfigError", "CreateContainerConfigError", "CrashLoopBackOff", "Init:CrashLoopBackOff", "ErrImagePull", "ImagePullBackOff", "Init:ErrImagePull", "Init:ImagePullBackOff"]:
            logging.warning(f"Pod [{pod_name}] in [{pod_status}] state!")
            if self.kill_pod_state:
                logging.info(f"Pod [{pod_name}] was already killed once, skipping pod kill")
            else:
                self.kill_pod_state = True
                logging.warning(f"Going to kill pod [{pod_name}] to recover")
                self.force_kill_pod(namespace=namespace, pod_name=pod_name)

    @prom_decorator()
    def verify_pod_running_and_correct_version(self, namespace, pod_name, app_version, timeout_override=None,
                                               kill_pod=False, critical_log_entries={}):

        timeout_after = self.get_pod_readiness_timeout_sec(namespace, pod_name) + \
                        (float(timeout_override) if timeout_override else 0)

        logging.info(f"Setting timeout to {timeout_after} sec")
        t_end = time.time() + timeout_after

        while time.time() < t_end:
            try:
                if critical_log_entries != {}:
                    self.verify_application_logs(critical_log_entries, namespace, pod_name)
                else:
                    logging.debug("No critical log entries to look for, skipping...")
                logging.info("Verifying pod [{}] is running in the correct version".format(pod_name))
                if self.check_if_pod_running(namespace, pod_name):
                    self.verify_pod_app_version(namespace, pod_name, app_version)
                else:
                    raise RuntimeError("Pod is not running")
                return True
            except SystemError:
                logging.error("Found major issue")
                raise
            except:
                if kill_pod:
                    self.kill_pod_if_bad_state(namespace, pod_name)
                logging.info("Pod [{}] not ready yet, waiting for [{}] more seconds...".format(
                    pod_name,
                    int(t_end - time.time())))
                pass
            time.sleep(10)

        command = "kubectl -n {} describe pod {}".format(namespace, pod_name)
        describe_output = self.exec_system_cmd(command, return_output=True)
        describe_string = ""
        for line in describe_output:
            describe_string = "{}{}".format(describe_string, line + '\n')
        raise TimeoutError("Pod [{}] exceeded [{}] seconds and failed to start.\n\n[{}] Output:\n\n{}".
                           format(pod_name, timeout_after, command, describe_string))

    def scale_sts(self, num_of_replicas, sts_name, namespace, wait_completed=True):
        logging.info("Trying to scale sts [{}] to [{}] replicas".format(sts_name, num_of_replicas))
        scale_command = "-n {} scale sts {} --replicas={}".format(namespace, sts_name, num_of_replicas)
        wait_command = "-n {} rollout status sts/{}".format(namespace, sts_name, num_of_replicas)
        try:
            self.exec(command=scale_command)
            if wait_completed:
                logging.info("Waiting for scaling operation to be completed")
                self.exec(command=wait_command)
        except:
            tb = traceback.format_exc()
            logging.error(f"Couldn't scale sts [{sts_name}]! Exception is: {tb}")
            return False
        return True

    def restart_sts(self, sts_name, namespace):
        logging.info("Trying to restart sts [{}]".format(sts_name))
        restart_command = "-n {} rollout restart sts/{}".format(namespace, sts_name)
        wait_command = "-n {} rollout status sts/{}".format(namespace, sts_name)
        try:
            self.exec(command=restart_command)
            logging.info("Waiting for restart operation to be completed")
            self.exec(command=wait_command, timeout=1800)
        except:
            logging.error("Couldn't restart sts [{}]".format(sts_name))
            return False
        return True

    def restart_deployment(self, deployment_name, namespace):
        logging.info("Trying to restart deployment [{}]".format(deployment_name))
        restart_command = "-n {} rollout restart deployment/{}".format(namespace, deployment_name)
        wait_command = "-n {} rollout status deployment/{}".format(namespace, deployment_name)
        try:
            self.exec(command=restart_command)
            logging.info("Waiting for restart operation to be completed")
            self.exec(command=wait_command)
        except:
            logging.error("Couldn't restart deployment [{}]".format(deployment_name))
            return False
        return True

    def delete_sts(self, sts_name, namespace, wait_all_gone=False):
        logging.info("Trying to delete sts [{}]".format(sts_name))
        delete_command = "-n {} delete statefulsets/{}".format(namespace, sts_name)
        wait_command = "-n {} get sts/{}".format(namespace, sts_name)
        try:
            self.exec(command=delete_command)
            logging.info("Waiting for delete operation to be completed")
            self.exec(command=wait_command)
            logging.info("Delete sts operation completed with success")
        except:
            logging.error("Couldn't delete sts [{}] (already deleted?)".format(sts_name))

        if wait_all_gone:
            logging.info("Waiting for all pods to be gone")
            t_end = time.time() + 500
            while time.time() < t_end:
                num_of_pods = self.number_of_pods_per_sts(namespace=namespace, pod_name_expr=sts_name, all_states=True)
                if num_of_pods == 0:
                    logging.info("No pods are left for the sts[{}]".format(sts_name))
                    return True
                else:
                    logging.warning("Waiting for all pods to be gone for the sts [{}] ({})".format(sts_name,
                                                                                                   num_of_pods))
                time.sleep(2)
            raise RuntimeError("Pods are still running on sts [{}] after 5 minutes".format(sts_name))

        return True

    def delete_deployment(self, deployment_name, namespace, wait_all_gone=False):
        logging.info("Trying to delete deployment [{}]".format(deployment_name))
        delete_command = "-n {} delete deployments/{}".format(namespace, deployment_name)
        wait_command = "-n {} get deployment/{}".format(namespace, deployment_name)
        try:
            self.exec(command=delete_command)
            logging.info("Waiting for delete operation to be completed")
            self.exec(command=wait_command)
            logging.info("Delete deployment operation completed with success")
        except:
            logging.error("Couldn't delete deployment [{}] (already deleted?)".format(deployment_name))

        if wait_all_gone:
            logging.info("Waiting for all pods to be gone")
            t_end = time.time() + 500
            while time.time() < t_end:
                num_of_pods = self.number_of_pods_per_deployment(namespace=namespace, pod_name_expr=deployment_name, all_states=True)
                if num_of_pods == 0:
                    logging.info("No pods are left for the deployment[{}]".format(deployment_name))
                    return True
                else:
                    logging.warning("Waiting for all pods to be gone for the deployment [{}] ({})".format(deployment_name,
                                                                                                   num_of_pods))
                time.sleep(2)
            raise RuntimeError("Pods are still running on deployment [{}] after 5 minutes".format(deployment_name))

        return True

    def is_ing_exists(self, ing_name: str, namespace: str):
        logging.debug(f"Checking if ing [{ing_name}] exists...")
        get_command = f"-n {namespace} get ing {ing_name}"
        try:
            self.exec(command=get_command)
        except:
            tb = traceback.format_exc()
            logging.debug(f"Couldn't get ing [{ing_name}]")
            return False

        return True

    def delete_ing(self, ing_name: str, namespace: str):
        logging.info("Trying to delete ing [{}]".format(ing_name))
        delete_command = "-n {} delete ing {}".format(namespace, ing_name)
        try:
            logging.info("Starting delete operation...")
            self.exec(command=delete_command)
        except:
            logging.error("Couldn't delete ing [{}]".format(ing_name))
            return False

        logging.info("Delete ing operation completed with success")

        return True

    def delete_svc(self, svc_name, namespace):
        logging.info("Trying to delete svc [{}]".format(svc_name))
        delete_command = "-n {} delete svc {}".format(namespace, svc_name)
        try:
            logging.info("Starting delete operation...")
            self.exec(command=delete_command)
        except:
            logging.error("Couldn't delete svc [{}]".format(svc_name))
            return False

        logging.info("Delete svc operation completed with success")

        return True

    def copy_file(self, source_path, destination_path):

        command = "cp {} {}".format(source_path, destination_path)
        self.exec(command)

        return True

    def download_file(self, source_path, destination_path, container, pod, namespace, use_shutil=True):

        source_path_pod = "{}/{}:{} -c {}".format(namespace, pod, source_path, container)
        if use_shutil:
            # workaround since tar version on the distroless docker image missing factually
            destination_path_tmp = "{}.tmp".format(uuid.uuid4().hex)
            self.copy_file(source_path_pod, destination_path_tmp)
            shutil.move(destination_path_tmp, destination_path)
        else:
            self.copy_file(source_path_pod, destination_path)

        file_exists = os.path.isfile(destination_path)
        if file_exists:
            logging.info("File was downloaded to filesystem [{}]".format(destination_path))
        else:
            raise Exception("Couldn't download file from [{}] to filesystem [{}]"
                            "".format(source_path_pod, destination_path))

        return True

    def upload_file(self, source_path, destination_path, container, pod, namespace):

        destination_path_pod = "{}/{}:{} -c {}".format(namespace, pod, destination_path, container)
        self.copy_file(source_path=source_path, destination_path=destination_path_pod)

        command = "-n {} exec -it {} -c {} -- bash -c \"ls -ltr {}\"".format(namespace, pod, container,
                                                                             destination_path)
        file_exists = self.exec(command)
        if file_exists:
            logging.info("File/s got uploaded to container's filesystem [{}]".format(destination_path))
        else:
            raise Exception("Couldn't upload file/s [{}] to container's filesystem [{}]"
                            "".format(source_path, destination_path))

        return True

    def uploaded_file_unzip(self, zip_file_path, destination_path, container, pod, namespace):

        command = "-n {} exec -it {} -c {} -- bash -c \"unzip -q {}/*.zip -d {}\"".format(namespace, pod, container,
                                                                             zip_file_path, destination_path)
        file_unzip = self.exec(command)
        if file_unzip:
            logging.info(
                "File/s got unzipped in container's filesystem [{}]".format(destination_path))
        else:
            raise Exception("Couldn't unzip file/s [{}/*.zip] in container's filesystem [{}]"
                            "".format(zip_file_path, destination_path))

        return True

    def del_pod_folder(self, destination_path, container, pod, namespace):

        command = "-n {} exec -it {} -c {} -- bash -c \"rm -rf {}\"".format(namespace, pod, container, destination_path)
        self.exec(command)

        return True

    def wait_pod_file_creation(self, file_path, container, pod, namespace, timeout=15):

        command = "-n {} exec -it {} -c {} -- bash -c \"while [ ! -f {} ]; do sleep 1; done\"".format(namespace, pod, container, file_path)
        file_exists = self.exec(command, timeout=timeout)

        if file_exists:
            logging.info("File [{}] got created in container's filesystem".format(file_path))
        else:
            raise Exception("Couldn't find file [{}] in container's filesystem""".format(file_path))

        return True

    def get_pod_file_content(self, file_path, container, pod, namespace):

        command = "kubectl -n {} exec -it {} -c {} -- bash -c \"cat {}\"".format(namespace, pod, container, file_path)
        get_output = self.exec_system_cmd(command, exit_code_expected=0, return_output=True)

        return get_output

    def port_forward(self, service, port, namespace, background=None, timeout=0):

        logging.info("Listen to remote port number [{}][{}] -n [{}]".format(service, port, namespace))
        if background:
            command = "{} kubectl port-forward -n {} service/{} {} &".format(f"timeout {timeout}", namespace, service, port)
        else:
            command = "{} kubectl port-forward -n {} service/{} {}".format(f"timeout {timeout}", namespace, service, port)

        self.exec_system_plain_cmd_timeout(command, executable='/bin/bash')

    def status(self):
        """
        check k8s connectivity
        :return:
        """
        logging.info("Check if cluster is accessible")
        cmd = "cluster-info"
        self.exec(cmd)

    def get_secret(self, namespace, secret_name):
        """
        Get k8s Secret
        :param secret_name:
        :param namespace:
        :return:
        """
        self.maintain_secret("get", namespace, secret_name)
        return True

    def set_secret_tls(self, secret_name, namespace, secret_key_file_path, secret_crt_file_path):
        """
        Set k8s TLS Secret for SSL Offload
        :param secret_name:
        :param namespace:
        :param secret_key_file_path:
        :param secret_crt_file_path:
        :return:
        """

        extra_cmd = "--key={} --cert {}".format(secret_key_file_path, secret_crt_file_path)
        self.maintain_secret("create", namespace, secret_name, extra_cmd=extra_cmd, secret_type="tls", force=True)
        return True

    def set_secret_docker_registry(self, secret_name, namespace, docker_server, docker_username, docker_password,
                                   docker_email=None):
        """

        :param secret_name:
        :param namespace:
        :param docker_server:
        :param docker_username:
        :param docker_password:
        :param docker_email:
        :return:
        """

        if docker_email is None:
            docker_email = "devops-team@jfrog.com"

        extra_cmd = "--docker-server={}  --docker-username={}  --docker-password={}  --docker-email={}" \
                    "".format(docker_server, docker_username, docker_password, docker_email)
        self.maintain_secret("create", namespace, secret_name, extra_cmd=extra_cmd, secret_type="docker-registry",
                             force=True)
        return True

    def set_secret_user_password(self, namespace, secret_name, user, password):
        """
        Set k8s Generic Secret from with user and password keys
        :param secret_name:
        :param namespace:
        :param user:
        :param password:
        :param type:
        :return:
        """

        extra_cmd = "--from-literal=user={} --from-literal=password={}".format(type,
                                                                               secret_name,
                                                                               namespace, user,
                                                                               password)
        self.maintain_secret("create", namespace, secret_name, extra_cmd, force=True)
        return True

    def set_secret_from_file(self, namespace, secret_name, file_path, file_name=None):
        """
        Set k8s Generic Secret from file
        :param secret_name:
        :param namespace:
        :param file_path:
        :return:
        """

        if file_name is None:
            file_name = os.path.basename(file_path)
        extra_cmd = "--from-file={}={}".format(file_name, file_path)
        self.maintain_secret("create", namespace, secret_name, extra_cmd=extra_cmd, force=True)
        return True

    def delete_secret(self, namespace, secret_name):
        """
        Delete k8s Secret
        :param secret_name:
        :param namespace:
        :return:
        """

        try:
            if self.get_secret(namespace, secret_name):
                pass
        except Exception as e:
            logging.warning(e)
            logging.warning("Secret {} does not exits for {}".format(secret_name, namespace))
            return True

        self.maintain_secret("delete", namespace, secret_name, secret_type="")
        return True

    def maintain_secret(self, action, namespace, secret_name, secret_type=None, extra_cmd='', force=True):
        """
        Allow multiple actions on k8s Secret
        :param action:
        :param namespace:
        :param secret_name:
        :param secret_type:
        :param extra_cmd:
        :param force:
        :return:
        """
        if secret_type is None and action == "get":
            secret_type = ""
        elif secret_type is None:
            secret_type = "generic"

        if force and action == "create":
            logging.info("{} secret is been forced".format(action.capitalize()))
            logging.info("Delete secret before creating a new secret")
            try:
                self.delete_secret(namespace, secret_name)
            except Exception as e:
                logging.warning(e)

        if action == "replace":
            logging.info("Delete old secret if exists before creating a new secret for the new registry")
            try:
                self.delete_secret(namespace, secret_name)
            except Exception as e:
                logging.warning(e)

        logging.info("{} secret, type=[{}], name=[{}], namespace=[{}]"
                     "".format(action.capitalize(), secret_type, secret_name, namespace))
        cmd = "{} secret {} {} -n {} {}".format(action, secret_type, secret_name, namespace, extra_cmd)
        try:
            self.exec(cmd)
        except:
            if "already exists" in str(sys.exc_info()):
                logging.info("Skipping [already exists] error found in output")
                pass
            else:
                raise
        return True

    def apply_certificate(self, secret_name, tls, namespace):
        logging.info(f"Applying [{secret_name}] cert on namespace [{namespace}] server")
        env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates'), keep_trailing_newline=True)
        kubectl_tls_secret_yaml_template = env.get_template("tools/kubectl-tls-secret.yaml.j2")
        with tempfile.NamedTemporaryFile(suffix=".yaml") as kubectl_tls_secret_yaml_file:
            kubectl_tls_secret_yaml_config = {"secret_name": secret_name,
                                              "tls_crt": tls["cert"],
                                              "tls_key": tls["key"]}
            kubectl_tls_secret_yaml = kubectl_tls_secret_yaml_template.render(kubectl_tls_secret_yaml_config)
            kubectl_tls_secret_yaml_file.write(kubectl_tls_secret_yaml.encode('utf-8'))
            kubectl_tls_secret_yaml_file.flush()
            cmd = "apply --namespace {} -f {}".format(namespace, kubectl_tls_secret_yaml_file.name)
            self.exec(cmd)
        return True

    def list_to_string(ls):
        # initialize an empty string
        str1 = " "

        # return string
        return (str1.join(ls))

    def info(self):
        """
        Get K8S cluster Info
        :param self:
        :return:
        """

        logging.info("CLOUD_PROVIDER = {}".format(self.cloud_provider))
        logging.info("PROJECT = {}".format(self.project))
        logging.info("CLOUD_ZONE = {}".format(self.zone))
        logging.info("CLUSTER = {}".format(self.cluster))

    def get_secret_data(self, namespace, secret_name):
        cmd = "kubectl get secret {} --namespace={} -o yaml".format(secret_name, namespace)
        data = self.exec_system_cmd(cmd, return_output=True, print_stdout=False)
        if data:
            return "".join(data)
        else:
            return None

    def get_secret_specific_data(self, namespace, secret_name, jsonpath):
        cmd = "kubectl get secret {} --namespace={} -o jsonpath={} | base64 -d".format(secret_name, namespace, jsonpath)
        data = self.exec_system_cmd(cmd, return_output=True, print_stdout=False)
        if data:
            return "".join(data)
        else:
            return None

    def kubectl_apply(self, namespace, yaml_data):
        cmd = "echo '{}' | kubectl apply --namespace={} -f -".format(yaml_data.replace('\n', '\\n'), namespace)
        return self.exec_system_cmd(cmd)

    def kubectl_replace(self, yaml_file, namespace=None):
        if namespace:
            self.exec(command="replace --namespace={} -f {}".format(namespace, yaml_file))
        else:
            self.exec(command="replace -f {}".format(yaml_file))

    def kubectl_apply_file(self, namespace, yaml_file):

        if namespace == "None":
            cmd = "kubectl apply -f {}".format(yaml_file)
        else:
            cmd = "kubectl apply --namespace={} -f {}".format(namespace, yaml_file)
        return self.exec_system_cmd(cmd)

    def kubectl_patch_file(self, namespace, yaml_file, deployment_name):
        cmd = f"kubectl -n {namespace} patch deployment {deployment_name} --patch-file {yaml_file}"
        return self.exec_system_cmd(cmd)

    def set_secret_data(self, namespace, secret_data):
        return self.kubectl_apply(namespace, yaml_data=secret_data)

    def check_if_secret_exists(self, namespace, secret_name):
        try:
            self.maintain_secret("get", namespace, secret_name)
        except Exception as e:
            logging.warn("Secret {} doesnt exists".format(secret_name))
            return False
        return True

    def replace_if_secret_exists(self, namespace, secret_name):
        if self.check_if_secret_exists(namespace=namespace, secret_name=secret_name):
            try:
                self.maintain_secret("replace", namespace, secret_name)
            except Exception as e:
                logging.warn("Secret {} doesnt exists".format(secret_name))
                return False
            return True

    def check_if_pvc_exists(self, namespace, pvc_name):
        logging.info("Trying to find pvc [{}]".format(pvc_name))
        search_command = "-n {} get pvc {} | grep Bound".format(namespace, pvc_name)
        try:
            logging.debug("Running command: kubectl {}".format(search_command))
            self.exec(command=search_command)
            logging.info("Found pvc [{}]".format(pvc_name))
            return True
        except:
            logging.info("PVC {} doesnt exists".format(pvc_name))
            return False

    def delete_pvc(self, pvc_name, namespace):
        logging.info("Trying to delete pvc [{}]".format(pvc_name))
        delete_command = "-n {} delete pvc/{}".format(namespace, pvc_name)
        wait_command = "-n {} get pvc {}/".format(namespace, pvc_name)
        try:
            self.exec(command=delete_command)
            logging.info("Waiting for delete operation to be completed")
            self.exec(command=wait_command)
            logging.info("Delete pvc operation completed with success")

        except:
            logging.error("Couldn't delete pvc [{}]".format(pvc_name))
            return False
        return True

    def get_probe_timeout(self, k8s_object, probe_key: str):
        probe_updated = False
        probe = {
            # Prod k8s default values
            # https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#configure-probes
            "initialDelaySeconds": 0,
            "periodSeconds": 10,
            "timeoutSeconds": 1,
            "successThreshold": 1,
            "failureThreshold": 3
        }
        if probe_key in k8s_object.keys():
            probe.update(k8s_object[probe_key])
            probe_updated = True
        if probe_updated:
            return probe["initialDelaySeconds"] + probe["failureThreshold"] * probe["periodSeconds"]
        return 0

    def get_pod_readiness_timeout_sec(self, namespace, pod_name_expr):
        logging.info(f"Calculating pods readiness timeout")
        deployments = self.get_dployment_jsons(namespace)
        sts = self.get_sts_jsons(namespace)
        items = deployments["items"] + sts["items"]
        timeout_sec = 0
        for d in items:
            current_timeout_sec = 0
            item_name = d["metadata"]["name"]
            if pod_name_expr.split("-0")[0] in item_name:  # to avoid specific sts instance (ends with -0)
                containers = []
                try:
                    containers = d["spec"]["template"]["spec"]["containers"]
                except:
                    logging.error(f"can't find pod containers of [{item_name}]...")
                for c in containers:
                    readiness = self.get_probe_timeout(c, "readinessProbe")
                    liveness = self.get_probe_timeout(c, "livenessProbe")
                    startup = self.get_probe_timeout(c, "startupProbe")
                    current_timeout_sec = max([readiness, liveness, startup, current_timeout_sec])
                    logging.debug(
                        f"readinessProbe = [{readiness}], livenessProbe = [{liveness}], startupProbe = [{startup}]")
                    logging.debug(f"current_timeout_sec = [{current_timeout_sec}]")
                replicas_count = d["spec"]["replicas"]
                try:
                    replicas_count = d["status"]["replicas"]
                except:
                    logging.warning("no current replicas found in object status section - using default")
                current_timeout_sec = current_timeout_sec*replicas_count
                timeout_sec = max([timeout_sec, current_timeout_sec])
        if timeout_sec == 0:
            logging.warning(
                "No pods found in deployed resources or there are no probes set - setting default timeout [600]")
            return 600
        return timeout_sec

    def wait_until_pods_are_up(self, namespace, pod_name_expr, min_pods_number: int = -1, max_pods_number: int = -1,
                               wait_before_retry=10, timeout_after=None):
        if timeout_after is None:
            timeout_after = self.get_pod_readiness_timeout_sec(namespace, pod_name_expr)
            timeout_after = max(timeout_after, 300)

        logging.info(f"Setting timeout to {timeout_after} sec")
        logging.info(f"Checking if pods are running... pod_name_expr=[{pod_name_expr}]")
        t_end = time.time() + timeout_after

        while time.time() < t_end:
            ready_pods_num = 0
            pods_info = self.get_running_pods_info_by_name(namespace=namespace,
                                                           pod_name_expr=pod_name_expr)
            formatted_pods_info = '\n'.join(pods_info)
            logging.info(f"Got the following pods:\n{formatted_pods_info}")
            is_all_running = True
            if len(pods_info) == 0:
                is_all_running = False

            for line in pods_info:
                pod_details = line.split()
                if pod_details[2] != 'Running':
                    is_all_running = False
                    logging.info('Pod {} is still in status {}'.format(pod_details[0], pod_details[2]))
                elif not self.is_all_containers_running(pod_details[1]):
                    is_all_running = False
                    logging.info('Pod {}, not all containers running: {}'.format(pod_details[0], pod_details[1]))
                else:
                    ready_pods_num += 1

            pods_num = len(pods_info)
            if min_pods_number != -1 and pods_num < min_pods_number:
                logging.info(f'Found [{pods_num}] pods, expecting minimum [{min_pods_number}]')
                is_all_running = False

            if max_pods_number != -1 and pods_num > max_pods_number:
                logging.info(f'Found [{pods_num}] pods, expecting maximum [{max_pods_number}]')
                is_all_running = False

            if min_pods_number != -1 and ready_pods_num >= min_pods_number:
                logging.info(f'Found [{ready_pods_num}/{pods_num}] ready pods, which passes minimum required [{min_pods_number}]')
                is_all_running = True

            if not is_all_running and timeout_after > 10:
                logging.info('Waiting {} seconds...'.format(wait_before_retry))
                time.sleep(wait_before_retry)
            else:
                logging.info('Finished waiting for pods to come up')
                return True

        return False

    def wait_until_pods_are_terminated(self, namespace, pod_name_prefix, timeout_after=600, wait_before_retry=10):
        logging.info(f'Waiting for pods {pod_name_prefix} to terminate...')
        t_end = time.time() + timeout_after
        while time.time() < t_end:
            pods_info = self.get_pods(namespace=namespace, pod_name_prefix=pod_name_prefix)

            if len(pods_info) > 0:
                logging.info('Pods are still running.')
                logging.info('Waiting {} seconds...'.format(wait_before_retry))
                time.sleep(wait_before_retry)
            else:
                return True

        return False

    def is_all_containers_running(self, pod_containers_count):
        container_count = pod_containers_count.split('/')
        return container_count[0] == container_count[1]

    def is_no_containers_running(self, pod_containers_count):
        container_count = pod_containers_count.split('/')
        return int(container_count[0]) == 0

    def get_nodes(self):
        """
        Get K8S cluster Nodes
        """
        nodes = self.client_v1.list_node().to_dict()
        return nodes

    def get_pods_in_node(self, node):
        """
        Get pods in Node
        """
        field_selector = 'spec.nodeName=' + node
        pods = self.client_v1.list_pod_for_all_namespaces(watch=False, field_selector=field_selector)
        return pods

    def valid_object(self, my_object):
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

    def scale_hpa(self, hpa_name: str, sts_name: str, namespace: str, min_replicas: int, max_replicas: int) -> bool:
        logging.info(f"Trying to scale HPA [{hpa_name}] to [{min_replicas}] min_replicas and [{max_replicas}] "
                     f"max_replicas")
        patch_expr = '{"spec":{"minReplicas":' + str(min_replicas) + ', "maxReplicas":' + str(max_replicas) + '}}'
        scale_command = f"-n {namespace} patch hpa {hpa_name} --patch '{patch_expr}'"
        try:
            self.exec(command=scale_command)
        except:
            tb = traceback.format_exc()
            logging.error(f"Couldn't scale sts [{sts_name}]! Exception is: {tb}")
            return False

        return True

    def is_hpa_exists(self, hpa_name: str, namespace: str):
        logging.info(f"Checking if HPA [{hpa_name}] exists...")
        get_command = f"-n {namespace} get hpa {hpa_name}"
        try:
            self.exec(command=get_command)
        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to get HPA [{hpa_name}]! Exception is: {tb}")
            return False

        return True

    def wait_for_sts_rollout(self, sts_name: str, namespace: str, timeout: str = None):
        logging.info(f"Waiting for sts [{sts_name}] rollout to complete...")
        wait_command = f"rollout status sts/{sts_name} -n {namespace}"
        if type(timeout) is str:
            wait_command = wait_command + f" --timeout {timeout}"
        logging.info(wait_command)
        self.exec(command=wait_command)

    def number_of_replicas_per_sts(self, sts_name, namespace):
        logging.info(f"Getting number of replicas for sts [{sts_name}]...")
        command = f"kubectl -n {namespace} get sts {sts_name} -o jsonpath='{'{.spec.replicas}'}'"
        try:
            num_of_replicas = self.exec_system_cmd(command,
                                                   exit_code_expected=None,
                                                   return_output=True)
            return int(num_of_replicas[0])

        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to get number of replicas for sts [{sts_name}]! Exception is: {tb}")
            return 0

    def max_number_of_replicas_per_hpa(self, hpa_name: str, namespace):
        logging.info(f"Getting maximum number of replicas for hpa [{hpa_name}]...")
        command = f"kubectl -n {namespace} get hpa {hpa_name} -o jsonpath='{'{.spec.maxReplicas}'}'"
        try:
            max_num_of_replicas = self.exec_system_cmd(command,
                                                   exit_code_expected=None,
                                                   return_output=True)
            return int(max_num_of_replicas[0])

        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to get maximum number of replicas for hpa [{hpa_name}]! Exception is: {tb}")
            return 0

    def min_number_of_replicas_per_hpa(self, hpa_name: str, namespace):
        logging.info(f"Getting minimum number of replicas for hpa [{hpa_name}]...")
        command = f"kubectl -n {namespace} get hpa {hpa_name} -o jsonpath='{'{.spec.minReplicas}'}'"
        try:
            min_num_of_replicas = self.exec_system_cmd(command,
                                                   exit_code_expected=None,
                                                   return_output=True)
            return int(min_num_of_replicas[0])

        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to get minimum number of replicas for hpa [{hpa_name}]! Exception is: {tb}")
            return 0

    def list_cronjobs_in_namespace(self, namespace):
        logging.info(f"Listing crobjobs for namespace {namespace}")
        cronjobs_command = f"kubectl -n {namespace} get cronjob"
        try:
            out = self.exec_system_cmd(command=cronjobs_command, exit_code_expected=0, return_output=True)
            if len(out) >= 2:
                out = out[1:]
                for row in out:
                    cronjob_name = row.split(' ')[0]
                    pods_command = f"-n {namespace} get job,pod -l app.kubernetes.io/name={cronjob_name}"
                    self.exec(command=pods_command)
            else:
                logging.info(f"No cronjobs found for namespace {namespace}")
        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to get cronjobs for namespace {namespace} | Exception is: {tb}")

    def trigger_cronjob(self, namespace, cronjob_name):
        logging.info(f"Triggering job from cronjob {cronjob_name} in namespace {namespace}")
        now = datetime.now().strftime('%Y%m%d%H%M%S')
        command = f"-n {namespace} create job --from=cronjob/{cronjob_name} {cronjob_name + '-manual-' + now}"
        try:
            self.exec(command=command)
        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to trigger job from cronjob {cronjob_name} in namespace {namespace} | Exception is: {tb}")

    def delete_cronjob_job(self, namespace, cronjob_name, job_name):
        logging.info(f"Attempting to delete job {job_name} for cronjob {cronjob_name} in namespace {namespace}")
        jobs_command = f'kubectl -n {namespace} get job -l app.kubernetes.io/name={cronjob_name}'
        try:
            out = self.exec_system_cmd(command=jobs_command, exit_code_expected=0, return_output=True)
            deleted = False
            if len(out) >= 2:
                out = out[1:]
                for row in out:
                    job = row.split(' ')[0]
                    if job_name == job:
                        logging.info(f"Deleting job {job_name} in namespace {namespace}")
                        delete_command = f"-n {namespace} delete job {job_name}"
                        self.exec(delete_command)
                        deleted = True
            if not deleted:
                logging.info(f"Job {job_name} in namespace {namespace} is not running or doesn't exist")
        except:
            tb = traceback.format_exc()
            logging.error(f"Failed to delete job {job_name} for cronjob {cronjob_name} in namespace {namespace} | Exception is: {tb}")

    def wait_for_job_completion(self, namespace, job_name, timeout=1800):
        logging.info(f"Waiting for job {job_name} in namespace {namespace} to finish")
        logging.info(f"Setting timeout to {timeout} sec")
        t_end = time.time() + timeout
        while time.time() < t_end:
            pods_info = self.get_running_pods_info_by_name(namespace=namespace,
                                                           pod_name_expr=job_name)
            formatted_pods_info = '\n'.join(pods_info)
            logging.info(f"Got the following pods:\n{formatted_pods_info}")
            is_all_complete = True
            for line in pods_info:
                pod_details = line.split()
                pod_status = pod_details[2]
                if pod_status == 'Completed':
                    pass
                elif pod_status == "Error":
                    if not self.is_no_containers_running(pod_details[1]):
                        is_all_complete = False
                        logging.info('Pod {} containers still working {}'.format(pod_details[0], pod_details[1]))
                else:
                    is_all_complete = False
                    logging.info('Pod {} is still in status {}'.format(pod_details[0], pod_status))

            if not is_all_complete:
                logging.info('Waiting {} seconds...'.format(10))
                time.sleep(10)
            else:
                return True
        return False

    def get_pod_containers_logs(self, namespace, pod_name):
        get_container_cmd = f"kubectl get pod -n {namespace} {pod_name} -o jsonpath='{{range .status.containerStatuses[*]}}[{{.name}},{{.state.*.reason}}] {{end}}'"
        out = self.exec_system_cmd(command=get_container_cmd, exit_code_expected=0, return_output=True, print_stdout=False)
        containers = out[0].strip(' ').split(' ')
        container_logs = []
        for container in containers:
            name, status = container.replace('[', '').replace(']', '').split(',')
            logs = self.get_container_logs(namespace=namespace,pod_name=pod_name,container_name=name)
            container_logs.append({
                'container_name': name,
                'status': status,
                'logs': logs
            })
        return container_logs

    def get_container_logs(self, namespace, pod_name, container_name):
        logs_cmd = f"kubectl logs -n {namespace} {pod_name} -c {container_name}"
        out = self.exec_system_cmd(command=logs_cmd, exit_code_expected=0, return_output=True, print_stdout=False)
        logs = '\n'.join(out)
        return logs
