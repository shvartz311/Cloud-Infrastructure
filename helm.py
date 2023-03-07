#!/usr/bin/env python3

import os, yaml, shutil
import subprocess, sys, traceback
import logging
import platform
import json
from jfrogdevopstools.tools.prometheus import prom_decorator
from retry import retry


class JfrogHelmCli():
    helm_plugin_source = {"tiller": "https://github.com/rimusz/helm-tiller"}
    helm_cmd = "helm3"
    use_helm3 = True

    def __init__(self):
        logging.debug("JfrogHelmCli init - using Helm 3")

    @property
    def os_type(self):
        """
        Get OS Type
        :return: Linux, Darwin or Windows
        """
        os_type = platform.system()
        return os_type.lower()

    def install_cli(self):

        logging.info("Installing \ verifying helm on {}".format(self.os_type))
        if self.os_type == "Darwin".lower():
            self.exec_system_cmd("hash helm && echo 'helm installed already' || brew install helm",
                                 exit_code_expected=0)
        else:
            self.exec_system_cmd("hash jfrog && echo 'JFrog CLI installed already'"
                                 " || cd /usr/local/bin/ && curl -LO https://storage.googleapis.com/kubernetes-release/"
                                 "release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/"
                                 "stable.txt)/bin/linux/amd64/kubectl | sh",
                                 exit_code_expected=0)
        return True

    def install_plugin(self, url):

        self.exec_system_cmd("helm plugin install {}".format(url))

        return True

    def exec(self, command, use_tiller=True, hide_string=[]):

        tiller_cmd = ""
        helm_cmd = "helm"

        if self.use_helm3:
            helm_cmd = "helm3"
            logging.debug("Force [use_tiller=False]")
            use_tiller = False

        if use_tiller:
            tiller_cmd = "tiller run helm"

        final_cmd = "{} {} {}".format(helm_cmd, tiller_cmd, command)
        log_command = final_cmd
        for string_to_hide in hide_string:
            log_command = log_command.replace(string_to_hide, "XXXX")
        logging.info("EXEC: [{}]".format(log_command))
        self.exec_system_cmd(final_cmd, exit_code_expected=0, context="helm")
        return True

    def exec_system_cmd(self, command, exit_code_expected=None, context='[OS CMD]', return_output=False):
        """Wait_to_code is the exit code number to expect the function to return"""

        output_array = []
        subproc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        for line in subproc.stdout:
            try:
                logging.info("%s %s" % (context, line.decode('utf-8').strip()))
            except:
                logging.info("%s %s" % (context, line))
            output_array.append(line.decode('utf-8'))

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

        if return_output:
            return output_array
        else:
            return True

    def helm_release_exists(self, namespace, release):
        command = f"helm3 ls --namespace {namespace} | grep -w {release}"

        if self.exec_system_cmd(command=command, context="helm", return_output=True):
            logging.info("Helm release [{}] exists".format(release))
        else:
            logging.warning(f"Helm release {release} doesn't exist on namespace {namespace}")
            return False
        return True

    def delete_helm_release(self, release, namespace=None):
        """Delete helm release from name space if it does not exist"""
        try:
            if self.use_helm3:
                if namespace:
                    self.exec("uninstall {} -n {}".format(release, namespace))
                else:
                    self.exec("uninstall {} -n {}".format(release, release.split("-")[0]))
            else:
                self.exec("delete --purge {}".format(release))
        except Exception as e:
            if "not found" in str(e):
                logging.info("Release {} not found, nothing to do".format(release))
            else:
                raise RuntimeError("Failed to delete release {}".format(release))

    def cache_chart(self, repo_key, chart_name, chart_version, chart_folder=None):

        if chart_folder is None:
            chart_folder = subprocess.run([self.helm_cmd, 'env', 'HELM_REPOSITORY_CACHE'], stdout=subprocess.PIPE).stdout.strip().decode('utf-8')
            chart_folder = os.environ.get('HELM_REPOSITORY_CACHE', chart_folder)
            logging.debug("Load HELM_REPOSITORY_CACHE env as {}".format(chart_folder))
        self.download_chart_tgz(repo_key, chart_name, chart_version, chart_folder)

    def download_chart_tgz(self, repo_key, chart_name, chart_version, chart_folder, force=False, do_repo_update=True):

        chart_file_name = "{}-{}.tgz".format(chart_name, chart_version)
        chart_tgz_path = os.path.join(chart_folder, chart_file_name)
        logging.info(f'Going to download chart [{chart_name}] version [{chart_version}], file path [{chart_tgz_path}]')

        if os.path.exists(chart_tgz_path):
            if not force:
                logging.debug("[{}] already exists, skipping chart download ...".format(chart_tgz_path))
                return True

            logging.debug("Deleting file [{}] ...".format(chart_tgz_path))
            os.remove(chart_tgz_path)

        if do_repo_update:
            self.repo_update()

        action = "fetch"
        if self.use_helm3:
            action = "pull"

        self.exec("{} {}/{} --version {} --destination {}".format(action, repo_key, chart_name, chart_version,
                                                                  chart_folder))
        return True

    def is_chart_part_of_index_yaml(self, repo_key, chart_name, chart_version):
        try:
            self.exec("search repo {}/{} --version {}".format(repo_key, chart_name, chart_version))
        except Exception as e:
            return False
        return True

    def download_chart(self, repo_key, chart_name, chart_version, chart_folder, force=False, do_repo_update=False):

        logging.debug("Going to download chart [{}] version [{}]".format(chart_name, chart_version))
        chart_path = os.path.join(chart_folder, chart_name)
        chart_yaml_path = os.path.join(chart_path, "Chart.yaml")
        if os.path.exists(chart_yaml_path):

            if not force:
                logging.debug("[{}] already exists, checking the chart version ...".format(chart_yaml_path))

                with open(chart_yaml_path) as chart_yaml:
                    chart_yaml_parsed = yaml.load(chart_yaml, Loader=yaml.FullLoader)
                    chart_yaml_version = chart_yaml_parsed["version"]
                chart_yaml.close()

                if chart_yaml_version == chart_version:
                    logging.debug("[{}] version already exists, skipping chart download ...".format(chart_version))
                    return True
                else:
                    logging.info("[{}] exists, but chart [{}]] is needed to be downloaded...".format(chart_yaml_version, chart_version))

            logging.debug("Deleting folder [{}] ...".format(chart_path))
            shutil.rmtree(chart_path)

        if do_repo_update or not self.is_chart_part_of_index_yaml(repo_key, chart_name, chart_version):
            self.repo_update()

        action = "fetch"
        if self.use_helm3:
            action = "pull"
        self.exec("{} {}/{} --version {} --untar --untardir {}".format(action, repo_key, chart_name, chart_version,
                                                                       chart_folder))
        return True

    def template(self, repo_key, chart_name, chart_version):

        self.exec("{} {}/{} --version {} > /dev/null".format("template", repo_key, chart_name, chart_version))

    @prom_decorator(name_override='helm_install')
    def install(self, release, namespace, helm_dir=None, repo_key=None, chart_name=None, chart_version=None,
                values_files_list=[], force=False, wait_timeout=None, helm_extra_params=None, helm3_release_state_fix_enabled=True, xray_release_upgrade_fix_enabled=True):
        # helm v3 max history
        os.environ["HELM_MAX_HISTORY"] = "2"

        if helm_dir is not None:
            helm_charts_details = helm_dir
            logging.info("Going to install helm chart from local filesystem "
                         "[helm_charts_details={}".format(helm_charts_details))

        elif repo_key is not None and chart_name is not None and chart_version is not None:
            helm_charts_details = "{}/{} --version {}".format(repo_key, chart_name, chart_version)
            logging.info("Going to install helm chart from remote helm repository "
                         "[helm_charts_details={}".format(helm_charts_details))
        else:
            raise Exception("[helm_dir] or [repo_key AND chart_name AND chart_version] is mandatory")

        helm_chart_values = ""
        for file_path in values_files_list:
            logging.info("setting file as helm values {}".format(file_path))
            helm_chart_values = "{} -f {}".format(helm_chart_values, file_path)

        force_flag = ""
        if force:
            force_flag = "--force"

        wait_timeout_flag = ""
        if wait_timeout is not None:
            wait_timeout_flag = "--wait --timeout {}".format(wait_timeout)

        if helm_extra_params is None:
            helm_extra_params = ""

        if self.check_if_helm_release_exists(release, namespace):
            if self.use_helm3:
                # Do not delete helm 3 release secret if it is less minutes than set below, as there might be another release is in progress.
                # Otherwise fix `UPGRADE FAILED: another operation (install/upgrade/rollback) is in progress` issue
                helm3_release_secret_time = "60"
                self.helm3_release_deploy_fix(
                    release, helm3_release_secret_time, namespace)

            if helm3_release_state_fix_enabled and self.use_helm3:
                self.helm3_release_state_fix(
                    release, helm_charts_details, helm_chart_values)

            if xray_release_upgrade_fix_enabled and self.use_helm3:
                if chart_name == "xray":
                    self.xray_release_upgrade_fix(
                        release, helm_charts_details, helm_chart_values)

        self.exec("upgrade --install {} {} --namespace {} {} {} {} {}".format(
            force_flag, release, namespace, wait_timeout_flag,
            helm_extra_params, helm_charts_details, helm_chart_values))

    def check_if_helm_release_exists(self, release, namespace):
        helm_cmd = "helm3"

        try:
            logging.debug("Going to check if helm release exists [{}]".format(release))
            release_list_info_cmd = "{} -n {} list --output json ".format(helm_cmd, namespace)
            release_list_info_data = json.loads(subprocess.check_output(release_list_info_cmd, shell=True))
            for helm_release_info in release_list_info_data:
                logging.debug("check_if_helm_release_exists: Checking if helm_release_info['name'] == [{}] == [{}]".format(helm_release_info['name'], release))
                if helm_release_info['name'] == release:
                    logging.debug("Found - {}".format(helm_release_info))
                    return True

        except Exception as e:
            logging.error(e)

        return False

    def helm3_release_deploy_fix(self, release, helm3_release_secret_time, namespace):
        helm3_release_deploy_fix_cmd = "/opt/jfrog/saas-deployer/scripts/fix-helm3-deploy.sh {} {} {}" \
            "".format(release, helm3_release_secret_time, namespace)

        self.exec_system_cmd(helm3_release_deploy_fix_cmd, exit_code_expected=0)

        return True

    def helm3_release_state_fix(self, release, helm_charts_details, helm_chart_values):

        helm3_release_state_fix_cmd = "/opt/jfrog/saas-deployer/scripts/fix-helm-2to3-app.sh {} {} {}" \
            "".format(release, helm_charts_details, helm_chart_values)

        self.exec_system_cmd(helm3_release_state_fix_cmd, exit_code_expected=0)

        return True

    def xray_release_upgrade_fix(self, release, helm_charts_details, helm_chart_values):

        xray_release_upgrade_fix_cmd = "/opt/jfrog/saas-deployer/scripts/fix-helm-xray-upgrade.sh {} {} {}" \
            "".format(release, helm_charts_details, helm_chart_values)

        self.exec_system_cmd(xray_release_upgrade_fix_cmd, exit_code_expected=0)

        return True

    def install_from_local(self, release, namespace, helm_dir, values_files_list=[], force=False, wait_timeout=None,
                           helm_extra_params=None):

        self.install(release=release, namespace=namespace, values_files_list=values_files_list,
                     helm_dir=helm_dir, force=force, wait_timeout=wait_timeout, helm_extra_params=helm_extra_params)

        return True

    def install_from_repo(self, release, namespace, repo_key, chart_name, chart_version, values_files_list=[],
                          force=False, wait_timeout=None, helm_extra_params=None,
                          xray_release_upgrade_fix_enabled=True):

        self.cache_chart(repo_key, chart_name, chart_version)

        self.install(release=release, namespace=namespace, values_files_list=values_files_list, repo_key=repo_key,
                     chart_name=chart_name, chart_version=chart_version, force=force, wait_timeout=wait_timeout,
                     helm_extra_params=helm_extra_params, xray_release_upgrade_fix_enabled=xray_release_upgrade_fix_enabled)

        return True

    def repo_add(self, repo_key, repo_url, username, password, force=True):
        logging.debug("Force Helm Repo add flag = [{}]".format(force))
        extra_flags = "--force-update"
        repo_url = "{}/{}".format(repo_url, repo_key)

        if force or not self.is_repo_exists(repo_key, repo_url):
            self.exec("repo add {} {} {} --username {} --password {}".format(
                repo_key, repo_url, extra_flags, username, password),
                use_tiller=False,
                hide_string=[password])

            self.repo_update()

        self.repo_list()

        return True

    @retry(tries=2, delay=5)
    def repo_update(self):
        self.exec("repo update")

    def repo_list(self):
        self.exec("repo list")

    def is_repo_exists(self, repo_key, repo_url):
        helm_cmd = "helm"

        if self.use_helm3:
            helm_cmd = "helm3"

        try:
            logging.debug("Going to check if repo_key exists [{}] repo_url [{}]".format(repo_key, repo_url))
            repo_list_info_cmd = "{} repo list --output json ".format(helm_cmd)
            repo_list_info_data = json.loads(subprocess.check_output(repo_list_info_cmd, shell=True))
            for helm_repo_info in repo_list_info_data:
                logging.debug("is_repo_exists: Checking if helm_repo_info['name'] == [{}] == [{}]".format(helm_repo_info['name'], repo_key))
                logging.debug("is_repo_exists: Checking if helm_repo_info['url']  == [{}] == [{}]".format(helm_repo_info['url'], repo_url))
                if helm_repo_info['name'] == repo_key and helm_repo_info['url'] == repo_url:
                    logging.debug("Found - {}".format(helm_repo_info))
                    return True

        except Exception as e:
            logging.error(e)

        return False

    def delete(self, release, purge=True):

        purge_flag = ""
        if purge:
            purge_flag = "--purge"

        self.exec("delete {} {}".format(purge_flag, release))
        return True

    def get_installed_chart_version(self, chart_name, namespace=None):
        not_installed = -1
        if namespace:
            output = self.exec_system_cmd("helm ls --namespace={} -o json".format(namespace), return_output=True)
        else:
            output = self.exec_system_cmd("helm ls -o json", return_output=True)
        output = json.loads(output[0])
        for chart in output:
            name_and_version = chart['chart'].rsplit("-", 1)
            if name_and_version[0] == chart_name:
                logging.info("current installed chart version: " + chart['chart'])
                return name_and_version[1]
        # not found so it is not installed :(
        return not_installed

    def list(self, namespace=None, return_output=False):
        if namespace:
            return self.exec_system_cmd(f'helm list -n {namespace}', exit_code_expected=0, return_output=return_output)
        else:
            self.exec("list")
        return True

    def status(self):
        """
        Get Cluster Status
        :return:
        """

        self.info()

        self.list()

        return True

    def info(self):
        """
        Get K8S cluster Info
        :param self:
        :return:
        """

        logging.info("INFO = {}".format(self))
        self.list()


if __name__ == "__main__":
    logging.info("*** Test mode ***")

    logging.getLogger().setLevel(logging.DEBUG)
    logging.debug("*** Debug mode ***")

    try:

        myHelm = JfrogHelmCli()
        myHelm.info()

    except Exception:
        logging.error("Oops!")
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
