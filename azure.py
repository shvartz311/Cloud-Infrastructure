#!/usr/bin/env python3

import argparse
import sys, os, traceback
from jfrogdevopstools.tools.functions import *
from jfrogdevopstools.tools.kubectl import *
from azure.common.credentials import ServicePrincipalCredentials
from azure.mgmt.sql import SqlManagementClient
from azure.storage.blob import BlockBlobService
from kubernetes import client, config
from datetime import datetime, timedelta

class JFrogPrivateLink:

    def __init__(self, resource_group,
                 consumer_id,
                 private_endpoint_name,
                 privatelink_service_name,
                 region,
                 narcissus_client,
                 customer_name):
        self.resource_group = resource_group
        self.consumer_id = consumer_id
        self.private_endpoint_name = private_endpoint_name
        self.privatelink_service_name = privatelink_service_name
        self.region = region
        self.narcissus_client = narcissus_client
        self.customer_name = customer_name
        pass


    def set_consumer(self):
        action="Approved"
        self.manage_connection_request(action=action)
        return self.validate_connection(desired_state=action)

    def delete_consumer(self):
        action="Rejected"
        self.manage_connection_request(action=action)
        self.validate_connection(desired_state=action)


    def manage_connection_request(self, action):
        manage_connection_cmd = f"az network private-link-service connection update -g {self.resource_group} " \
                           f"-n {self.private_endpoint_name} " \
                           f"--service-name {self.privatelink_service_name} --connection-status {action}"
        logging.info(f"Going to execute: {manage_connection_cmd}")
        exec_system_cmd(command=manage_connection_cmd, exit_code_expected=0)

    def validate_connection(self, desired_state, max_depth=60, recur_depth=0):
        sleep_secs = 10
        found_connection = None
        current_state = ""
        private_link_service_details_cmd = f"az network private-link-service show -n {self.privatelink_service_name} " \
                                           f"-g {self.resource_group}"
        logging.info(f"Going to execute: {private_link_service_details_cmd}")
        private_link_service_details = self.exec_system_cmd(command=private_link_service_details_cmd, exit_code_expected=0, return_output=True)
        private_link_service_details_dict = json.loads(private_link_service_details)

        if len(private_link_service_details_dict) == 0:
            logging.info("Cannot validate connection status for Private Endpoint ID: [{}], "
                         "assuming it is already deleted by consumer.".format(self.private_endpoint_name))
            return

        private_link_service_connections = private_link_service_details_dict['privateEndpointConnections']
        for connection in private_link_service_connections:
            if connection['name'] == self.private_endpoint_name:
                found_connection = connection

        if found_connection is not None:
            current_state = found_connection['privateLinkServiceConnectionState']['status']

        if current_state == desired_state:
            logging.info("Private endpoint ID: [{}] connection is {}, as desired".format(
                self.private_endpoint_name, desired_state))
            if "linkIdentifier" in found_connection and found_connection["linkIdentifier"] is not None:
                logging.info("Fetching LinkID from the Azure Private Link connection")
                azure_privatelink_linkid = found_connection["linkIdentifier"]
                logging.info(f"Found LinkID: [{azure_privatelink_linkid}]")

                return azure_privatelink_linkid

        if recur_depth >= max_depth:
            raise Exception("PrivateLink connection took too long to be {}. Exiting".format(desired_state))

        logging.info("PrivateLink connection is not {} yet. Sleeping {} seconds...".format(desired_state, sleep_secs))
        time.sleep(sleep_secs)
        return self.validate_connection(desired_state, max_depth, recur_depth + 1)

    @staticmethod
    def exec_system_cmd(command, exit_code_expected=0, return_output=True):
        """Wait_to_code is the exit code number to expect the function to return"""

        try:
            output = subprocess.check_output(
                command, stderr=subprocess.STDOUT, shell=True, timeout=5,
                universal_newlines=True)
        except subprocess.CalledProcessError as exc:
            exit_code = exc.returncode
            error_output = exc.output

            if exit_code is not None and int(exit_code) != int(exit_code_expected):
                raise Exception("Exit code '{}' of command `{}` not equal to '{}'. CMD Output: {}\n CMD Err: {}"
                        "".format(exit_code, command, exit_code_expected, error_output, error_output))

        if return_output and output is not None:
            return output
        else:
            return True



class JFrogAzureBlobContainer:
    account_name = None
    account_key = None
    container_name = None
    block_blob_service = None
    permissions_template_target_path = None
    subscription_id = None

    def __init__(self, account_name, account_key, container_name, subscription_id, labels):
        logging.info("Going to create [JFrogAzureBlobContainer] object")
        self.account_name = account_name
        self.account_key = account_key
        self.container_name = container_name
        self.subscription_id = subscription_id
        self.block_blob_service = BlockBlobService(account_name=account_name,
                                                   account_key=account_key)
        self.labels = labels


    def create(self):
        logging.info("Trying to create [{}] container under [{}] storage account".format(self.container_name,
                                                                                         self.account_name))
        # The [create_container] has a built it method that skips if already exists
        self.block_blob_service.create_container(container_name=self.container_name)
        self.block_blob_service.set_container_metadata(container_name=self.container_name, metadata=self.labels)
        return True

    def delete(self):
        logging.info("Going to delete [{}] container under [{}] storage account".format(self.container_name,
                                                                                        self.account_name))
        self.block_blob_service.delete_container(container_name=self.container_name)
        return True

    def generate_sas_token(self, days_to_expire):

        start_date = datetime.today().strftime('%Y-%m-%d')
        end_date = (datetime.today() + timedelta(days=days_to_expire)).strftime('%Y-%m-%d')

        logging.info("Generating SAS token for container {} using az cli".format(self.container_name))

        try:
            azure_generate_sas_token_command = "az storage container generate-sas --account-name {}" \
                                               " --subscription {} --name {} --permissions racwdl --start {} --expiry {}" \
                                               " --auth-mode key --account-key {}" \
                                               "".format(self.account_name,
                                                         self.subscription_id,
                                                         self.container_name,
                                                         start_date,
                                                         end_date,
                                                         self.account_key)

            response = self.exec_system_cmd(azure_generate_sas_token_command)

            self.azure_sas_token = response[0].rstrip().replace('"','')
            self.azure_sas_token_expiry = end_date

            logging.debug("Generated SAS token API response {}".format(response))
            logging.info("Generated SAS token successfully")

        except Exception:
            logging.error("Failed to generate SAS token for container {} using az cli".format(self.container_name))
            raise

        return True

    def exec_system_cmd(self, command, exit_code_expected=0, return_output=True, executable='/bin/sh', print_stdout=False):
        """Wait_to_code is the exit code number to expect the function to return"""
        output_array = []
        subproc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   executable=executable)
        for line in subproc.stdout:
            log_line = "[{}]".format(line.decode('utf-8').rstrip())
            if print_stdout and log_line != "[]":
                logging.info(log_line)
            output_array.append(line.decode('utf-8'))

        try:
            out, err = subproc.communicate(timeout=30)
        except TimeoutExpired:
            proc.kill()
            out, err = subproc.communicate()

        exit_code = subproc.returncode
        logging.debug(exit_code)
        if exit_code_expected is not None and int(exit_code) != int(exit_code_expected):
            raise Exception("Exit code '{}' of command `{}` not equal to '{}'. CMD Output: {}\n CMD Err: {}"
                            "".format(exit_code, command, exit_code_expected, out, err))
        if return_output:
            return output_array
        else:
            return True

    def grant_permissions(self, application_id): \
        grant_permissions_cmd = "az deployment group create --resource-group {} --template-file {}  --parameters {}".format(self.resource_group)


    def __render_permissions_template(self):

        self.permissions_template_target_path = "/tmp/{}{}{}".format(self.container_name,
                                                        str(randrange(100000)),
                                                        str(randrange(1000)))
        permissions_json = {
            "$schema": "https://schema.management.azure.com/schemas/2015-01-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "storageAccountName": {
                    "type": "string",
                    "metadata": {
                        "description": "The storage account name where the storage container exists"
                    }
                },
                "containerName": {
                    "type": "string",
                    "metadata": {
                        "description": "The name of the storage container exists"
                    }
                },
                "principalId": {
                    "type": "string",
                    "metadata": {
                        "description": "The principal to assign the role to"
                    }
                },
                "builtInRoleType": {
                    "type": "string",
                    "metadata": {
                        "description": "Built-in role to assign"
                    }
                },
                "newGUID": {
                    "type": "string",
                    "defaultValue": "[newGuid()]",
                    "metadata": {
                        "description": "A new GUID used to identify the role assignment"
                    }
                }
            },
            "variables": {
                "apiVersion": "2018-01-01-preview",
                "roleTypeGUID": "[concat('/subscriptions/', subscription().subscriptionId, '/providers/Microsoft.Authorization/roleDefinitions/', parameters('builtInRoleType'))]"
            },
            "resources": [
                {
                    "type": "Microsoft.Storage/storageAccounts/blobServices/containers/providers/roleAssignments",
                    "apiVersion": "[variables('apiVersion')]",
                    "name": "[concat(parameters('storageAccountName'), '/default/', parameters('containerName'), '/Microsoft.Authorization/', parameters('newGUID'))]",
                    "properties": {
                        "roleDefinitionId": "[variables('roleTypeGUID')]",
                        "principalId": "[parameters('principalId')]"
                    }
                }
            ],
            "outputs": {}
        }

        with io.FileIO(self.permissions_template_target_path, "w") as file:
            file.write(permissions_json)


def __get_permissions_json(self, application_id):
            permissions_json = {
                "storageAccountName": {
                    "value": "{}".format(self.account_name)
                },
                "containerName": {
                    "value": "{}".format(self.container_name)
                },
                "builtInRoleType": {
                    "value": "ba92f5b4-2d11-453d-a403-e96b0029c9fe"
                },
                "principalId": {
                    "value": "'{}".format(application_id)
                }
            }


class JFrogAzureAppRegistration:
    name = None

    def __init__(self, name):
        logging.info("Going to create [JFrogAzureAppRegistration] object")
        self.name = name

    def create(self):
        logging.info("Trying to create App registration [{}] storage account".format(self.name))
        return True

    def delete(self):
        logging.info("Trying to delete App registration [{}] storage account".format(self.name))
        return True


class JfrogAksKubectlCli(JfrogKubectlCli):
    cloud_provider = "azure"
    cloud_provider_sdm_name = "Azure"
    client_id = None
    client_pass = None
    tenant_id = None
    subscription_id = None
    k8s_resource_group_name = None

    def __init__(self,
                 environment,
                 region,
                 azure_cluster,
                 azure_zone,
                 azure_project,
                 azure_client_id,
                 azure_client_pass,
                 azure_tenant_id,
                 azure_subscription_id,
                 k8s_resource_group_name=None):

        self.client_id = azure_client_id
        self.client_pass = azure_client_pass
        self.tenant_id = azure_tenant_id
        self.subscription_id = azure_subscription_id

        # Fallback to cluster_name=k8s_resource_group_name
        if k8s_resource_group_name is None:
            k8s_resource_group_name = azure_cluster
        self.k8s_resource_group_name = k8s_resource_group_name

        super(JfrogAksKubectlCli, self).__init__(region=region,
                                                 project=azure_project,
                                                 cluster=azure_cluster,
                                                 zone=azure_zone,
                                                 environment=environment)

    def cloud_connect(self):
        """
        Connect to Azure cluster
        :return:
        """

        logging.info("Connecting to AZURE cluster [{}], zone [{}], project [{}]".format(self.cluster, self.zone, self.project))

        logging.info("Login with service-principal client_id with az")
        azure_login_command = "az login --service-principal -u {} -p \"{}\" --tenant {}" \
                              "".format(self.client_id, self.client_pass, self.tenant_id)
        self.exec_system_cmd(azure_login_command)

        logging.info("Configuring kubectl for {} with az".format(self.cluster))
        logging.info("Using Azure k8s resource group [{}]".format(self.k8s_resource_group_name))
        azure_update_kubeconfig = "az aks get-credentials --subscription {} --resource-group {} --name {} --admin --overwrite-existing" \
                                  "".format(self.subscription_id, self.k8s_resource_group_name, self.cluster)
        self.exec_system_cmd(azure_update_kubeconfig)

        self.config = config.load_kube_config()
        self.client_v1 = client.CoreV1Api()

        return True


def set_azure_secret(creds=None):
    if creds is None:
        creds = {}
        
    client_id = get_first_value(os.environ.get('CLIENT_ID'), creds.get('client_id'), None)
    secret = get_first_value(os.environ.get('SECRET'), creds.get('secret'), None)
    tenant = get_first_value(os.environ.get('TENANT'), creds.get('tenant'), None)
    subscription_id = get_first_value(os.environ.get('SUBSCRIPTION_ID'), creds.get('subscription_id', None))

    if not client_id:
        raise ValueError('CLIENT_ID is empty.')

    if not secret:
        raise ValueError('SECRET is empty.')

    if not tenant:
        raise ValueError('TENANT is empty.')

    if not subscription_id:
        raise ValueError('SUBSCRIPTION_ID is empty.')

    return (client_id, secret, tenant, subscription_id)

def get_azure_bucket_size(customer_bucket_name,account_name, token):
    block_blob_service = BlockBlobService(account_name=account_name, token_credential=token)
    generator = block_blob_service.list_blobs(customer_bucket_name)
    total_size = 0
    for blob in generator:
        total_size += blob.properties.content_length
    return total_size

def delete_azure_blob_container(customer_bucket_name,account_name, token):
    block_blob_service = BlockBlobService(account_name=account_name, token_credential=token)
    block_blob_service.delete_container(customer_bucket_name)

def get_azure_creds_object_and_subscription_id(creds=None):
    if creds is None:
        creds = {}

    client_id, secret, tenant, subscription_id = set_azure_secret(creds)
    azure_creds_object = ServicePrincipalCredentials(client_id=client_id,
                                                     secret=secret,
                                                     tenant=tenant)
    return azure_creds_object, subscription_id


def get_azure_mssql_client(creds):
    azure_creds_object, subscription_id = get_azure_creds_object_and_subscription_id(creds)

    return SqlManagementClient(azure_creds_object, subscription_id)


def get_azure_location():
    location = {}
    location['resource_group'] = os.environ.get('RESOURCE_GROUP')
    location['azure_location'] = os.environ.get('AZURE_LOCATION')
    return location

def main():
    logging.getLogger().setLevel(logging.INFO)
    logging.info("Azure")
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)

    subparsers = parser.add_subparsers(dest='command')

    # Create
    create_parser = subparsers.add_parser(
        'service_create')
    create_parser.add_argument('name')

    # List
    list_parser = subparsers.add_parser(
        'service_list')

    # List Keys
    list_keys_parser = subparsers.add_parser(
        'service_list_keys')
    list_keys_parser.add_argument('name')

    # Create Key
    list_keys_parser = subparsers.add_parser(
        'service_create_key')
    list_keys_parser.add_argument('name')

    # Delete
    delete_parser = subparsers.add_parser(
        'service_delete')
    delete_parser.add_argument('name')

    # Delete keys
    delete_parser = subparsers.add_parser(
        'service_delete_keys')
    delete_parser.add_argument('name')

    # Create Bucket
    bucket_create = subparsers.add_parser(
        'bucket_create')
    bucket_create.add_argument('bucket_name')

    bucket_view_iam_members = subparsers.add_parser(
        'bucket_view_iam_members')
    bucket_view_iam_members.add_argument('bucket_name')

    # Create Bucket
    bucket_create_owner = subparsers.add_parser(
        'bucket_create_owner')
    bucket_create_owner.add_argument('bucket_name')
    bucket_create_owner.add_argument('name')

    args = parser.parse_args()
    try:
        name = args.name
    except:
        name = None

    if "service_" in args.command:
        az_app_registration = JFrogAzureAppRegistration(name=name)
        if args.command == 'service_create':
            az_app_registration.create()
        elif args.command == 'service_delete':
            az_app_registration.delete()


if __name__ == '__main__':
    main()
