#!/usr/bin/env python
import argparse
from google.oauth2 import service_account
import googleapiclient.discovery
from google.cloud import storage
import json
import jfrogdevopstools.tools.functions as tools
from jfrogdevopstools.tools.kubectl import *
from retry import retry
from kubernetes import client, config
import tempfile
from urllib.parse import urlparse


class JFrogGCPStorage:
    storage_client = None
    bucket_name = None
    bucket = None

    def __init__(self, bucket_name, labels):

        self.storage_client = storage.Client()
        self.bucket_name = bucket_name
        self.bucket = self.storage_client.bucket(bucket_name=self.bucket_name)
        self.labels = labels

    def create(self, location=None):
        if self.bucket.exists():
            logging.info("Bucket [{}] already exists [nothing to do]".format(self.bucket_name))
            bucket = self.storage_client.get_bucket(self.bucket_name)
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                logging.info("Bucket [{}] has uniform bucket-level access set to False. Setting to True...".format(
                    self.bucket_name))
                bucket.iam_configuration.uniform_bucket_level_access_enabled = True
                bucket.patch()
                logging.info("Uniform bucket-level access was enabled for [{}].".format(self.bucket_name))
            self.setup_labels()
            return True
        try:
            self.bucket.iam_configuration.uniform_bucket_level_access_enabled = True
            self.bucket.create(location=location)
            logging.info("Created bucket [{}]".format(self.bucket_name))
        except:
            if "You already own this bucket" in str(sys.exc_info()):
                logging.info("Bucket [{}] already exists".format(self.bucket_name))
            elif "that name is not available. Please try a different one" in str(sys.exc_info()):
                logging.info("Bucket [{}] already exists".format(self.bucket_name))
            else:
                raise
        return True

    def setup_labels(self):
        bucket = self.storage_client.get_bucket(self.bucket_name)
        labels = bucket.labels
        labels.update(self.labels)
        bucket.labels = labels
        bucket.patch()
        logging.info('Updated labels on {}.'.format(self.bucket_name))

    def grant_permissions(self, gcp_service_account):
        for attempt in range(1, 60):
            if self.bucket.exists() and gcp_service_account.exists():
                logging.info("Granting permissions to service account [{}] on bucket [{}]".format(
                    gcp_service_account.get_email.split("@")[0], self.bucket_name))
                policy = self.bucket.get_iam_policy(requested_policy_version=3)
                policy.bindings.append({"role": "roles/storage.objectAdmin",
                                        "members": {"serviceAccount:" + gcp_service_account.get_email}})
                self.bucket.set_iam_policy(policy)
                return True
            else:
                logging.info(
                    "Waiting for matched condition to exist, assets service account [{}] and bucket [{}] are mandatory,"
                    " retry attempt: [{}]".format(
                        gcp_service_account.split("@")[0], self.bucket_name, attempt))
                time.sleep(5)
                continue
        raise RuntimeError(
            "ERROR: Granting permissions to service account [{}] on bucket [{}] failed due to unmatched condition".format(
                gcp_service_account.get_email.split("@")[0], self.bucket_name))

    def bucket_view_iam_members(self):
        policy = self.bucket.get_iam_policy()
        for role in policy:
            members = policy[role]
            print('Role: {}, Members: {}'.format(role, members))


class JFrogGCPServiceAccount:
    service_account_id = None
    project_id = None
    key = None
    service_account_list = []
    service_account_keys_list = []

    def __init__(self, service_account_id=None):
        gcp_account = get_gcp_account()

        self.project_id = gcp_account['project_id']
        self.gcp_account_service = gcp_account['service']

        if service_account_id is None:
            logging.info("service_account_id, only list option is available")
        else:
            self.service_account_id = service_account_id
            self.service_account_email = "{}@{}.iam.gserviceaccount.com".format(
                self.service_account_id, self.project_id)

    @property
    def get_email(self):
        return self.service_account_email

    @property
    def get_key(self):
        return self.key

    def create(self):
        """Creates a service account."""

        service_account_body = {
            'accountId': self.service_account_id,
            'serviceAccount': {
                'displayName': self.service_account_id
            }}

        try:
            self.gcp_account_service.projects().serviceAccounts().create(
                name='projects/' + self.project_id, body=service_account_body).execute()
            logging.info('Created service account: [{}]'.format(self.service_account_id))
        except:
            # Skipping already exists service account error
            if "already exists within project" in str(sys.exc_info()):
                logging.info("INFO: Service account [{}] already exists".format(self.service_account_id))
            else:
                raise
        return True

    def exists(self):
        logging.info("Checking if service account [{}] exists".format(self.service_account_email))
        try:
            self.gcp_account_service.projects().serviceAccounts().get(
                name='projects/{}/serviceAccounts/{}'.format(self.project_id, self.service_account_email)).execute()
            return True
        except:
            return False

    def delete(self):
        """Deletes a service account."""
        try:
            logging.info("Trying to delete GCP service account [{}]".format(self.service_account_email))
            self.gcp_account_service.projects().serviceAccounts().delete(
                name='projects/-/serviceAccounts/' + self.service_account_email).execute()
        except:
            pass
            logging.info("GCP service account [{}] does not exist".format(self.service_account_email))
        return True

    def create_key(self):
        service_account_name = 'projects/{}/serviceAccounts/{}'.format(self.project_id, self.service_account_email)
        self.key = self.gcp_account_service.projects().serviceAccounts().keys().create(name=service_account_name,
                                                                                       body={}).execute()
        logging.info("Created key for service account [%s] successfully" % self.service_account_id)
        return True

    @retry(tries=5, delay=30)
    def get_role_artifactory_workload_identity(self):
        role_id = "artifactoryWorkloadIdentity"
        role_description = "Permissions to SignBlob for Workload Identity (DO NOT DELETE OR MODIFY PERMISSIONS!)"
        role_permission = "iam.serviceAccounts.signBlob"
        role_stage = "GA"

        # Check if role exist and return role id
        gcloud_command = "gcloud iam roles describe {} --project={}".format(
            role_id, self.project_id)
        cmd = tools.do_shell_cmd(cmd=gcloud_command)

        # TODO: validate role permissions, make sure stage=GA (not state=DELETED) and not deleted=true
        if cmd['exitcode'] == 0:
            return role_id

        # If role doesn't exist create it and return role id
        gcloud_command = "gcloud iam roles create {} --project={} --title={} --description=\"{}\" --permissions=\"{}\" --stage={}".format(
            role_id, self.project_id, role_id, role_description, role_permission, role_stage)
        cmd = tools.do_shell_cmd(cmd=gcloud_command)

        if cmd['exitcode'] != 0:
            raise RuntimeError("Failed to create role {}:Output {} Error: {}".format(role_id, str(cmd['output']),
                                                                                     str(cmd['error'])))
        return role_id

    @retry(tries=5, delay=30)
    def add_iam_role_binding(self):
        # Bind IAM service account with the role to sign blob
        role_id = self.get_role_artifactory_workload_identity()
        gcloud_command = "gcloud iam service-accounts add-iam-policy-binding {} --role projects/{}/roles/{} --member serviceAccount:{}".format(
            self.service_account_email, self.project_id, role_id, self.service_account_email)
        cmd = tools.do_shell_cmd(cmd=gcloud_command)

        if cmd['exitcode'] != 0:
            raise RuntimeError("Failed to bind service account with role to sign blob:Output {} Error: {}".format(str(cmd['output']),
                                                                                                                  str(cmd['error'])))

        return True

    @retry(tries=5, delay=30)
    def add_iam_gke_sa_binding(self, customer_name):
        kubernetes_sa = "{}.svc.id.goog[{}/{}-artifactory]".format(
            self.project_id, customer_name, customer_name)
        # Bind GKE service account with GCP IAM service account
        gcloud_command = "gcloud iam service-accounts add-iam-policy-binding {} --role roles/iam.workloadIdentityUser --member \"serviceAccount:{}\"".format(
            self.service_account_email, kubernetes_sa)
        cmd = tools.do_shell_cmd(cmd=gcloud_command)
        if cmd['exitcode'] != 0:
            raise RuntimeError("Failed to bind service account with workload identity role:Output {} Error: {}".format(str(cmd['output']),
                                                                                                                  str(cmd['error'])))

        return True

    @retry(tries=5, delay=30)
    def create_gcloud_key(self):
        filepath = self.service_account_id + ".json"
        gcloud_command = "gcloud iam service-accounts keys create {} --iam-account {}".format(
            filepath, self.service_account_email)
        cmd = tools.do_shell_cmd(cmd=gcloud_command)

        if cmd['exitcode'] != 0:
            raise RuntimeError("Failed to create service account:Output {} Error: {}".format(str(cmd['output']),
                                                                                             str(cmd['error'])))
        else:
            with open(filepath) as f:
                contect = f.read()
            self.key = contect
            os.remove(filepath)
        return True

    def list_keys(self):
        service_account_name = 'projects/{}/serviceAccounts/{}'.format(self.project_id, self.service_account_email)
        service_account_keys_json = self.gcp_account_service.projects().serviceAccounts().keys().list(
            name=service_account_name).execute()
        if len(service_account_keys_json['keys']) == 1:
            logging.info("Service account [{}] has no active keys".format(self.service_account_id))
        else:
            for key in service_account_keys_json['keys']:
                self.service_account_keys_list.append(key['name'])
            logging.info(self.service_account_keys_list)
        return True

    def create_with_key(self):
        self.create()
        self.create_key()
        return True

    def create_with_gcloud_key(self):
        self.create()
        for attempt in range(1, 60):
            if self.exists():
                self.create_gcloud_key()
                return True
            else:
                logging.info(
                    "Waiting for matched condition to exist, asset service account [{}] ] is mandatory,"
                    " retry attempt: [{}]".format(
                        self.get_email.split("@")[0], attempt))
                time.sleep(5)
                continue
        raise RuntimeError(
            "ERROR: Granting key to service account [{}] failed".format(
                self.get_email.split("@")[0]))

    def list(self):
        """Lists all service accounts for the current project."""

        service_accounts = self.gcp_account_service.projects().serviceAccounts().list(
            name='projects/' + self.project_id).execute()
        for account in service_accounts['accounts']:
            self.service_account_list.append(account['email'].split("@")[0])
        logging.info(self.service_account_list)
        return True

    def delete_keys(self):
        """Lists all service accounts for the current project."""
        self.list_keys()
        for key in self.service_account_keys_list:
            try:
                self.gcp_account_service.projects().serviceAccounts().keys().delete(name=key).execute()
            except:
                # Skipping failure on google internal key deletion, which is impossible
                if "HttpError 400 when requesting" in str(sys.exc_info()):
                    pass
                elif "does not exist" in str(sys.exc_info()):
                    pass
                else:
                    raise
        logging.info("Service account [{}] has no keys".format(self.service_account_id))
        return True


class JfrogGkeKubectlCli(JfrogKubectlCli):
    cloud_provider = "gcp"
    cloud_provider_sdm_name = "GCP"
    private_key = None

    def __init__(self, environment, region, gcloud_project, gcloud_zone, gcloud_cluster, gcloud_key):
        self.private_key = gcloud_key

        super(JfrogGkeKubectlCli, self).__init__(region=region,
                                                 project=gcloud_project,
                                                 cluster=gcloud_cluster,
                                                 zone=gcloud_zone,
                                                 environment=environment)

    def cloud_connect(self):
        """
        Connect to GCP cluster
        :return:
        """

        logging.info(
            "Connecting to GCP cluster [{}], zone [{}], project [{}]".format(self.cluster, self.zone, self.project))

        logging.info("Configuring gcloud auth using key-file")
        # TODO: service account json file should be removed once connect finish (needed by JFrogGCPStorage init)
        gcp_service_account_key_file = tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False)
        gcp_service_account_key_file.write(self.private_key)
        gcp_service_account_key_file.flush()

        os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = gcp_service_account_key_file.name

        gcloud_auth_command = "gcloud auth activate-service-account --key-file={}" \
                              "".format(gcp_service_account_key_file.name)
        self.exec_system_cmd(gcloud_auth_command)

        logging.info("Configuring kubectl for [{}] with gcloud".format(self.cluster))
        gcloud_update_kubeconfig = "gcloud container clusters get-credentials {} --zone {} --project {}" \
                                   "".format(self.cluster, self.zone, self.project)
        self.exec_system_cmd(gcloud_update_kubeconfig)

        self.config = config.load_kube_config()
        self.client_v1 = client.CoreV1Api()

        return True

class JFrogPrivateLink:
    __connection_limit = 10
    def __init__(self, privatelink_endpoint_service_id,
                 region,
                 narcissus_client,
                 customer_name,
                 privatelink_consumer_endpoint_id):
        self.privatelink_endpoint_service_id = privatelink_endpoint_service_id
        self.region = region
        self.narcissus_client = narcissus_client
        self.customer_name = customer_name
        self.privatelink_consumer_endpoint_id = privatelink_consumer_endpoint_id
        pass


    def set_consumer(self):
        action="accept"
        self.update_private_service(action=action)
        return self.validate_connection(desired_state=action)

    def delete_consumer(self):
        action="reject"
        self.update_private_service(action=action)
        self.validate_connection(desired_state=action)

    def get_private_service_details(self):
        private_service_details_cmd = f"gcloud compute service-attachments describe {self.privatelink_endpoint_service_id} --region={self.region} --format=\"json\""
        logging.info(f"Going to execute: {private_service_details_cmd}")
        private_service_json = self.exec_system_cmd(command=private_service_details_cmd, exit_code_expected=0)

        if not private_service_json:
            raise Exception(f"Couldn't get GCP Private Service Connect [{self.privatelink_endpoint_service_id}] details")
        return json.loads(private_service_json)

    def get_connection_from_private_service(self, desired_status):
        private_service_json = self.get_private_service_details()
        private_service_connections_list = private_service_json["connectedEndpoints"]
        found_connection = {}

        logging.info(f"Searching for a connection id of [{self.privatelink_consumer_endpoint_id}] from the Private Service connections")
        for connection in private_service_connections_list:
            if self.privatelink_consumer_endpoint_id == connection["pscConnectionId"] \
                and (connection["status"] == desired_status.upper() or connection["status"] == "ACCEPTED"):

                logging.info("Found the desired connection [{}]".format(connection))
                found_connection = connection

        if not found_connection:
            raise Exception(f"Endpoint {self.privatelink_consumer_endpoint_id} has not found")

        return found_connection

    def get_projectid_from_endpoint(self, endpoint):
        url = endpoint["endpoint"]
        path = str(urlparse(url).path)

        if path:
            project_id = path.split("/")[4]
        else:
            raise Exception(f"Couldn't find GCP path endpoint [{endpoint}]")

        if not project_id:
            raise Exception(f"Couldn't find a GCP project ID from endpoint [{endpoint}]")

        logging.info("Found a GCP Project ID [{}]".format(project_id))
        return project_id


    def get_consumer_list(self, list_name):
        private_service_desired_list_details = None
        if list_name not in ["consumer-accept-list", "consumer-reject-list"]:
            raise Exception(f"Illegal list name [{list_name}], failed on fetching list")

        kind_of_lists ={ "consumer-accept-list": "consumerAcceptLists", "consumer-reject-list": "consumerRejectLists"}
        private_service_json = self.get_private_service_details()
        logging.debug("Printing Private Service Connect details before the action")
        logging.debug(private_service_json)

        if kind_of_lists[list_name] not in private_service_json:
            logging.info(f"The list [{list_name}] doesn't exist in the Private Service Connect details, will create it for the first time")
        else:
            private_service_desired_list_details = private_service_json[kind_of_lists[list_name]]

        return private_service_desired_list_details

    def add_property_to_list(self, list_name, property):
        updated_list=[]
        property_exists_in_list = False
        current_list_details = self.get_consumer_list(list_name)

        logging.info("Going to add a property to list [{}]".format(list_name))
        for item in current_list_details:
            if list_name == "consumer-accept-list":
                connectionLimit = item["connectionLimit"]
                projectIdOrNum = item["projectIdOrNum"]
                string_to_insert = f"{projectIdOrNum}={connectionLimit}"
            else:
                string_to_insert = f"{item}"
            if property == string_to_insert:
                property_exists_in_list = True

            updated_list.append(string_to_insert)

        logging.info("Adding property [{}] to list [{}]".format(property, list_name))
        if not property_exists_in_list:
            updated_list.append(property)
        else:
            logging.info("A Property [{}] is already on the list [{}]".format(property, list_name))

        return updated_list

    def update_private_service(self, action):
        if action == "accept":
            list_name = "consumer-accept-list"
            desired_status = "accepted"
        elif action == "reject":
            list_name = "consumer-reject-list"
            desired_status = "rejected"
        else:
            raise Exception("Wrong action [{}]".format(action))

        logging.info("Getting endpoint information before updating GCP Private Service Connect [{}]".format(self.privatelink_consumer_endpoint_id))
        endpoint = self.get_connection_from_private_service(desired_status=desired_status)
        logging.info("Getting a GCP Project ID from endpoint [{}]".format(endpoint))
        project_id = self.get_projectid_from_endpoint(endpoint=endpoint)

        item_to_add_to_list = f"{project_id}"
        if action == "accept":
            #Connections limit is required only for adding a
            item_to_add_to_list = f"{item_to_add_to_list}={self.__connection_limit}"

        list_to_update = self.add_property_to_list(list_name=list_name, property=item_to_add_to_list)
        if not list_to_update:
            raise Exception(f"There is an issue with list [{list_name}], exiting...")

        #Converting List to string with commas
        list_to_update_str = ','.join(list_to_update)

        update_command = f"gcloud compute service-attachments update {self.privatelink_endpoint_service_id} --region={self.region} --{list_name}={list_to_update_str}"
        logging.info("Going to execute: {}".format(update_command))
        self.exec_system_cmd(command=update_command, exit_code_expected=0)

        logging.debug("Printing Private Service Connect details after the action")
        logging.debug(self.get_private_service_details())

    def validate_connection(self, desired_state, max_depth=60, recur_depth=0):
        found_connection = None
        sleep_secs = 10

        found_connection = self.get_connection_from_private_service(desired_status=desired_state)
        if found_connection is not None:
                psc_connection_id = found_connection["pscConnectionId"]
                if psc_connection_id:
                    return psc_connection_id

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

def get_gcp_account():
    gcp_service_account_path = os.environ['GOOGLE_APPLICATION_CREDENTIALS']

    # Login with gcloud is needed to create a key that fits Artifactory JAVA client
    logging.info("Authenticating gcloud with [{}] service account file".format(gcp_service_account_path))
    gcloud_auth_command = "gcloud auth activate-service-account --key-file {}".format(gcp_service_account_path)
    cmd = tools.do_shell_cmd(cmd=gcloud_auth_command)

    if cmd['exitcode'] != 0:
        raise RuntimeError("Failed to login with service account with gcloud: {}".format(str(cmd['output'])))

    # Get project ID from file
    with open(gcp_service_account_path) as f: contect = f.read()
    project_id = json.loads(contect)['project_id']

    credentials = service_account.Credentials.from_service_account_file(
        filename=gcp_service_account_path,
        scopes=['https://www.googleapis.com/auth/cloud-platform'])

    google_service = googleapiclient.discovery.build(serviceName='iam',
                                                     version='v1',
                                                     credentials=credentials,
                                                     cache_discovery=False)

    # Create google account object for service account use
    gcp_account = {
        "service": google_service,
        "project_id": project_id}

    return gcp_account


def get_gcp_bucket_size(bucketname, project_id):
    total_size = 0
    blob_list = []
    client = storage.Client(project=project_id)
    bucket = client.bucket(bucketname)
    blobs = bucket.list_blobs()
    for blob in blobs:
        size = blob.size
        total_size = total_size + size
        blob_list.append(blob)
    return blob_list, total_size


def delete_gcp_bucket_content(bucketame, project_id, blob_list):
    client = storage.Client(project=project_id)
    bucket = client.get_bucket(bucketame)
    bucket.delete_blobs(blob_list, timeout=1200)


def get_gcp_bucket_policy_bindings(bucketname, project_id):
    client = storage.Client(project=project_id)
    bucket = client.get_bucket(bucketname)
    policy = bucket.get_iam_policy(requested_policy_version=3)
    return policy._bindings


def create_static_ip_address(name, project_id, region=None):
    if region:
        logging.info(f'Region set to {region}, creating a regional static ip')
        create_cmd = f'gcloud compute addresses create {name} --project={project_id} --region {region}'
        describe_cmd = f"gcloud compute addresses describe {name} --project={project_id} --region {region} " \
                       "| grep address: | awk '{print $2}'"
    else:
        logging.info('Region is not set, creating a global static ip')
        create_cmd = f'gcloud compute addresses create {name} --project={project_id} --global'
        describe_cmd = f"gcloud compute addresses describe {name} --project={project_id} --global" \
                       "| grep address: | awk '{print $2}'"

    tools.run_command(command=create_cmd, print_stdout=False)
    ip_address = tools.run_command(command=describe_cmd, return_output=True, print_stdout=False)
    return ip_address.strip()


def describe_static_ip_address(name, project_id, region=None):
    if region:
        logging.info(f'Region set to {region}, describing a regional static ip')
        describe_cmd = f"gcloud compute addresses describe {name} --project={project_id} --region {region} " \
                       "| grep address: | awk '{print $2}'"
    else:
        logging.info('Region is not set, creating a global static ip')
        describe_cmd = f"gcloud compute addresses describe {name} --project={project_id} --global" \
                       "| grep address: | awk '{print $2}'"

    ip_address = tools.run_command(command=describe_cmd, return_output=True, print_stdout=False)
    return ip_address.strip()


def get_formatted_region(region):
    """
    Makes sure region is formatted correctly without availability zone e.g. us-east1-b returns us-east1
    :param region:
    :return:
    """
    if region.count('-') > 1:
        last_hyphen_index = region.rindex('-')
        formatted_region = region[:last_hyphen_index]
        return formatted_region
    return region


def main():
    logging.getLogger().setLevel(logging.INFO)
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
        gcp_service_account = JFrogGCPServiceAccount(service_account_id=name)
        if args.command == 'service_create':
            gcp_service_account.create_with_key()
        elif args.command == 'service_list':
            gcp_service_account.list()
        elif args.command == 'service_list_keys':
            gcp_service_account.list_keys()
        elif args.command == 'service_create_key':
            gcp_service_account.create_key()
        elif args.command == 'service_delete':
            gcp_service_account.delete()
        elif args.command == 'service_delete_keys':
            gcp_service_account.delete_keys()

    if 'bucket_' in args.command:
        bucket = JFrogGCPStorage(bucket_name=args.bucket_name)
        if args.command == 'bucket_create':
            bucket.create()
        if args.command == 'bucket_view_iam_members':
            bucket.bucket_view_iam_members()
        elif args.command == "bucket_create_owner":
            bucket.create()
            gcp_service_account = JFrogGCPServiceAccount(service_account_id=args.name)
            gcp_service_account.create_with_gcloud_key()
            bucket.grant_permissions(gcp_service_account.get_email)


if __name__ == '__main__':
    main()
