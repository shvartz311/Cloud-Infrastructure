import datetime
import os, yaml, shutil
import re
import subprocess, sys, traceback
import logging
import platform
import json
import time

from jinja2 import Environment, PackageLoader
from retry import retry
from aliyunsdkcore.client import AcsClient
from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.DeleteDomainRecordRequest import DeleteDomainRecordRequest
from aliyunsdkalidns.request.v20150109.UpdateDomainRecordRequest import UpdateDomainRecordRequest
from aliyunsdkram.request.v20150501.CreateUserRequest import CreateUserRequest
from aliyunsdkram.request.v20150501.GetUserRequest import GetUserRequest
from aliyunsdkram.request.v20150501.DeleteUserRequest import DeleteUserRequest
from aliyunsdkram.request.v20150501.CreateAccessKeyRequest import CreateAccessKeyRequest
from aliyunsdkram.request.v20150501.ListAccessKeysRequest import ListAccessKeysRequest
from aliyunsdkram.request.v20150501.DeleteAccessKeyRequest import DeleteAccessKeyRequest
from aliyunsdkram.request.v20150501.ListPoliciesForUserRequest import ListPoliciesForUserRequest
from aliyunsdkram.request.v20150501.CreatePolicyRequest import CreatePolicyRequest
from aliyunsdkram.request.v20150501.DeletePolicyRequest import DeletePolicyRequest
from aliyunsdkram.request.v20150501.ListUsersRequest import ListUsersRequest
from aliyunsdkram.request.v20150501.AttachPolicyToUserRequest import AttachPolicyToUserRequest
from aliyunsdkram.request.v20150501.DetachPolicyFromUserRequest import DetachPolicyFromUserRequest


class JfrogAliyunCli:
    aliyun_cmd = "aliyun"
    KMS_DEFAULT_REGIONS = ["cn-beijing"]

    def __init__(self, cmk_arns=None, cmk_alias=None, current_region=None, regions=None, creds={}):
        logging.debug("JfrogAliyunCli init - using aliyun-cli")

        if regions is None:
            self.regions = self.KMS_DEFAULT_REGIONS
        else:
            self.regions = regions

        if current_region is None:
            self.region = self.regions[0]
        else:
            self.region = current_region

        if creds:
            self.set_kms_environment(creds['ali_access_key_id'], creds['ali_secret_access_key'])

    def set_kms_environment(self, access_key, secret):
        os.environ["ACCESS_KEY_ID"] = access_key
        os.environ["ACCESS_KEY_SECRET"] = secret
        os.environ["REGION"] = self.region

    def create_cmk_alias(self, keyid,
                         aliasname):  # might be worth mentioning the region here, for the usage of multi-region availability
        alias = self.exec(f"kms CreateAlias --KeyId {keyid} --AliasName {aliasname}")
        return alias

    @retry(tries=3, delay=4)
    def decrypt_msg(self, cipherblob):
        if cipherblob is None:
            logging.info("Got Empty text to encrypt [Nothing to do]")
            return None
        logging.info('Decrypting with alikms')
        plaintext = self.exec(f"kms Decrypt --CiphertextBlob {cipherblob}", hide_string=[cipherblob])
        plaintext_json = json.loads(plaintext)["Plaintext"]
        return plaintext_json

    @retry(tries=3, delay=4)
    def encrypt_msg(self, aliasname, plaintext):
        if plaintext is None:
            logging.info("Got Empty text to encrypt [Nothing to do]")
            return None
        logging.info('Encrypting with alikms')
        encryptedtext = self.exec(f"kms Encrypt --KeyId {aliasname} --Plaintext {plaintext}", hide_string=[plaintext])
        encryptedtext_json = json.loads(encryptedtext)["CiphertextBlob"]
        return encryptedtext_json

    def exec(self, command, hide_string=[]):

        aliyun_cmd = "aliyun"

        final_cmd = "{} {}".format(aliyun_cmd, command)
        log_command = final_cmd
        for string_to_hide in hide_string:
            log_command = log_command.replace(string_to_hide, "XXXX")
        logging.debug("EXEC: [{}]".format(log_command))
        output = self.exec_system_cmd(final_cmd, exit_code_expected=0)
        return output

    def exec_system_cmd(self, command, exit_code_expected=None, hide_string=[]):
        """Wait_to_code is the exit code number to expect the function to return"""

        subproc = subprocess.run(command, shell=True, capture_output=True)

        output = subproc.stdout
        err = subproc.stderr
        exit_code = subproc.returncode
        if exit_code_expected is not None:
            if int(exit_code) != int(exit_code_expected):
                for string_to_hide in hide_string:
                    err = err.replace(string_to_hide, "XXXX")
                raise Exception("Exit code '{}' of command  not equal to '{}'. Error received: {}"
                                "".format(exit_code, exit_code_expected, err))

        return output


# JFrogAliCloudDNS
class JFrogAliCloudDNS:
    aliyun_cmd = "aliyun"
    record_set = {}  # new values
    hosted_zone = {}
    client_route53 = None
    aws_record_set = {}  # already exists record set, as it on AWS
    default_region = "cn-beijing"
    client = None
    record_type = None
    domain_name = None
    target = None
    host = None
    access_key = None
    secret = None
    record_id = None

    def __init__(self, record_type, domain_name, target, host, creds=None,
                 current_region=None, regions=None):
        self.record_type = record_type
        self.domain_name = domain_name
        self.target = target
        self.host = host
        if creds:
            self.access_key = creds['ali_access_key_id']
            self.secret = creds['ali_secret_access_key']
        else:
            self.access_key = os.environ["ALI_KMS_JENKINS_DEPLOYER_ACCESS_KEY_ID"]
            self.secret = os.environ["ALI_KMS_JENKINS_DEPLOYER_SECRET_ACCESS_KEY"]
        self.client = AcsClient(self.access_key, self.secret, self.default_region)
        if regions is None:
            self.regions = self.default_region
        else:
            self.regions = regions

        if current_region is None:
            self.region = self.regions[0]
        else:
            self.region = current_region

        self.record_id = self.get_id()

    def print_info(self, l, r):
        """Print using key=value format"""

        print('{:.<20}'.format(l) + str(r))

    def info(self):
        """Print the class metadata"""
        print("== JFrogAliCloudDNS Info =======================================================================")
        self.print_info("Domain Name", self.domain_name)
        self.print_info("Destination", self.target)
        self.print_info("Record Type", self.record_type)
        self.print_info("Host", self.host)
        print("=============================================================================================")

    def create(self):
        """Create AliDNS record set"""
        logging.info(f"Creating {self.record_type} {self.host} to {self.target}")
        try:
            request = AddDomainRecordRequest()
            request.set_accept_format('json')

            request.set_DomainName(self.domain_name)
            request.set_RR(self.host)
            request.set_Type(self.record_type)
            request.set_Value(self.target)

            response = self.client.do_action_with_exception(request)
            logging.info(f"Created record {self.host} with type {self.record_type} with value {self.target}")
            return True

        except Exception:
            logging.error(f"Oops! Cannot create {self.record_type} {self.host} to {self.target}")
            raise

    def set(self, updated_record_type=None, updated_target=None):
        """Set AliDNS record set ID"""
        if self.record_id is None:
            self.create()
        else:
            self.update()
        return True

    def get(self):
        """Get AliDNS record set"""
        logging.info(f"Retrieving {self.record_type} {self.host} to {self.target}")

        request = DescribeDomainRecordsRequest()
        request.set_accept_format('json')

        request.set_DomainName(self.domain_name)
        request.set_KeyWord(self.host)
        request.set_SearchMode("EXACT")

        try:
            response = self.client.do_action_with_exception(request)
            record = json.loads(response)["DomainRecords"]["Record"][0]
        except:
            record = None

        return record

    def get_id(self):
        """Get AliDNS record set"""
        if self.record_id is not None and self.record_id != {}:
            pass
        else:
            record_id = self.get()
            if record_id:
                self.record_id = record_id["RecordId"]
            else:
                self.record_id = record_id
        return self.record_id

    def delete(self):
        """Delete AliDNS record set"""
        logging.info(f"Deleting {self.record_type} {self.host} to {self.target}")

        try:
            request = DeleteDomainRecordRequest()
            request.set_accept_format('json')

            get_record = self.get_id()
            request.set_RecordId(get_record)
            response = self.client.do_action_with_exception(request)
            logging.info(f"Deleted record {self.host} with type {self.record_type} with value {self.target}")

        except Exception:
            logging.error(f"Oops! Cannot delete {self.record_type} {self.host} to {self.target}")
            traceback.print_exc(file=sys.stdout)

        return True

    def update(self, updated_record_type=None, updated_target=None):
        """Update AliDNS record set"""
        logging.info(f"Updating record {self.host} of type {self.record_type} with value {self.target}")

        if updated_record_type is None:
            updated_record_type = self.record_type
        if updated_target is None:
            updated_target = self.target

        try:
            request = UpdateDomainRecordRequest()
            request.set_accept_format('json')

            get_record = self.get()
            record_id = get_record['RecordId']
            record_type = get_record['Type']
            record_value = get_record['Value']

            if updated_record_type == record_type and updated_target == record_value:
                logging.info('Found nothing to update in existing record')
                return True

            request.set_RecordId(record_id)
            request.set_RR(self.host)
            request.set_Type(updated_record_type)
            request.set_Value(updated_target)
            response = self.client.do_action_with_exception(request)
            logging.info(f"Updated record {self.host} with type {updated_record_type} with value {updated_target}")

        except Exception:
            logging.error(
                f"Oops! Cannot update record {self.host} of type {updated_record_type} with values {updated_target}")
            traceback.print_exc(file=sys.stdout)

        return True


# JFrogRAM
class JFrogRAM:
    user_name = None
    user_access_key = None  # Current user_access_key, key should not be created if key already exists
    client_ram = None
    ram_user_record_set = {}  # already exists record set, as it on AWS
    ram_user_access_key_list = {}  # {"AccessKey": "SecretKey"} - SecretKey is NOT NONE for new AccessKey
    user_policy_inline_templates = {"AccessToBucketUser": "user/policy/AccessToBucketUser.json.j2"}
    default_region = "cn-beijing"

    def __init__(self, user_name, oss_bucket=None, oss_bucket_path=None, user_access_key=None, creds={},
                 policy_template=None,
                 deny_other_resources=False):
        """

        :param user_name:
        :param user_access_key: Can be None for new users / First registration
        :param oss_bucket:
        :param oss_bucket_path:
        :param creds:
        """

        self.user_name = user_name
        self.user_access_key = user_access_key
        self.oss_bucket = oss_bucket
        self.deny_other_resources = deny_other_resources

        self.access_key = os.environ["ALI_KMS_JENKINS_DEPLOYER_ACCESS_KEY_ID"]
        self.secret = os.environ["ALI_KMS_JENKINS_DEPLOYER_SECRET_ACCESS_KEY"]
        self.client = AcsClient(self.access_key, self.secret, self.default_region)

        if oss_bucket_path is None:
            self.oss_bucket_path = "aol-{}/filestore".format(user_name)
        else:
            self.oss_bucket_path = oss_bucket_path

        if self.user_name is not None:
            self.ram_user_record_set = self.get_user()

        if policy_template is not None:
            self.user_policy_inline_templates = policy_template

    def set(self):
        """
        Create and setup RAM user
        :return:
        """
        self.create_user()
        self.put_user_policies()

        if self.user_access_key is None or self.user_access_key == "None":
            self.create_access_key()

        return True

    def delete(self):
        """

        :return:
        """
        try:
            self.delete_user()
        except:
            # Sleep was added to allow Alicloud to sync, there are dependencies between the entities
            self.delete_access_keys()
            time.sleep(2)
            self.delete_user_policies()
            time.sleep(2)
            self.delete_user()

        return True

    def get_user(self):
        """
        Check RAM user record set
        :return:
        """
        empty_record_set = {}

        print("INFO: Getting RAM information for user [{}]".format(self.user_name))

        if self.ram_user_record_set is not None and self.ram_user_record_set != {}:
            return self.ram_user_record_set

        logging.debug("Getting information from RAM")
        try:
            request = GetUserRequest()
            request.set_accept_format('json')
            request.set_UserName(self.user_name)
            response = self.client.do_action_with_exception(request)
            ram_user_record_set = json.loads(response)["User"]["UserName"]

        except Exception:
            logging.info("RAM user does not exists on Alicloud")
            return empty_record_set

        logging.debug("Response from server [ali_ram_set]: {}".format(ram_user_record_set))

        if self.user_name == ram_user_record_set:
            return ram_user_record_set

        return self.ram_user_record_set

    def create_user(self):
        """
        Create/update RAM user
        :return: True
        """

        logging.debug("Generate user for {}".format(self.user_name))

        if self.ram_user_record_set != {}:
            logging.info("RAM user [{}] already exists, skipping".format(self.user_name))
            return True

        logging.info("Creating RAM user as {}".format(self.user_name))

        try:
            request = CreateUserRequest()
            request.set_accept_format('json')
            request.set_UserName(self.user_name)
            response = self.client.do_action_with_exception(request)
            logging.info("Created RAM user as {} successfully".format(self.user_name))
            logging.debug("Response from server: {}".format(response))
            self.ram_user_record_set = self.get_user()

        except Exception:
            traceback.print_exc(file=sys.stdout)
            raise Exception("Oops! Cannot set RAM user {}".format(self.user_name))

        return True

    def delete_user(self):
        """
        Delete RAM user record set
        :return:
        """

        logging.info("Deleting RAM user {}".format(self.user_name))

        if self.ram_user_record_set == {} or self.ram_user_record_set is None:
            logging.debug("ram_user_record_set: {}".format(self.ram_user_record_set))
            logging.info("Nothing to delete, RAM [{}] does not exist".format(self.user_name))
            return True

        try:

            request = DeleteUserRequest()
            request.set_accept_format('json')
            request.set_UserName(self.user_name)
            response = self.client.do_action_with_exception(request)

            # Clear AWS local record
            self.ram_user_record_set = {}
            logging.info("Delete RAM user for {} successfully".format(self.user_name))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception:
            logging.error("Oops! Cannot delete RAM user for {}".format(self.user_name))
            traceback.print_exc(file=sys.stdout)
            raise

    def create_access_key(self):
        """
        Create AccessKey
        :return: dict{AccessKey, SecretKey}
        """

        logging.info("Creating RAM user AccessKey for {}".format(self.user_name))

        self.ram_user_access_key_list = self.list_access_keys()

        # check if Limit is not Exceeded (max 2 access keys)
        if len(self.ram_user_access_key_list) == 2 or len(self.ram_user_access_key_list) > 2:
            raise Exception("AccessKey LimitExceeded Exception!")

        try:

            request = CreateAccessKeyRequest()
            request.set_accept_format('json')
            request.set_UserName(self.user_name)
            response = self.client.do_action_with_exception(request)

            logging.debug("Response from server: {}".format(response))

            access_key_id = json.loads(response)['AccessKey']['AccessKeyId'] or None
            secret_access_key = json.loads(response)['AccessKey']['AccessKeySecret'] or None

            if access_key_id is None or secret_access_key is None:
                raise Exception("User AccessKey cannot be created")

            print("INFO: Created RAM user AccessKey for {} successfully".format(self.user_name))
            self.ram_user_access_key_list[access_key_id] = secret_access_key

        except Exception:
            logging.error("Oops! Cannot create user AccessKey for {}".format(self.user_name))
            traceback.print_exc(file=sys.stdout)
            raise Exception("User AccessKey cannot be created!")

        return True

    def list_access_keys(self):
        """
        List AccessKeys, KeyStatus can be Active / inactive
        :return: dict{AccessKey, KeyStatus}
        """

        logging.info("Getting RAM user AccessKeys for user [{}]".format(self.user_name))

        try:
            request = ListAccessKeysRequest()
            request.set_UserName(self.user_name)
            request.set_accept_format('json')
            response = self.client.do_action_with_exception(request)

            all_keys = {}
            for key in json.loads(response)['AccessKeys']['AccessKey']:
                all_keys[key['AccessKeyId']] = key['Status']

            logging.debug("Response from server: {}".format(response))
            logging.debug("Getting RAM user AccessKeys for [{}] successfully".format(self.user_name))

        except Exception:
            logging.error("Oops! Cannot fetch user AccessKeys for {}".format(self.user_name))
            traceback.print_exc(file=sys.stdout)
            raise Exception("User AccessKey cannot be fetched")

        logging.debug("all_keys {}".format(all_keys))
        return all_keys

    def delete_access_keys(self):
        """
        Delete RAM user access keys
        :return:
        """

        logging.info("Deleting RAM user access keys for {}".format(self.user_name))

        keys = self.list_access_keys()
        logging.debug("keys list to delete: {}".format(keys))
        for key in keys:
            try:
                request = DeleteAccessKeyRequest()
                request.set_accept_format('json')
                request.set_UserAccessKeyId(key)
                request.set_UserName(self.user_name)
                response = self.client.do_action_with_exception(request)
                logging.info("Delete RAM user access key {} for {} successfully".format(key, self.user_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                traceback.print_exc(file=sys.stdout)
                raise ("Oops! Cannot delete RAM user access key {} for {}".format(key, self.user_name))

        return True

    def list_user_policies(self):
        try:
            request = ListPoliciesForUserRequest()
            request.set_accept_format('json')
            request.set_UserName(self.user_name)
            response = self.client.do_action_with_exception(request)

            if len(json.loads(response)['Policies']) > 0:
                all_policies = []
                for policy in json.loads(response)['Policies']['Policy']:
                    all_policies.append(policy['PolicyName'])
                return all_policies
        except:
            traceback.print_exc(file=sys.stdout)
            raise Exception("User policies cannot be fetched")

    def list_users(self, prefix=None):
        try:
            users_list = []
            print("Fetching all RAM users from Alicloud...")
            request = ListUsersRequest()
            request.set_accept_format('json')
            response = self.client.do_action_with_exception(request)
            json_response = json.loads(response)['Users']['User']
            all_users_list = []
            for user in json_response:
                username = user['UserName']
                if prefix is not None:
                    if username.startswith(prefix):
                        sys.stdout.write("Number of RAMs: [%d]   \r" % (len(all_users_list)))
                        sys.stdout.flush()
                        users_list.append(username)
            all_users_list.extend(users_list)
            print("Found [{}] RAM users".format(len(all_users_list)))
            return all_users_list
        except:
            traceback.print_exc(file=sys.stdout)
            raise Exception("User policies cannot be fetched")

    def put_user_policies(self):
        """
        Create RAM user policy and attach it to that user
        :return: True
        """
        if self.oss_bucket is None:
            raise ValueError("oss_bucket is mandatory for put_user_policies()")

        logging.debug("Generate policies for {}".format(self.user_name))
        logging.info("Creating RAM user policy for {}".format(self.user_name))

        env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates/alicloud'),
                          keep_trailing_newline=True)
        acs_arn_prefix = 'acs'
        policy_template_keys = {"oss_bucket": self.oss_bucket, "oss_bucket_path": self.oss_bucket_path,
                                "acs_arn_prefix": acs_arn_prefix}
        for policy in self.user_policy_inline_templates:
            policy_name = "{}_{}".format(policy, self.user_name)
            policy_template = env.get_template(self.user_policy_inline_templates[policy])

            logging.info("Creating RAM user policy name [{}] based on {} template".format(
                policy_name, policy_template))

            policy_document = policy_template.render(policy_template_keys)
            try:

                request = CreatePolicyRequest()
                request.set_accept_format('json')
                request.set_PolicyName(policy_name)
                request.set_PolicyDocument(policy_document)

                response = self.client.do_action_with_exception(request)
                logging.info("Created RAM user policy as {} successfully".format(policy_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                logging.error("Oops! Cannot set RAM user policy {}{} ".format(policy_name, policy_document))
                traceback.print_exc(file=sys.stdout)
                raise

            logging.info("Attaching newly created policy [{}] to RAM user".format(policy_name, self.user_name))

            try:

                request = AttachPolicyToUserRequest()
                request.set_accept_format('json')
                request.set_PolicyType("Custom")
                request.set_PolicyName(policy_name)
                request.set_UserName(self.user_name)

                response = self.client.do_action_with_exception(request)
                logging.info("Attached user policy {} to {} successfully".format(policy_name, self.user_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                logging.error("Oops! Cannot attach policy {} to RAM user {} ".format(policy_name, self.user_name))
                traceback.print_exc(file=sys.stdout)
                raise

        return True

    def delete_user_policies(self):
        """
        Delete RAM user record set and detach it from that user
        :return:
        """

        policies = self.list_user_policies()

        logging.info("Deleting RAM user policies for {}".format(self.user_name))

        logging.debug("policies list to detach and delete: {}".format(policies))
        for policy in policies:

            logging.info("Detaching policy [{}] from RAM user".format(policy, self.user_name))
            try:
                request = DetachPolicyFromUserRequest()
                request.set_accept_format('json')
                request.set_PolicyType("Custom")
                request.set_PolicyName(policy)
                request.set_UserName(self.user_name)

                response = self.client.do_action_with_exception(request)
                logging.info("Detached user policy {} from {} successfully".format(policy, self.user_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                logging.error("Oops! Cannot detach policy {} from RAM user {} ".format(policy, self.user_name))
                traceback.print_exc(file=sys.stdout)
                raise

            try:

                request = DeletePolicyRequest()
                request.set_accept_format('json')
                request.set_PolicyName(policy)

                response = self.client.do_action_with_exception(request)
                logging.info("Delete RAM user policy {} for {} successfully".format(policy, self.user_name))
                logging.debug("Response from server: {}".format(response))
                return True

            except Exception:
                traceback.print_exc(file=sys.stdout)
                raise ("Oops! Cannot delete RAM user policy {} for {}".format(policy, self.user_name))

        return True

    @staticmethod
    def print_info(l, r):
        """
        Print using key=value format
        :param l:
        :param r:
        :return:
        """
        print('{:.<25}'.format(l) + str(r))

    def info(self):
        """
        Print the class metadata
        :return: True
        """
        print("== JFrogRAM Info =======================================================================")
        self.print_info("User Name", self.user_name)
        self.print_info("RAM User Record Set", self.ram_user_record_set)
        self.print_info("RAM User Access Key", self.ram_user_access_key_list)
        print("=============================================================================================")

def manage_app_cname(action, domain_name, target_name, host, ali_dns_creds=None, region_name=None, record_type="CNAME"):

    if action == "set" and "_" in host:
        raise ValueError("manage_app_cname | [{}] is not a valid subdomain ".format(host))

    dns_record = JFrogAliCloudDNS(record_type=record_type,
                                  domain_name=domain_name,
                                  target=target_name,
                                  host=host,
                                  creds=ali_dns_creds,
                                  current_region=region_name)

    if action == "set":
        dns_record.set()
    elif action == "delete":
        dns_record.delete()
    else:
        raise Exception("Cannot [{}] DNS [action not supported]".format(action))

    del dns_record


if __name__ == "__main__":
    logging.info("*** Test mode ***")

    logging.getLogger().setLevel(logging.DEBUG)
    logging.debug("*** Debug mode ***")
    oss_bucket = "k8s-stg-cn-beijing-shared-main"

    try:

        print("in main")
        aliram = JFrogRAM(user_name="orys123",oss_bucket=oss_bucket)
        # aliram.set()
        # aliram.list_users()
        # aliram.list_user_policies()
        # aliram.create_access_key()
        # aliram.list_access_keys()
        # aliram.delete_user_policies()
        # aliram.delete_access_keys()
        # aliram.delete_user()
        # aliram.info()


    except Exception:
        logging.error("Oops!")
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
