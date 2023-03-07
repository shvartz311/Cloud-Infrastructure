#!/usr/bin/env python3

# http://boto3.readthedocs.io/en/latest/reference/services/route53.html

import re
import json
from retry import retry
import requests
from jinja2 import Environment, PackageLoader
from exitstatus import ExitStatus
import boto3
import botocore
from botocore.exceptions import ClientError
import aws_encryption_sdk
from aws_encryption_sdk.identifiers import CommitmentPolicy
from jfrogdevopstools.tools.kubectl import *
import time
from datetime import datetime, timedelta
from jfrogdevopstools.logger.logging_data import LoggingData
from jfrogdevopstools.logger.thread_logging_helper import ThreadLoggingHelper

# Set log level of aws_encryption_sdk to WARN because lots of unnecessary logs...
logging.getLogger("aws_encryption_sdk.streaming_client").setLevel(logging.WARN)
logging.getLogger("aws_encryption_sdk.key_providers.base").setLevel(logging.WARN)

AWS_IP_RANGE_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

AWS_KMS_ARN_PREFIX = "arn:aws:kms"

# Base REST URLs by environment
ROUTE53_RECORD_MAP = {}
ROUTE53_RECORD_MAP["alias"] = {"type": "A", "ttl": 300, "description": "Alias"}
ROUTE53_RECORD_MAP["cname"] = {"type": "CNAME", "ttl": 60, "description": "Cname"}


def printInfo(msg, context=None):
    if context is None:
        print("INFO: %s" % msg)
    else:
        print("[%s] INFO: %s" % (context, msg))


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


# JFrog AWS KMS
# https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/python-example-code.html
# https://aws.amazon.com/blogs/security/how-to-use-the-new-aws-encryption-sdk-to-simplify-data-encryption-and-improve-application-availability/
class JFrogAWSKms:
    cmk_arns = None
    region = None
    regions = None
    account_id = None
    kms_client = None
    kms_master_key_provider_client = None
    encryption_sdk_client = None
    sso_profile = None
    KMS_DEFAULT_REGIONS = ["us-east-1", "ap-southeast-2", "eu-central-1"]

    def __init__(self, cmk_arns=None, cmk_alias=None, current_region=None, regions=None, creds={}):
        logging.debug("Init JFrogAWSKms")

        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret(creds)

        if regions is None:
            self.regions = self.KMS_DEFAULT_REGIONS
        else:
            self.regions = regions

        if current_region is None:
            self.region = self.regions[0]
        else:
            self.region = current_region

        if self.sso_profile:
            boto3_session = boto3.session.Session(profile_name=f"{self.sso_profile}")
        else:
            # Create Boto3 session and Boto3 KMS client
            boto3_session = boto3.session.Session(aws_access_key_id=self.aws_access_key_id,
                                                  aws_secret_access_key=self.aws_secret_access_key,
                                                  region_name=self.region)
        self.account_id = get_account_id(creds, region=self.region)
        botocore_session = boto3_session._session
        self.kms_client = boto3_session.client('kms')

        # KMS CMK must be set in encryption flow AWS Encryption SDK embeds the KMS CMK key id ARN in the header of
        # the encrypted blob No Need to set KMS CMK in decryption flow AWS Encryption SDK dynamically parses the
        # header during decryption and establish the key required to decrypt the data
        if cmk_arns is not None:
            self.cmk_arns = cmk_arns
        elif cmk_alias is not None:
            self.cmk_arns = self.get_cmk_arns_list(cmk_alias)
        else:
            logging.info("JFrogAWSKms - init with no cmk arn or cmk alias; OK for decrypt, CANNOT encrypt")

        # Create KMS master key provider
        kms_kwargs = dict()
        kms_kwargs["botocore_session"] = botocore_session
        if self.cmk_arns is not None:
            kms_kwargs["key_ids"] = self.cmk_arns
            self.kms_master_key_provider_client = aws_encryption_sdk.StrictAwsKmsMasterKeyProvider(**kms_kwargs)
        else:
            self.kms_master_key_provider_client = aws_encryption_sdk.DiscoveryAwsKmsMasterKeyProvider(**kms_kwargs)
        self.encryption_sdk_client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT)

    def create_cmk(self, cmk_alias=None):

        # NOTE: the cmk will be created in the region configured in the boto3 client
        desc = 'Key for protecting critical data, e.g.: data keys'
        response = self.kms_client.create_key(Description=desc)
        key_id = response['KeyMetadata']['KeyId']
        key_arn = response['KeyMetadata']['Arn']

        # Create an alias for a CMK
        response = self.kms_client.create_alias(AliasName="alias/{}".format(cmk_alias),
                                                TargetKeyId=key_id)

        return key_arn

    def generate_data_key(self, key_id):

        # Generate a data key
        response = self.kms_client.generate_data_key(KeyId=key_id,
                                                     KeySpec='AES_256')
        plaintext_data_key = response['Plaintext']
        ciphertext_data_key = response['CiphertextBlob']

        return {"plaintext_data_key": plaintext_data_key,
                "ciphertext_data_key": ciphertext_data_key}

    def kms_cmk_key_arn_format(region, account_id, kms_key_id):
        return "{}:{}:{}:key/{}".format(AWS_KMS_ARN_PREFIX, region, account_id, kms_key_id)

    def kms_cmk_alias_arn_format(region, account_id, kms_alias_name):
        return "{}:{}:{}:alias/{}".format(AWS_KMS_ARN_PREFIX, region, account_id, kms_alias_name)

    def get_cmk_arn(self, cmk_ref):

        try:
            # Input cmk_ref can be: key id, key arn, alias name or alias arn
            response = self.kms_client.describe_key(KeyId=cmk_ref)
            return response['KeyMetadata']['Arn']

        except Exception as e:
            print(e)
            return None

    def get_cmk_arns_list(self, cmk_alias):

        cmk_arns_list = []

        # Collect all regions cmk from kms
        for region in self.regions:
            cmk_alias_arn = JFrogAWSKms.kms_cmk_alias_arn_format(region, self.account_id, cmk_alias)

            # This check can't be performed on different region keys except for the region
            # set to boto3 on connect
            # key_arn = self.get_cmk_arn(cmk_alias_arn)
            # if key_arn is None:
            #    raise RuntimeError("Couldn't find cmk '{}' for region '{}'".format(cmk_alias, region))

            cmk_arns_list.append(cmk_alias_arn)

        return cmk_arns_list

    def list_existing_keys(self):

        print("List existing KMS customer managed keys:")
        print("IMPORANT: please note key description in order to understand which ket should be used for which purpose")
        print("-------------------------------------------------------------------------------------------------------")
        list_aliases = self.kms_client.list_aliases()

        for alias in list_aliases["Aliases"]:
            alias_name = re.search('alias\/(.*_master_key)', alias["AliasName"])
            if alias_name is not None:
                describe_key = self.kms_client.describe_key(KeyId=alias["TargetKeyId"])
                print("{} : {}".format(alias_name.group(1), describe_key["KeyMetadata"]["Description"]))

        print("-------------------------------------------------------------------------------------------------------")

    def decrypt_msg(self, ciphertext):

        plaintext, encryptor_header = self.encryption_sdk_client.decrypt(source=ciphertext,
                                                                 key_provider=self.kms_master_key_provider_client)

        return plaintext

    def decrypt_file(self, ciphertext_file_path):

        if not os.path.isfile(ciphertext_file_path):
            raise KeyError("Input file [%s] does not exist" % ciphertext_file_path)

        # TODO: override original file
        new_plaintext_filename = ciphertext_file_path + '.decrypted'
        new_plaintext_filename = new_plaintext_filename.replace('.encrypted', '')

        with open(ciphertext_file_path, 'rb') as ct_file, open(new_plaintext_filename, 'wb') as pt_file:
            with self.encryption_sdk_client.stream(
                    mode='d',
                    source=ct_file,
                    key_provider=self.kms_master_key_provider_client
            ) as decryptor:
                for chunk in decryptor:
                    pt_file.write(chunk)

        return True

    def encrypt_msg(self, plaintext):
        if plaintext is None:
            logging.info("Got Empty text to encrypt [Nothing to do]")
            return None
        ciphertext, encryptor_header = self.encryption_sdk_client.encrypt(source=plaintext,
                                                                  key_provider=self.kms_master_key_provider_client)

        return ciphertext

    def encrypt_file(self, plaintext_file_path):

        if not os.path.isfile(plaintext_file_path):
            raise KeyError("Input file [%s] does not exist" % plaintext_file_path)

        # TODO: override original file
        ciphertext_filename = plaintext_file_path + '.encrypted'

        # Encrypt the plaintext source data
        with open(plaintext_file_path, 'rb') as plaintext, open(ciphertext_filename, 'wb') as ciphertext:
            with self.encryption_sdk_client.stream(
                    mode='e',
                    source=plaintext,
                    key_provider=self.kms_master_key_provider_client
            ) as encryptor:
                for chunk in encryptor:
                    ciphertext.write(chunk)

        # TODO: override original file with encrypted file

        return True


# JFrogAWSRout53
class JFrogAWSRout53:
    record_set = {}  # new values
    hosted_zone = {}
    target = []  # list of destinations
    client_route53 = None
    aws_record_set = {}  # already exists record set, as it on AWS
    sso_profile = None
    aws_region_name = None

    # https://docs.aws.amazon.com/general/latest/gr/elb.html
    aws_hostedzone_internals = {
        "us-west-2": "Z1H1FL5HABSF5",
        "us-east-1": "Z35SXDOTRQ7X7K",
        "us-west-1": "Z368ELLRRE2KJ0"
    }

    @staticmethod
    def get_intenral_hostedzone(lb_url):
        for region in JFrogAWSRout53.aws_hostedzone_internals:
            if region in lb_url:
                return JFrogAWSRout53.aws_hostedzone_internals[region]

    # target can be a string or a list
    # special_conf
    # e.g. special_conf={ "TTL":12, 'Weight': 123 }
    def __init__(self, record_type, domain_name, target, special_conf={}, creds=None, hosted_zone_name=None, aws_region_name=None):

        self.target = target
        self.aws_region_name = aws_region_name
        # convert string to list
        if isinstance(target, str):
            target = [target]

        if domain_name.count(".") == 1:
            hosted_zone_name = domain_name
        # Get hosted zone
        elif hosted_zone_name is None:
            m = re.search('.*\.(\w+\.\w+)', domain_name)
            hosted_zone_name = m.group(1)

        # Validate hosted zone
        if not domain_name.endswith(hosted_zone_name):
            raise ValueError("Hosted zone [{}] doesn't fit the domain name [{}]".format(hosted_zone_name,
                                                                                        domain_name))
        logging.info("Using hosted zone [{}]".format(hosted_zone_name))

        self.record_set = {
            "Name": domain_name,
            "Type": ROUTE53_RECORD_MAP[record_type]['type'],
            "TTL": ROUTE53_RECORD_MAP[record_type]['ttl'],
            "ResourceRecords": []
        }

        for value in target:
            self.record_set["ResourceRecords"].append({"Value": value})

        force_creds = True if creds else False
        # Set AWS Secret
        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret(creds=creds,
                                                                                                force_creds=force_creds)

        if self.sso_profile and not creds:
            boto3_session = boto3.session.Session(profile_name=f"{self.sso_profile}")
            botocore_session = boto3_session._session
            self.client_route53 = boto3_session.client('route53')

        else:
            # Create Boto3 session and Boto3 KMS client
            self.client_route53 = boto3.client('route53', aws_access_key_id=self.aws_access_key_id,
                                               aws_secret_access_key=self.aws_secret_access_key,
                                               region_name=self.aws_region_name)
            logging.debug(f"from accesskey :{self.aws_access_key_id}")

        try:
            logging.info(f"Hosted zone name {hosted_zone_name}")
            self.hosted_zone = self.client_route53.list_hosted_zones_by_name(
                DNSName=hosted_zone_name,
                MaxItems='1'
            )['HostedZones'][0]

            logging.debug("Response from server [hosted_zone]: {}".format(self.hosted_zone))

            if not hosted_zone_name + '.' == self.hosted_zone['Name']:
                raise Exception("Hosted Zone does not exist")
        except Exception as e:
            logging.info(f"Caught exception: {e}")
            raise RuntimeError("Hosted Zone Name [ " + hosted_zone_name + " ] is not supported")

        self.aws_record_set = self.get()

        # Load external conf
        self.record_set.update(special_conf)

    def set(self):
        """Create/update route53 record set"""
        logging.info("Creating {} {} to {}".format(self.record_set['Type'], self.record_set['Name'], str(self.target)))
        try:
            logging.debug("Set ResourceRecordSet: {}".format(self.record_set))
            if "dualstack" in self.record_set['ResourceRecords'][0]["Value"]:
                target_domain = self.record_set['ResourceRecords'][0]["Value"]
                self.record_set["AliasTarget"] = {"HostedZoneId": self.get_intenral_hostedzone(target_domain),
                                                  "DNSName": target_domain,
                                                  "EvaluateTargetHealth": False}

                del(self.record_set['ResourceRecords'])  # Those records are not needed for an A alias record
                del(self.record_set['TTL'])  # Those records are not needed for an A alias record

            change_batch = {'Changes': [{'Action': 'UPSERT',
                                         'ResourceRecordSet': self.record_set
                                         }, ]}
            response = self.client_route53.change_resource_record_sets(HostedZoneId=self.hosted_zone['Id'],
                                                                       ChangeBatch=change_batch)
            logging.info("Created route53 {} {} to {} successfully".format(self.record_set['Type'],
                                                                           self.record_set['Name'],
                                                                           self.target))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception:
            logging.error("Oops!  Cannot create {} {} to {}".format(self.record_set['Type'], self.record_set['Name'],
                                                                    self.target))
            raise

    def get(self):
        """Check route53 record set"""

        logging.info("INFO: Getting {} information".format(self.record_set['Name']))

        if self.aws_record_set is not None and self.aws_record_set != {}:
            return self.aws_record_set

        logging.info("Getting information from Route53")
        aws_record_set = self.client_route53.list_resource_record_sets(
            HostedZoneId=self.hosted_zone['Id'],
            StartRecordName=self.record_set['Name'],
            StartRecordType=self.record_set['Type'],
            MaxItems='1'
        )['ResourceRecordSets'][0]

        logging.debug("Response from server [aws_record_set]: {}".format(aws_record_set))

        if self.record_set['Name'] + '.' == aws_record_set['Name']:
            return aws_record_set

        return self.aws_record_set

    def delete(self):
        "Delete route53 record set"

        print("INFO: Deleting {} {}".format(self.record_set['Type'], self.record_set['Name']))

        if self.aws_record_set is None or self.aws_record_set == {}:
            print("INFO: Nothing to delete, [{}] does not exist".format(self.record_set['Name']))
            return True

        try:
            # Ignore TTL differences for deletion
            delete_set_record = dict.copy(self.record_set)
            delete_set_record['TTL'] = self.aws_record_set['TTL']

            # Ignore where DNS is pointing to in deletion
            delete_set_record['ResourceRecords'] = self.aws_record_set['ResourceRecords']

            response = self.client_route53.change_resource_record_sets(HostedZoneId=self.hosted_zone['Id'],
                                                                       ChangeBatch={'Changes': [
                                                                           {'Action': 'DELETE',
                                                                            'ResourceRecordSet': delete_set_record
                                                                            },
                                                                       ]}
                                                                       )

            print("Delete route53 {} {} to {} response: {}".format(delete_set_record['Type'], delete_set_record['Name'],
                                                                   self.target,
                                                                   response))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception:
            print("Oops!  Cannot delete {} {} to {}".format(delete_set_record['Type'], delete_set_record['Name'],
                                                            self.target))
            traceback.print_exc(file=sys.stdout)

        return True

    def print_info(self, l, r):
        "Print using key=value format"

        print('{:.<20}'.format(l) + str(r))

    def info(self):
        "Print the class metadata"
        print("== JFrogAWSRout53 Info =======================================================================")
        self.print_info("Domain Name", self.record_set['Name'])
        self.print_info("Destination", self.target)
        self.print_info("Record Set", self.record_set)
        self.print_info("Record Set (AWS)", self.aws_record_set)
        self.print_info("Hosted Zone", json.dumps(self.hosted_zone))
        print("=============================================================================================")


    def create_health_check(self, resource_path):
        logging.info("Creating Route53 health_check {} ".format(self.record_set['Name']))
        try:
            response = self.client_route53.create_health_check(
                CallerReference=str(int(time.time())),
                HealthCheckConfig={
                    'Port': 443,
                    'Type': 'HTTPS',
                    'ResourcePath': resource_path,
                    'FullyQualifiedDomainName': self.record_set['Name'],
                    'RequestInterval': 10,
                    'FailureThreshold': 3,
                    'EnableSNI': True
                }
            )

            logging.info("Created route53 health_check {} successfully".format(self.record_set['Name']))
            logging.debug("Response from server: {}".format(response))
            health_check_id = response['HealthCheck']['Id']
            self.set_health_check_name(health_check_id)
            return True

        except Exception:
            logging.error("Oops!  Cannot create route53 health_check {} ".format(self.record_set['Name']))
            raise

    def set_health_check_name(self, health_check_id):
        logging.info("Set Route53 health_check {} name ".format(self.record_set['Name']))
        try:
            response = self.client_route53.change_tags_for_resource(
                ResourceType='healthcheck',
                ResourceId=health_check_id,
                AddTags=[
                    {
                        'Key': 'Name',
                        'Value': self.record_set['Name']
                    },
                ],
            )
            logging.info("Set route53 health_check {} name successfully".format(self.record_set['Name']))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception:
            logging.error("Oops!  Cannot set route53 health_check {} name".format(self.record_set['Name']))
            raise

    def get_health_check_list(self):
        logging.info("Get Route53 health_check list")
        try:
            response = self.client_route53.list_health_checks()
            return response
        except Exception:
            logging.error("Oops!  Cannot set route53 health_check list")
            raise

    def is_health_check_exist(self, health_check_name):
        logging.info("check if Route53 health_check {} already exist".format(health_check_name))
        try:
            health_check_list = self.get_health_check_list()
            for health_check in health_check_list['HealthChecks']:
                if 'FullyQualifiedDomainName' in health_check['HealthCheckConfig']:
                    if health_check_name == health_check['HealthCheckConfig']['FullyQualifiedDomainName']:
                        return True
            return False
        except Exception:
            logging.error("Oops! Cannot check if health check exist")
            raise

    def is_cname_exist(self):
        if self.aws_record_set == {}:
            return False
        else:
            return True


    def get_health_check_id(self, health_check_name):
        logging.info("check if Route53 health_check {} already exist".format(self.record_set['Name']))
        try:
            health_check_list = self.get_health_check_list()
            for health_check in health_check_list['HealthChecks']:
                if 'FullyQualifiedDomainName' in health_check['HealthCheckConfig']:
                    if health_check_name == health_check['HealthCheckConfig']['FullyQualifiedDomainName']:
                        return health_check['Id']
            return None
        except Exception:
            logging.error("Oops! Cannot check if health check exist")
            raise

    def set_failover_alias(self, failover_role, health_check_name):
        """Create/update alias route53 record set"""
        logging.info("Creating alias {} {} to {}".format(self.record_set['Type'], self.record_set['Name'], str(self.target)))
        # get alias record data
        host_zone = self.hosted_zone['Id'].replace('/hostedzone/', '')
        alias_target = {'HostedZoneId': host_zone, 'DNSName': health_check_name,
                        'EvaluateTargetHealth': True}
        self.record_set.update({'SetIdentifier': health_check_name, 'Failover': failover_role, 'AliasTarget': alias_target,
                                'HealthCheckId': self.get_health_check_id(health_check_name)})
        # remove unrelevant rows for alias record
        if 'TTL' in self.record_set:
            self.record_set.pop('TTL')
        if 'ResourceRecords' in self.record_set:
            self.record_set.pop('ResourceRecords')

        try:
            logging.debug("Set ResourceRecordSet: {}".format(self.record_set))

            response = self.client_route53.change_resource_record_sets(HostedZoneId=self.hosted_zone['Id'],
                                                                   ChangeBatch={'Changes': [{'Action': 'UPSERT',
                                                                                             'ResourceRecordSet': self.record_set
                                                                                             }, ]}
                                                                   )
            logging.info("Created route53 alias {} {} to {} successfully".format(self.record_set['Type'],
                                                                       self.record_set['Name'],
                                                                       health_check_name))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception:
            logging.error("Oops!  Cannot create alias {} {} to {}".format(self.record_set['Type'], self.record_set['Name'],
                                                                self.target))
            raise

# JFrogIAM
class JFrogIAM:
    user_name = None
    user_access_key = None  # Current user_access_key, key should not be created if key already exists
    client_iam = None
    aws_user_record_set = {}  # already exists record set, as it on AWS
    aws_role_record_set = {}  # already exists record set, as it on AWS
    aws_user_access_key_list = {}  # {"AccessKey": "SecretKey"} - SecretKey is NOT NONE for new AccessKey
    user_policy_inline_templates = {"AccessToBucketUser": "user/policy/AccessToBucketUser.json.j2"}
    role_trust_policy_template = {"TrustRelationship": "role/trust_policy/TrustRelatioship.json.j2"}
    sso_profile = None
    is_gov = False
    aws_byok_kms_arn = None
    is_irsa = False
    eks_oidc_provider = None
    namespace = None
    cloud_cluster = None

    def __init__(self, user_name, s3_bucket=None, s3_bucket_path=None, user_access_key=None, creds={},
                 policy_template=None,
                 tuned_s3_policy=False,
                 deny_other_resources=False,
                 is_gov=False,
                 aws_byok_kms_arn=None,
                 is_irsa=False,
                 namespace=None,
                 eks_oidc_provider=None):
        """

        :param user_name:
        :param user_access_key: Can be None for new users / First registration
        :param s3_bucket:
        :param s3_bucket_path:
        :param creds:
        """

        self.user_name = user_name
        self.user_access_key = user_access_key
        self.s3_bucket = s3_bucket
        self.deny_other_resources = deny_other_resources
        self.tuned_s3_policy = tuned_s3_policy
        self.aws_byok_kms_arn = aws_byok_kms_arn
        self.is_irsa = is_irsa
        self.namespace = namespace

        if s3_bucket_path is None:
            self.s3_bucket_path = user_name
        else:
            self.s3_bucket_path = s3_bucket_path

        # In case of IRSA require including EKS cluster OIDC provider
        if self.is_irsa:
            self.eks_oidc_provider = eks_oidc_provider
            if self.eks_oidc_provider is None:
                raise 'eks oidc provider not defined for this cluster, cannot proceed with irsa'

        force_creds = True if creds else False
        # Set AWS Secret
        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret(creds=creds,
                                                                                                force_creds=force_creds)

        if self.sso_profile and not creds:
            boto3_session = boto3.session.Session(profile_name=f"{self.sso_profile}")
            botocore_session = boto3_session._session
            self.client_iam = boto3_session.client('iam')
            self.client_sts = boto3_session.client('sts')

        else:
            self.client_iam = boto3.client('iam', aws_access_key_id=self.aws_access_key_id,
                                           aws_secret_access_key=self.aws_secret_access_key)
            self.client_sts = boto3.client('sts', aws_access_key_id=self.aws_access_key_id,
                                           aws_secret_access_key=self.aws_secret_access_key)

        if self.user_name is not None:
            self.aws_role_record_set = self.get_role()    
            self.aws_user_record_set = self.get_user()

        if policy_template is not None:
            self.user_policy_inline_templates = policy_template

        self.is_gov = is_gov

        self.account_id = self.client_sts.get_caller_identity()["Account"]
        logging.info("Going to perform actions in AWS account " + self.account_id)

    def set(self):
        """
        Create and setup IAM user/role
        :return:
        """
        if self.is_irsa:
            # delete AWS user & access keys if customer is already deployed with role
            if self.aws_role_record_set and self.aws_user_record_set:
                try:
                    self.delete_user()
                except:
                    # Sleep was added to allow AWS to sync, there are dependencies between the entities
                    self.delete_access_keys()
                    time.sleep(2)
                    self.delete_user_policies()
                    time.sleep(2)
                    self.delete_user()
            self.create_oidc_provider()
            self.create_role()
            self.put_role_policies()
        else:
            # delete AWS role if customer is already deployed with user
            if self.aws_role_record_set and self.aws_user_record_set:
                try:
                    self.delete_role()
                except:
                    # Sleep was added to allow AWS to sync, there are dependencies between the entities
                    self.delete_role_policies()
                    time.sleep(2)
                    self.delete_role()
            self.create_user()
            self.put_user_policies()

            if self.user_access_key is None or self.user_access_key == "None":
                self.create_access_key()

        return True

    def create_oidc_provider(self):
        self.eks_oidc_provider_arn = "arn:aws:iam::{}:oidc-provider/{}".format(self.account_id, self.eks_oidc_provider)
        try:
            self.client_iam.get_open_id_connect_provider(
                OpenIDConnectProviderArn=self.eks_oidc_provider_arn
            )
            logging.info("OIDC provider already exists - " + self.eks_oidc_provider_arn)
        except self.client_iam.exceptions.NoSuchEntityException:
            logging.info("OIDC provider doesn't exist going to create") 
            response = self.client_iam.create_open_id_connect_provider(
                Url="https://" + self.eks_oidc_provider,
                ThumbprintList=["9E99A48A9960B14926BB7F3B02E22DA2B0AB7280"],
                ClientIDList=["sts.amazonaws.com"]
            )
            logging.info("OIDC provider created successfully - " + response['OpenIDConnectProviderArn'])

    def delete(self):
        """

        :return:
        """
        try:
            self.delete_user()
            self.delete_role()
        except:
            # Sleep was added to allow AWS to sync, there are dependencies between the entities
            self.delete_access_keys()
            time.sleep(2)
            self.delete_user_policies()
            self.delete_role_policies()
            time.sleep(2)
            self.delete_user()
            self.delete_role()

        return True

    def get_user(self):
        """
        Check IAM user record set
        :return:
        """
        empty_record_set = {}

        print("INFO: Getting IAM information for user [{}]".format(self.user_name))

        if self.aws_user_record_set is not None and self.aws_user_record_set != {}:
            return self.aws_user_record_set

        logging.debug("Getting information from IAM")
        try:
            aws_user_record_set = self.client_iam.get_user(UserName=self.user_name)

        except botocore.exceptions.ClientError as ClientError:
            if 'NoSuchEntity' in str(ClientError):
                logging.info("IAM user does not exists on AWS")
                return empty_record_set

        logging.debug("Response from server [aws_iam_set]: {}".format(aws_user_record_set))

        if self.user_name == aws_user_record_set['User']['UserName']:
            return aws_user_record_set

        return self.aws_user_record_set

    def get_role(self):
        """
        Check IAM role record set
        :return:
        """
        empty_record_set = {}

        print("INFO: Getting IAM information for role [{}]".format(self.user_name))

        if self.aws_role_record_set is not None and self.aws_role_record_set != {}:
            return self.aws_role_record_set

        logging.debug("Getting information from IAM")
        try:
            aws_role_record_set = self.client_iam.get_role(RoleName=self.user_name)

        except botocore.exceptions.ClientError as ClientError:
            if 'NoSuchEntity' in str(ClientError):
                logging.info("IAM role does not exists on AWS")
                return empty_record_set

        logging.debug("Response from server [aws_iam_set]: {}".format(aws_role_record_set))

        if self.user_name == aws_role_record_set['Role']['RoleName']:
            return aws_role_record_set

        return self.aws_role_record_set

    def create_user(self):
        """
        Create/update IAM user
        :return: True
        """

        logging.debug("Generate user for {}".format(self.user_name))

        if self.aws_user_record_set != {}:
            logging.info("IAM user [{}] already exists, skipping".format(self.user_name))
            return True

        logging.info("Creating IAM user as {}".format(self.user_name))

        try:
            response = self.client_iam.create_user(UserName=self.user_name)
            logging.info("Created IAM user as {} successfully".format(self.user_name))
            logging.debug("Response from server: {}".format(response))
            self.aws_user_record_set = self.get_user()

        except Exception:
            traceback.print_exc(file=sys.stdout)
            raise Exception("Oops! Cannot set IAM user {}".format(self.user_name))

        return True

    def create_role(self):
        """
        Create/update IAM role
        :return: True
        """

        logging.debug("Generate role for {}".format(self.user_name))

        logging.info("Creating IAM role for {}".format(self.user_name))

        env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates/aws'),
                          keep_trailing_newline=True)
        policy_template_keys = {
            "eks_oidc_provider_arn": self.eks_oidc_provider_arn,
            "eks_oidc_provider": self.eks_oidc_provider,
            "namespace": self.namespace,
            "service_account": self.namespace + "-artifactory"
        }
        logging.debug("policy_template_keys: " + str(policy_template_keys))
        for policy in self.role_trust_policy_template:
            policy_template = env.get_template(self.role_trust_policy_template[policy])
        policy_document = policy_template.render(policy_template_keys)
        print(policy_document)

        try:
            if self.aws_role_record_set == {}:
                response = self.client_iam.create_role(
                    RoleName=self.user_name,
                    AssumeRolePolicyDocument=policy_document,
                    Description="IAM Roles For Service Accounts For EKS"
                )
                logging.info("Created IAM role of {} successfully".format(self.user_name))
            else:
                response = self.client_iam.update_assume_role_policy(
                    RoleName=self.user_name,
                    PolicyDocument=policy_document
                )
                response = self.client_iam.update_role_description(
                    RoleName=self.user_name,
                    Description="IAM Roles For Service Accounts For EKS"
                )
                logging.info("Updated IAM role of {} successfully".format(self.user_name))
            logging.debug("Response from server: {}".format(response))
            response = self.client_iam.tag_role(
                RoleName=self.user_name,
                Tags=[
                    {"Key": "CreatedBy", "Value": "SaaS-Deployer"},
                    {"Key": "Application", "Value": "Artifactory"},
                    {"Key": "artifactory_bucket_name", "Value": self.s3_bucket},
                    {"Key": "eks_oidc_provider_arn", "Value": self.eks_oidc_provider_arn}
                ]
            )
            self.aws_role_record_set = self.get_role()

        except Exception:
            traceback.print_exc(file=sys.stdout)
            raise Exception("Oops! Cannot set IAM role {}".format(self.user_name))

        return True

    def delete_user(self):
        """
        Delete IAM user record set
        :return:
        """

        logging.info("Deleting IAM user {}".format(self.user_name))

        if self.aws_user_record_set == {} or self.aws_user_record_set is None:
            logging.debug("aws_user_record_set: {}".format(self.aws_user_record_set))
            logging.info("Nothing to delete, IAM [{}] does not exist".format(self.user_name))
            return True

        try:
            response = self.client_iam.delete_user(UserName=self.user_name)
            # Clear AWS local record
            self.aws_user_record_set = {}
            logging.info("Delete IAM user for {} successfully".format(self.user_name, response))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception as e:
            if "must delete policies first" not in str(e):
                logging.error("Oops! Cannot delete IAM user for {}".format(self.user_name))
                traceback.print_exc(file=sys.stdout)
            raise
    
    def delete_role(self):
        """
        Delete IAM role record set
        :return:
        """

        logging.info("Deleting IAM role {}".format(self.user_name))

        if self.aws_role_record_set == {} or self.aws_role_record_set is None:
            logging.debug("aws_role_record_set: {}".format(self.aws_role_record_set))
            logging.info("Nothing to delete, IAM [{}] does not exist".format(self.user_name))
            return True

        try:
            response = self.client_iam.delete_role(RoleName=self.user_name)
            # Clear AWS local record
            self.aws_role_record_set = {}
            logging.info("Delete IAM role for {} successfully".format(self.user_name, response))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception as e:
            if "must delete policies first" not in str(e):
                logging.error("Oops! Cannot delete IAM role for {}".format(self.user_name))
                traceback.print_exc(file=sys.stdout)
            raise

    def create_access_key(self):
        """
        Create AccessKey
        :return: dict{AccessKey, SecretKey}
        """

        logging.info("Creating IAM user AccessKey for {}".format(self.user_name))

        self.aws_user_access_key_list = self.list_access_keys()

        # check if Limit is not Exceeded (max 2 access keys)
        if len(self.aws_user_access_key_list) == 2 or len(self.aws_user_access_key_list) > 2:
            raise Exception("AccessKey LimitExceeded Exception!")

        try:
            response = self.client_iam.create_access_key(UserName=self.user_name)
            logging.debug("Response from server: {}".format(response))

            access_key_id = response['AccessKey']['AccessKeyId'] or None
            secret_access_key = response['AccessKey']['SecretAccessKey'] or None

            if access_key_id is None or secret_access_key is None:
                raise Exception("User AccessKey cannot be created")

            print("INFO: Created IAM user AccessKey for {} successfully".format(self.user_name))
            self.aws_user_access_key_list[access_key_id] = secret_access_key

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

        logging.info("Getting IAM user AccessKeys for user [{}]".format(self.user_name))

        try:
            response = self.client_iam.list_access_keys(UserName=self.user_name)
            all_keys = {}
            for key in response['AccessKeyMetadata']:
                all_keys[key['AccessKeyId']] = key['Status']

            logging.debug("Response from server: {}".format(response))
            logging.debug("Getting IAM user AccessKeys for [{}] successfully".format(self.user_name))
        except self.client_iam.exceptions.NoSuchEntityException:
            return {}
        except Exception:
            logging.error("Oops! Cannot fetch user AccessKeys for {}".format(self.user_name))
            traceback.print_exc(file=sys.stdout)
            raise Exception("User AccessKey cannot be fetched")

        logging.debug("all_keys {}".format(all_keys))
        return all_keys

    def delete_access_keys(self):
        """
        Delete IAM user access keys
        :return:
        """

        logging.info("Deleting IAM user access keys for {}".format(self.user_name))

        keys = self.list_access_keys()
        logging.debug("keys list to delete: {}".format(keys))
        for key in keys:
            try:
                response = self.client_iam.delete_access_key(UserName=self.user_name, AccessKeyId=key)
                logging.info("Delete IAM user access key {} for {} successfully".format(key, self.user_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                traceback.print_exc(file=sys.stdout)
                raise ("Oops! Cannot delete IAM user access key {} for {}".format(key, self.user_name))

        return True

    def list_user_policies(self):
        try:
            response = self.client_iam.list_user_policies(UserName=self.user_name)
            if len(response['PolicyNames']) > 0:
                all_policies = []
                for policy in response['PolicyNames']:
                    all_policies.append(policy)
                return all_policies
        except self.client_iam.exceptions.NoSuchEntityException:
            return []
        except:
            traceback.print_exc(file=sys.stdout)
            raise Exception("User policies cannot be fetched")

    def list_role_policies(self):
        try:
            response = self.client_iam.list_role_policies(RoleName=self.user_name)
            if len(response['PolicyNames']) > 0:
                all_policies = []
                for policy in response['PolicyNames']:
                    all_policies.append(policy)
                return all_policies
        except self.client_iam.exceptions.NoSuchEntityException:
            return []
        except:
            traceback.print_exc(file=sys.stdout)
            raise Exception("Role policies cannot be fetched")

    def list_users(self, prefix=None):
        try:
            print("Fetching all IAM users from AWS...")
            paginator = self.client_iam.get_paginator('list_users')
            all_users_list = []
            for response in paginator.paginate():
                users_list = []
                for user in response['Users']:
                    username = user['UserName']
                    if prefix is not None:
                        if username.startswith(prefix):
                            sys.stdout.write("Number of IAMs: [%d]   \r" % (len(all_users_list)))
                            sys.stdout.flush()
                            users_list.append(username)
                all_users_list.extend(users_list)
            print("Found [{}] IAM users".format(len(all_users_list)))
            return all_users_list
        except:
            traceback.print_exc(file=sys.stdout)
            raise Exception("User policies cannot be fetched")

    def put_user_policies(self):
        """
        Create/update IAM user policy
        :return: True
        """
        if self.s3_bucket is None:
            raise ValueError("s3_bucket is mandatory for put_user_policies()")

        logging.debug("Generate policies for {}".format(self.user_name))
        logging.info("Creating IAM user policy for {}".format(self.user_name))

        env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates/aws'),
                          keep_trailing_newline=True)
        aws_arn_prefix= 'arn:aws-us-gov' if self.is_gov else 'arn:aws'
        policy_template_keys = {"s3_bucket": self.s3_bucket, "s3_bucket_path": self.s3_bucket_path,
                                "tuned_s3_policy": self.tuned_s3_policy,
                                "aws_arn_prefix": aws_arn_prefix,
                                "aws_byok_kms_arn": self.aws_byok_kms_arn}
        for policy in self.user_policy_inline_templates:
            policy_name = "{}_{}".format(policy, self.user_name)
            policy_template = env.get_template(self.user_policy_inline_templates[policy])

            logging.info("Creating IAM user policy name [{}] based on {} template".format(
                policy_name, policy_template))

            policy_document = policy_template.render(policy_template_keys)
            try:
                response = self.client_iam.put_user_policy(UserName=self.user_name, PolicyName=policy_name,
                                                           PolicyDocument=policy_document)
                logging.info("Created IAM user policy as {} successfully".format(policy_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                logging.error("Oops! Cannot set IAM user policy {}{} ".format(policy_name,policy_document))
                traceback.print_exc(file=sys.stdout)

        return True

    def put_role_policies(self):
        """
        Create/update IAM role policy
        :return: True
        """
        if self.s3_bucket is None:
            raise ValueError("s3_bucket is mandatory for put_role_policies()")

        logging.debug("Generate policies for {}".format(self.user_name))
        logging.info("Creating IAM role policy for {}".format(self.user_name))

        env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates/aws'),
                          keep_trailing_newline=True)
        aws_arn_prefix= 'arn:aws-us-gov' if self.is_gov else 'arn:aws'
        policy_template_keys = {"s3_bucket": self.s3_bucket, "s3_bucket_path": self.s3_bucket_path,
                                "tuned_s3_policy": self.tuned_s3_policy,
                                "aws_arn_prefix": aws_arn_prefix,
                                "aws_byok_kms_arn": self.aws_byok_kms_arn}
        for policy in self.user_policy_inline_templates:
            policy_name = "{}_{}".format(policy, self.user_name)
            policy_template = env.get_template(self.user_policy_inline_templates[policy])

            logging.info("Creating IAM role policy name [{}] based on {} template".format(
                policy_name, policy_template))

            policy_document = policy_template.render(policy_template_keys)
            try:
                response = self.client_iam.put_role_policy(RoleName=self.user_name, PolicyName=policy_name,
                                                           PolicyDocument=policy_document)
                logging.info("Created IAM role policy as {} successfully".format(policy_name))
                logging.debug("Response from server: {}".format(response))

            except Exception:
                logging.error("Oops! Cannot set IAM role policy {}{} ".format(policy_name,policy_document))
                traceback.print_exc(file=sys.stdout)

        return True

    def delete_user_policies(self):
        """
        Delete IAM user record set
        :return:
        """

        logging.info("Deleting IAM user policies for {}".format(self.user_name))

        policies = self.list_user_policies()
        logging.debug("policies list to delete: {}".format(policies))
        for policy in policies:
            try:
                response = self.client_iam.delete_user_policy(UserName=self.user_name, PolicyName=policy)
                logging.info("Delete IAM user policy {} for {} successfully".format(policy, self.user_name))
                logging.debug("Response from server: {}".format(response))
                return True

            except Exception:
                traceback.print_exc(file=sys.stdout)
                raise ("Oops! Cannot delete IAM user policy {} for {}".format(policy, self.user_name))

        return True

    def delete_role_policies(self):
        """
        Delete IAM role record set
        :return:
        """

        logging.info("Deleting IAM role policies for {}".format(self.user_name))

        policies = self.list_role_policies()
        logging.debug("policies list to delete: {}".format(policies))
        for policy in policies:
            try:
                response = self.client_iam.delete_role_policy(RoleName=self.user_name, PolicyName=policy)
                logging.info("Delete IAM role policy {} for {} successfully".format(policy, self.user_name))
                logging.debug("Response from server: {}".format(response))
                return True

            except Exception:
                traceback.print_exc(file=sys.stdout)
                raise ("Oops! Cannot delete IAM role policy {} for {}".format(policy, self.user_name))

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
        print("== JFrogIAM Info =======================================================================")
        self.print_info("User Name", self.user_name)
        self.print_info("AWS User Record Set", self.aws_user_record_set)
        self.print_info("AWS User Access Key", self.aws_user_access_key_list)
        print("=============================================================================================")


# JFrogCloudFront
# https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html
class JFrogCloudFront:
    oai_id = None
    distribution_inline_templates = {"CreateDistribution": "cloudfront/distribution/CreateDistribution.json.j2"}
    # Default OAI Caller Reference usually used when shared between CDNs on shared s3 bucket
    oai_cloud_cr = "global_oai_for_eplus_customers"
    oai_cloud_comment = "Global OAI for Eplus customers"  # Default comment will appear in AWS Origin Access Identity UI
    # create_distribution
    distribution_domain_name = None
    distribution_id = None
    distribution_etag = None
    s3_bucket = None
    logs_s3_bucket = None
    alias = None
    sso_profile = None
    iam_certificate_id = None  # The ID for the SSL server_certificate as it appears on AWS systems

    # Readiness waiter defaults
    delay = 5
    max_attempts = 120

    def __init__(self, cloud_id, s3_bucket=None, logs_s3_bucket=None, alias=None,
                 iam_certificate_id=None, distribution_id=None, creds={}, cache_policy=False):
        """

        :param cloud_id:
        :param s3_bucket:
        :param logs_s3_bucket:
        :param distribution_id:
        :param creds:
        :param cache_policy:
        """

        # Mandatory for creation
        self.cloud_id = cloud_id
        self.s3_bucket = s3_bucket
        self.logs_s3_bucket = logs_s3_bucket
        self.cache_policy = cache_policy

        # Mandatory for deletion
        if distribution_id is not None:
            self.distribution_id = distribution_id

        # Mandatory for cname update
        self.alias = alias
        self.iam_certificate_id = iam_certificate_id

        # Set AWS Secret
        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret(creds)

        if self.sso_profile:
            boto3_session = boto3.session.Session(profile_name=f"{self.sso_profile}")
            botocore_session = boto3_session._session
            self.client_cdn = boto3_session.client('cloudfront')
        else:
            self.client_cdn = boto3.client('cloudfront', aws_access_key_id=self.aws_access_key_id,
                                           aws_secret_access_key=self.aws_secret_access_key)

    def set(self):
        """
        Create Regional CloudFront distribution AND OriginAccessIdentity
        :return:
        """
        self.create_oai()
        self.create_distribution()
        # TODO: Create bucket policy
        # self.put_bucket_policies()
        # TODO: Create logs bucket
        # self.create_logs_bucket()

        return True

    def delete(self):
        """
        Delete customer CloudFront distribution AND OriginAccessIdentity when using shared OAI
        :return:
        """
        try:
            self.delete_distribution()
        except:
            traceback.print_exc(file=sys.stdout)
            logging.error("Oops! Cannot delete CloudFront distribution for {}".format(self.cloud_id))
            raise

        return True

    def create_oai(self):
        """
        Create global Origin Access Identity
        :return: True
        """

        # TODO: Check if already exists before creating
        # logging.debug("Checking if OAI exist for {}".format(self.cloud_id))
        # For start we will rely on unique CallerReference defence
        # logging.info("CloudFront OAI [{}] already exists, skipping".format(self.oai_cloud_id))

        logging.info("Creating Origin Access Identity for {}".format(self.cloud_id))

        try:
            response = self.client_cdn.create_cloud_front_origin_access_identity(CloudFrontOriginAccessIdentityConfig={
                'CallerReference': self.oai_cloud_cr,
                'Comment': self.oai_cloud_comment})
            self.oai_id = response["CloudFrontOriginAccessIdentity"]["Id"]
            logging.debug("ID from response: {}".format(self.oai_id))
            logging.debug("API response for create_oai: {}".format(response))
            logging.info("Created CloudFront Origin Access Identity for [{}] successfully"
                         "".format(self.cloud_id))

        except Exception:
            traceback.print_exc(file=sys.stdout)
            logging.error("Oops! Cannot create CloudFront Origin Access Identity for {}".format(self.cloud_id))
            raise

        return True

    def create_distribution(self):
        """
        Create CloudFront distribution for customer
        :return: True
        """

        # Readiness waiter params
        delay = 5
        max_attempts = 120

        if self.s3_bucket is None:
            raise ValueError("s3_bucket is mandatory for create_distribution()")

        if self.logs_s3_bucket is None:
            raise ValueError("logs_s3_bucket is mandatory for create_distribution()")

        logging.info("Creating CloudFront distribution for {}".format(self.cloud_id))

        env = Environment(loader=PackageLoader('jfrogdevopstools', 'templates/aws'),
                          keep_trailing_newline=True)

        configuration = {"origin_access_identity": "origin-access-identity/cloudfront/{}".format(self.oai_id),
                         "cloud_id": self.cloud_id,
                         "s3_bucket": self.s3_bucket,
                         "logs_s3_bucket": self.logs_s3_bucket,
                         "cache_policy": self.cache_policy}

        for config in self.distribution_inline_templates:
            config_name = "{}_{}".format(config, self.cloud_id)
            config_template = env.get_template(self.distribution_inline_templates[config])

            logging.info("Creating CloudFront distribution for [{}] based on {} template"
                         "".format(config_name, config_template))
            try:
                distribution_config_payload_file = config_template.render(configuration)
                distributionconfig = eval(distribution_config_payload_file)
                logging.debug("Created and rendered distribution payload {}".format(distributionconfig))

            except Exception:
                logging.error("Failed to render CloudFront distribution configuration file")
                raise

            try:
                response = self.client_cdn.create_distribution(DistributionConfig=distributionconfig)
                self.distribution_domain_name = response["Distribution"]["DomainName"]
                self.distribution_id = response["Distribution"]["Id"]
                self.distribution_etag = response["ETag"]
                logging.debug("API response for create_distribution: {}".format(response))
                logging.info("Created CloudFront distribution {} successfully".format(self.distribution_domain_name))
                # Waiter
                logging.info("Waiting for CloudFront distribution to be ready. This may take a few minutes...")
                self.waiter_readiness(delay, max_attempts)
                logging.info("CloudFront distribution is ready. Continuing...")

            except:
                if "distribution. Already exists" in str(sys.exc_info()):
                    std_out = str(sys.exc_info()).split(" ")
                    existing_distribution = std_out[-5].split("'")[0]
                    logging.info("CloudFront distribution [{}] already exists".format(existing_distribution))
                    # Assuming something bad happend to the existing properties if we are here... Re updating values.
                    logging.info(
                        "Fetching values for existing CloudFront distribution {}".format(existing_distribution))
                    response = self.client_cdn.get_distribution(Id=existing_distribution)
                    self.distribution_domain_name = response["Distribution"]["DomainName"]
                    self.distribution_id = response["Distribution"]["Id"]
                    self.distribution_etag = response["ETag"]
                else:
                    logging.error("Oops! Cannot create CloudFront distribution {}".format(config_name))
                    traceback.print_exc(file=sys.stdout)
                    raise

        return True

    def delete_distribution(self):
        """
        Delete CloudFront distribution for customer
        :return:
        """

        if self.distribution_id is None:
            raise Exception("class distribution_id is mandatory")

        eTag = ""
        disabledConf = ""
        distribution = self.distribution_id

        timeout_mins = 30
        sleep_secs = 10
        wait_until = datetime.now() + timedelta(minutes=timeout_mins)
        notFinished = True

        logging.debug("distributions to delete: {}".format(distribution))

        logging.info("Disabling CloudFront distribution for {}".format(self.cloud_id))

        # Getting the distribution Etag, need to get it twice before and after deploy
        response = self.client_cdn.get_distribution(Id=distribution)
        eTag = response['ETag']
        distributionconfig = response['Distribution']['DistributionConfig']
        distributionconfig['Enabled'] = False

        # Disabling the distribution before delete
        response = self.client_cdn.update_distribution(DistributionConfig=distributionconfig,
                                                       Id=distribution, IfMatch=eTag)

        # Wait for distribution to disable...
        logging.info(
            "Waiting for distribution disable. This may take a while...Timeout is {} mins.".format(timeout_mins))
        while (notFinished):
            # Checking if timeout reached
            if wait_until < datetime.now():
                logging.error("Distribution took too long to disable. Exiting")
                raise Exception("Distribution took too long to disable. Exiting")

            response = self.client_cdn.get_distribution(Id=distribution)
            if (response['Distribution']['DistributionConfig']['Enabled'] == False and response['Distribution'][
                'Status'] == 'Deployed'):
                eTag = response['ETag']
                notFinished = False

            logging.info("CloudFront is not disabeld yet. Sleeping {} seconds...".format(sleep_secs))
            time.sleep(sleep_secs)

        logging.info("Deleting CloudFront distribution for {}...".format(self.cloud_id))

        try:
            response = self.client_cdn.delete_distribution(Id=distribution, IfMatch=eTag)
            logging.info(
                "Done, deleted CloudFront distribution {} for {} successfully".format(distribution, self.cloud_id))
            logging.debug("Response from server: {}".format(response))
            return True

        except Exception:
            traceback.print_exc(file=sys.stdout)
            raise ("Oops! Cannot delete CloudFront distribution {} for {}".format(distribution, self.cloud_id))

        return True

    def create_cname(self):
        """
        Create CNAME/Alias in CloudFront distribution
        :return:
        """

        if self.distribution_id is None:
            raise Exception("class distribution_id is mandatory")

        eTag = ""
        distribution = self.distribution_id

        logging.info("Creating CloudFront cname for {}".format(self.cloud_id))

        try:
            # Getting the distribution Etag, need to get it before the update
            response = self.client_cdn.get_distribution(Id=distribution)
            eTag = response['ETag']
            distributionconfig = response['Distribution']['DistributionConfig']
            distributionconfig['Aliases'] = {'Quantity': 1, 'Items': [self.alias]}
            distributionconfig['ViewerCertificate'] = {'IAMCertificateId': self.iam_certificate_id,
                                                       'SSLSupportMethod': 'sni-only',
                                                       'MinimumProtocolVersion': 'TLSv1.1_2016'}
            response = self.client_cdn.update_distribution(DistributionConfig=distributionconfig, Id=distribution,
                                                           IfMatch=eTag)

        except Exception:
            logging.error("Failed to create CloudFront CNAME")
            raise

        # Waiter
        logging.info("Waiting for CloudFront to deploy the changes. This may take a few minutes...")
        self.waiter_readiness(self.delay, self.max_attempts)
        logging.info("CloudFront distribution is ready. Continuing...")

    def delete_cname(self):
        """
        Delete CNAME/Alias in CloudFront distribution
        :return:
        """

        if self.distribution_id is None:
            raise Exception("class distribution_id is mandatory")

        eTag = ""
        distribution = self.distribution_id

        logging.info("Deleting CloudFront cname for {}".format(self.cloud_id))

        try:
            # Getting the distribution Etag, need to get it before the update
            response = self.client_cdn.get_distribution(Id=distribution)
            eTag = response['ETag']
            distributionconfig = response['Distribution']['DistributionConfig']
            distributionconfig['Aliases'] = {'Quantity': 0}
            distributionconfig['ViewerCertificate'] = {'CloudFrontDefaultCertificate': True,
                                                       'MinimumProtocolVersion': 'TLSv1'}
            response = self.client_cdn.update_distribution(DistributionConfig=distributionconfig, Id=distribution,
                                                           IfMatch=eTag)

        except Exception:
            logging.error("Failed to delete CloudFront CNAME")
            raise

        # Waiter
        logging.info("Waiting for CloudFront to deploy the changes. This may take a few minutes...")
        self.waiter_readiness(self.delay, self.max_attempts)
        logging.info("CloudFront distribution is ready. Continuing...")

    def validate_cname(self):
        """
        Validate CNAME/Alias in CloudFront distribution
        :return:
        """

        if self.distribution_id is None:
            raise Exception("class distribution_id is mandatory")

        distribution = self.distribution_id

        logging.info("Validating CloudFront cname for {}".format(self.cloud_id))

        try:
            response = self.client_cdn.get_distribution(Id=distribution)
            is_cdn_cname_exist = response['Distribution']['DistributionConfig']['Aliases']['Quantity']
            if is_cdn_cname_exist:
                self.existing_cdn_cname = response['Distribution']['DistributionConfig']['Aliases']['Items']
                is_cdn_cname_exist = True

                if self.iam_certificate_id is not None:
                    existing_iam_certificate_id = response['Distribution']['DistributionConfig']['ViewerCertificate'][
                        'IAMCertificateId']
                    if self.iam_certificate_id.lower() != existing_iam_certificate_id.lower():
                        logging.info("Certificate IDs does not match. Deploying new CloudFront certificate...")
                        logging.debug(
                            "Old Certificate id {} will be replaced with the new id {}".format(self.iam_certificate_id,
                                                                                               existing_iam_certificate_id))
                        is_cdn_cname_exist = False

            return is_cdn_cname_exist

        except Exception:
            logging.error("Failed to validate CloudFront CNAME")
            raise

    def waiter_readiness(self, delay, max_attempts):
        """
        Wait for CloudFront distribution to be deployed
        :return:
        """
        waiter = self.client_cdn.get_waiter('distribution_deployed')

        waiter.wait(Id=self.distribution_id, WaiterConfig={'Delay': delay,
                                                           'MaxAttempts': max_attempts})

    @staticmethod
    def print_info(l, r):
        """
        Print using key=value format
        :param l:
        :param r:
        :return:
        """
        print('{:.<40}'.format(l) + str(r))

    def info(self):
        """
        Print the class metadata
        :return: True
        """
        print("== JFrogCloudFront Info =======================================================================")
        self.print_info("Customer Name", self.cloud_id)
        self.print_info("CloudFront Origin Access Identity", self.oai_id)
        self.print_info("CloudFront Distribution DomainName", self.distribution_domain_name)
        self.print_info("CloudFront Distribution Id", self.distribution_id)
        self.print_info("CloudFront ETag", self.distribution_etag)
        self.print_info("CloudFront Distribution CNAME", self.alias)
        self.print_info("CloudFront Certificate Id", self.iam_certificate_id)
        print("=============================================================================================")


class JFrogPrivateLink:
    # Consumer creation
    consumer_id = None
    region_name = None
    privatelink_endpoint_service_id = None
    privatelink_consumer_endpoint_id = None

    def __init__(self, region_name, consumer_id, privatelink_consumer_endpoint_id, privatelink_endpoint_service_id,
                 creds={}):
        """
        :param region_name:
        :param consumer_id:
        :param privatelink_consumer_endpoint_id:
        :param privatelink_endpoint_service_id:
        :param creds:
        """

        # Consumer creation / deletion
        self.consumer_id = consumer_id
        self.region_name = region_name
        self.privatelink_consumer_endpoint_id = privatelink_consumer_endpoint_id
        self.privatelink_endpoint_service_id = privatelink_endpoint_service_id

        # Set AWS Secret
        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret(creds)

        self.client_ec2 = boto3.client('ec2', region_name=self.region_name, aws_access_key_id=self.aws_access_key_id,
                                       aws_secret_access_key=self.aws_secret_access_key)

    def set_consumer(self):
        """
        Create consumer PrivateLink connection to endpoint service
        :return:
        """
        self.manage_connection_request(action="accept")
        self.validate_connection(desired_state="available")

        return True

    def delete_consumer(self):
        """
        Delete consumer PrivateLink connection to endpoint service
        :return:
        """
        self.manage_connection_request(action="reject")
        self.validate_connection(desired_state="rejected")

        return True

    def manage_connection_request(self, action):
        """
        Manage consumer connection request for PrivateLink
        :return:
        """
        logging.info("{} PrivateLink consumer VPCE: [{}] connection for {}".format(
            action, self.privatelink_consumer_endpoint_id, self.consumer_id))

        try:
            response = eval(
                "self.client_ec2.{}_vpc_endpoint_connections(ServiceId='{}',VpcEndpointIds=['{}'])".format(action,
                                                                                                           self.privatelink_endpoint_service_id,
                                                                                                           self.privatelink_consumer_endpoint_id))
            logging.debug("API {}_vpc_endpoint response from server: {}".format(action, response))

            if response["Unsuccessful"]:
                error_message = response["Unsuccessful"][0]["Error"]["Message"]
                if "not exist" in error_message.lower() and action == "reject":
                    logging.info("PrivateLink consumer VPCE: [{}] connection not found for {}, "
                                 "assuming it is already deleted by the consumer.".format(
                        self.privatelink_consumer_endpoint_id, self.consumer_id))
                    return
                raise RuntimeError("Error occurred while {} PrivateLink connection request for [{}]\n"
                                   "Error message: {}".format(action, self.privatelink_consumer_endpoint_id,
                                                              error_message))

        except Exception:
            logging.error("Failed to {} PrivateLink connection request".format(action))
            raise

    def validate_connection(self, desired_state, max_depth=60, recur_depth=0):

        sleep_secs = 10
        response = self.client_ec2.describe_vpc_endpoint_connections(Filters=[{
            "Name": "service-id", "Values": [self.privatelink_endpoint_service_id],
            "Name": "vpc-endpoint-id", "Values": [self.privatelink_consumer_endpoint_id]}])

        if not response["VpcEndpointConnections"]:
            logging.info("Cannot validate connection status for PrivateLink consumer VPCE: [{}], "
                         "assuming it is already deleted by consumer.".format(self.privatelink_consumer_endpoint_id))
            return
        current_state = response["VpcEndpointConnections"][0]["VpcEndpointState"].lower()

        if current_state == desired_state:
            logging.info("PrivateLink VPCE: [{}] connection is {} for {}...".format(
                self.privatelink_consumer_endpoint_id, desired_state, self.consumer_id))
            return

        if recur_depth >= max_depth:
            raise Exception("PrivateLink connection took too long to be {}. Exiting".format(desired_state))

        logging.info("PrivateLink connection is not {} yet. Sleeping {} seconds...".format(desired_state, sleep_secs))
        time.sleep(sleep_secs)
        return self.validate_connection(desired_state, max_depth, recur_depth + 1)

    @staticmethod
    def print_info(l, r):
        """
        Print using key=value format
        :param l:
        :param r:
        :return:
        """
        print('{:.<40}'.format(l) + str(r))

    def info(self):
        """
        Print the class metadata
        :return: True
        """
        print("== JFrogPrivateLink Info =======================================================================")
        self.print_info("Consumer Name", self.consumer_id)
        self.print_info("Consumer AWS region name", self.region_name)
        self.print_info("Consumer Endpoint ID", self.privatelink_consumer_endpoint_id)
        self.print_info("Provider Endpoint Service ID", self.privatelink_endpoint_service_id)
        print("==============================================================================================")


class JFrogAWSS3:
    s3 = None
    boto3_session = None
    region = None

    def __init__(self, region_name=None):
        self.region = region_name
        self.s3 = self.get_s3(region_name)

    def get_s3(self, region=None):
        """Get a Boto 3 S3 resource with a specific Region or with your default Region."""
        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret({})
        self.boto3_session = boto3.session.Session(profile_name=f"{self.sso_profile}")
        s3_resource = self.boto3_session.resource('s3')
        if not region or s3_resource.meta.client.meta.region_name == region:
            return s3_resource
        else:
            return self.boto3_session.resource('s3', region_name=region)

    def create_bucket(self, name, block_public_access=True):
        """
        Create an Amazon S3 bucket with the specified name and in the specified Region.

        Usage is shown in usage_demo at the end of this module.

        :param name: The name of the bucket to create. This name must be globally unique
                    and must adhere to bucket naming requirements.
        :param region: The Region in which to create the bucket. If this is not specified,
                    the Region configured in your shared credentials is used. If no
                    Region is configured, 'us-east-1' is used.
        :return: The newly created bucket.
        """
        region = self.region
        if region == "us-east-1":  # https://github.com/boto/boto3/issues/125 strange AWS boto3 behavior
            region = None
        try:
            if region:
                bucket = self.s3.create_bucket(
                    Bucket=name,
                    CreateBucketConfiguration={
                        'LocationConstraint': region
                    }
                )
            else:
                bucket = self.s3.create_bucket(Bucket=name)

            bucket.wait_until_exists()

            logging.info("Created bucket '%s' in region=%s", bucket.name,
                         self.s3.meta.client.meta.region_name)
            if block_public_access:
                logging.info("Adding block public access for bucket '%s'", bucket.name)
                self.boto3_session.client('s3').put_public_access_block(
                    Bucket=bucket.name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    },
                )
        except ClientError as error:
            logging.exception("Couldn't create bucket named '%s' in region=%s.",
                              name, region)
            if error.response['Error']['Code'] == 'IllegalLocationConstraintException':
                logging.error("When the session Region is anything other than us-east-1, "
                              "you must specify a LocationConstraint that matches the "
                              "session Region. The current session Region is %s and the "
                              "LocationConstraint Region is %s.",
                              self.s3.meta.client.meta.region_name, region)
            raise error
        else:
            return bucket

    def bucket_exists(self, bucket_name):
        """
        Determine whether a bucket with the specified name exists.

        Usage is shown in usage_demo at the end of this module.

        :param bucket_name: The name of the bucket to check.
        :return: True when the bucket exists; otherwise, False.
        """
        try:
            self.s3.meta.client.head_bucket(Bucket=bucket_name)
            logging.info("Bucket %s exists.", bucket_name)
            exists = True
        except ClientError:
            logging.warning("Bucket %s doesn't exist or you don't have access to it.",
                            bucket_name)
            exists = False
        return exists

    def get_buckets(self):
        """
        Get the buckets in all Regions for the current account.

        Usage is shown in usage_demo at the end of this module.

        :return: The list of buckets.
        """
        try:
            buckets = list(self.s3.buckets.all())
            logging.info("Got buckets: %s.", buckets)
        except ClientError:
            logging.exception("Couldn't get buckets.")
            raise
        else:
            return buckets


class MetricsToCloudwatch:
    vpcesvc = None
    value = None
    vpclist = []
    aws_region = None
    aws_object = None
    sso_profile = None
    boto3_session = None

    def __init__(self, aws_region, aws_object=None, creds=None):
        self.aws_region = aws_region
        self.aws_object = aws_object
        self.aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
        self.aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']

        (self.aws_access_key_id, self.aws_secret_access_key, self.sso_profile) = set_aws_secret(creds)

        if self.sso_profile:
            self.boto3_session = boto3.session.Session(profile_name=f"{self.sso_profile}")
        else:
            # Create Boto3 session
            self.boto3_session = boto3.session.Session(aws_access_key_id=self.aws_access_key_id,
                                                       aws_secret_access_key=self.aws_secret_access_key,
                                                       region_name=self.aws_region)

    # Need to creat a generic function that retrieves data on any service from AWS api and calls the "create_generic_metric" function.
    def get_generic_data(self):
        logging.info("Getting data on", self.aws_object)

    def get_vpce_data(self):
        client_ec2 = self.boto3_session.client('ec2')
        try:
            endpoint_connections_response = client_ec2.describe_vpc_endpoint_connections()
            endpoint_services_response = client_ec2.describe_vpc_endpoint_services()
        except Exception as e:
            logging.error("Failed to get data error:" + str(e))
            raise e

        for endpoint in endpoint_services_response["ServiceDetails"]:
            # Filtering the service endpoint from all endpoints
            vpce_name = endpoint["BaseEndpointDnsNames"][0].split(".")
            if "vpce-svc" in vpce_name[0] and endpoint["Owner"] != "amazon":
                self.vpclist.append(endpoint)
                for az in endpoint["AvailabilityZones"]:
                    self.create_generic_metric(namespace='VPCEndpointService',
                                               metric_name='PrivateLinkAvailabilityZones',
                                               service_name='VPCEndpointID', service_id=endpoint["ServiceId"],
                                               dimension_name='AvailabilityZone', dimension_value=az, metric_value=1)
            else:
                continue
        for self.vpcesvc in endpoint_connections_response["VpcEndpointConnections"]:
            for vpc in self.vpclist:
                if self.vpcesvc["ServiceId"] == vpc["ServiceId"]:
                    VpcEndpointState = self.vpcesvc["VpcEndpointState"]
                    self.value = (0, 1)[VpcEndpointState == "available"]
                    self.create_generic_metric(namespace='VPCEndpointService', metric_name='PrivateLinkServiceStatus',
                                               service_name='VPCEndpointID', service_id=self.vpcesvc["ServiceId"],
                                               dimension_name='VPCEndpointName', dimension_value=vpc["ServiceName"],
                                               metric_value=self.value)
                    return self.vpcesvc, self.value, vpc
        return {}

    def create_generic_metric(self, namespace, metric_name, service_name, service_id, dimension_name, dimension_value,
                              metric_value):
        client_cloudwatch = self.boto3_session.client('cloudwatch')
        logging.info("Creating {} metric for {}".format(metric_name, service_id))
        try:
            client_cloudwatch.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {
                        'MetricName': metric_name,
                        'Dimensions': [
                            {
                                'Name': service_name,
                                'Value': service_id
                            },
                            {
                                'Name': dimension_name,
                                'Value': dimension_value
                            }
                        ],
                        'Value': metric_value
                    }
                ]
            )
        except Exception as e:
            logging.error("Failed to create metric error:" + str(e))
            raise e


def get_first_value(*args):
    for arg in args:
        if arg:
            return arg

    return None


def set_aws_secret(creds=None, force_creds=False):
    # Export AWS_SSO_PROFILE_NAME = profile name. 'cat ~/.aws/config' -> [profile XXXX] for example.
    sso_profile = os.environ.get('AWS_SSO_PROFILE_NAME', None)
    if sso_profile and not force_creds:
        logging.debug(f"Using SSO_PROFILE as the credentials for aws")
        return (None, None, sso_profile)

    else:
        if creds is None:
            creds = {}

        aws_access_key_id = get_first_value(creds.get('aws_access_key_id', None),
                                            os.environ.get('AWS_ACCESS_KEY_ID', None))
        aws_secret_access_key = get_first_value(creds.get('aws_secret_access_key', None),
                                                os.environ.get('AWS_SECRET_ACCESS_KEY', None))
        logging.debug("Using AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY as the credentials for aws")
        if not aws_access_key_id:
            raise ValueError('AWS_ACCESS_KEY_ID is empty.')

        if not aws_secret_access_key:
            raise ValueError('AWS_SECRET_ACCESS_KEY is empty.')

        return (aws_access_key_id, aws_secret_access_key, None)


def get_account_id(creds={}, region=None):
    """
    Get account id
    :return:
    """

    (aws_access_key_id, aws_secret_access_key, sso_profile) = set_aws_secret(creds)
    if sso_profile:
        boto3_session = boto3.session.Session(profile_name=f"{sso_profile}")
        botocore_session = boto3_session._session
        sts_client = boto3_session.client('sts')
    else:
        sts_client = boto3.client('sts',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

    account_id = sts_client.get_caller_identity()["Account"]
    return account_id


def get_activated_regions(creds={}):
    """
    List all activated regions in account
    :return: list of regions
    """

    (aws_access_key_id, aws_secret_access_key, sso_profile) = set_aws_secret(creds)
    if sso_profile:
        boto3_session = boto3.session.Session(profile_name=f"{sso_profile}")
        botocore_session = boto3_session._session
        ec2_client = boto3_session.client('route53')
    else:
        ec2_client = boto3.client('ec2',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)

    regions = [region['RegionName'] for region in ec2_client.describe_regions(AllRegions=False)['Regions']]

    return regions


def get_current_region(creds={}):
    """

    :return:
    """
    boto3_session = boto3.session.Session()
    current_region = boto3_session.region_name

    return current_region


def get_aws_cidr(service=None):
    "Getting AWS ip-ranges"

    print("Getting AWS ip-ranges")

    aws_cidr_list = []
    aws_cidr_list_ipv6 = []
    aws_cidr_dict = {'ipv4': aws_cidr_list, 'ipv6': aws_cidr_list_ipv6}
    response = requests.get(AWS_IP_RANGE_URL)
    result = response.content.decode('ascii')
    parsed_json = json.loads(result)

    try:
        # Print status and body of response
        logging.debug("Response Status:" + str(response.status_code))
        logging.debug("Response Body:" + response.content)

    except Exception:
        print("Oops!  Cannot get JSON data")
        traceback.print_exc(file=sys.stdout)

    # IPv4
    for prefix in parsed_json['prefixes']:
        if service is None or prefix['service'] == service:
            aws_cidr_list.append(prefix['ip_prefix'])

    # IPv6
    for prefix in parsed_json['ipv6_prefixes']:
        if service is None or prefix['service'] == service:
            aws_cidr_list_ipv6.append(prefix['ipv6_prefix'])

    return aws_cidr_dict


def get_aws_resouce(service, aws_access_key_id, aws_secret_access_key, sso_profile):
    if sso_profile:
        boto3_session = boto3.session.Session(profile_name=f"{sso_profile}")
        botocore_session = boto3_session._session
        resource = boto3_session.client(service)
    else:
        resource = boto3.resource(service, aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key)
    resource = boto3.resource(service)
    return resource


def get_s3_bucket_size(bucketname, prefix, aws_access_key_id, aws_secret_access_key, sso_profile):
    s3 = get_aws_resouce('s3', aws_access_key_id=aws_access_key_id,
                         aws_secret_access_key=aws_secret_access_key, sso_profile=sso_profile)

    bucket = s3.Bucket(f'{bucketname}')
    total_size = 0
    for object in bucket.objects.filter(Prefix=prefix):
        total_size += object.size
    return total_size


def get_s3_bucket_policy(bucketname, aws_access_key_id, aws_secret_access_key, sso_profile):
    get_aws_resouce('s3', aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key, sso_profile=sso_profile)
    s3 = boto3.client('s3', )
    result = s3.get_bucket_policy(Bucket=bucketname)
    policy_dict = json.loads(result['Policy'])
    return policy_dict


def set_s3_bucket_policy(bucketname, bucket_policy, aws_access_key_id, aws_secret_access_key, sso_profile):
    string_bucket_policy = json.dumps(bucket_policy)
    get_aws_resouce('s3', aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key, sso_profile=sso_profile)
    s3 = boto3.client('s3', )
    s3.put_bucket_policy(Bucket=bucketname, Policy=string_bucket_policy)


def delete_s3_bucket_content(bucketname, prefix, aws_access_key_id, aws_secret_access_key, sso_profile):
    s3 = get_aws_resouce('s3', aws_access_key_id=aws_access_key_id,
                         aws_secret_access_key=aws_secret_access_key, sso_profile=sso_profile)
    b = s3.Bucket(f'{bucketname}')
    if prefix == None:
        return -1
    response = b.objects.filter(Prefix=f"{prefix}").delete()
    return response


def upload_to_s3(src, dest, creds={}, region_name=None):
    """Uploading a non-empty file to an S3 bucket"""
    # Don't upload an empty file
    file_size_os = os.path.getsize(src)
    if file_size_os == 0:
        raise Exception("[%s] is empty, nothing to do..." % src)

    (aws_access_key_id, aws_secret_access_key, sso_profile) = set_aws_secret(creds)
    if sso_profile:
        boto3_session = boto3.session.Session(profile_name=f"{sso_profile}")
        botocore_session = boto3_session._session
        client_s3 = boto3_session.client('s3')
        head_client = boto3_session.client('s3')
    else:
        client_s3 = boto3.resource('s3', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key,
                                   region_name=region_name)
        head_client = boto3.client('s3', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key,
                                   region_name=region_name)

    full_dest = dest.split("/", 1)
    bucket_name = full_dest[0]
    key_name = full_dest[1]

    if sso_profile:
        client_s3.upload_file(src, bucket_name, key_name)
    else:
        client_s3.meta.client.upload_file(src, bucket_name, key_name)

    head_response = head_client.head_object(Bucket=bucket_name, Key=key_name)
    file_size_bucket = head_response["ContentLength"]

    ThreadLoggingHelper().set_logging_data(LoggingData(file_size=file_size_bucket))

    if file_size_bucket != file_size_os:
        print("Uploading [{}] to S3 failed".format(src))
        raise RuntimeError("Uploading to S3 failed because: file_size_bucket != file_size_os [{} != {}]".format(
            file_size_bucket, file_size_os))

    logging.info("Successfully uploaded [%s] to S3 [%s] (%s bytes)" % (src, dest, file_size_bucket))
    return True


def download_from_s3(src, dst, creds={}, region_name=None):
    """Downloading a non-empty file from an S3 bucket"""
    (aws_access_key_id, aws_secret_access_key, sso_profile) = set_aws_secret(creds)
    if sso_profile:
        boto3_session = boto3.session.Session(profile_name=f"{sso_profile}")
        botocore_session = boto3_session._session
        client_s3 = boto3_session.client('s3')
        head_client = boto3_session.client('s3')
    else:
        client_s3 = boto3.client('s3', aws_access_key_id=aws_access_key_id,
                                 aws_secret_access_key=aws_secret_access_key,
                                 region_name=region_name)

        head_client = boto3.client('s3', aws_access_key_id=aws_access_key_id,
                                   aws_secret_access_key=aws_secret_access_key,
                                   region_name=region_name)

    full_src = src.split("/", 1)
    bucket_name = full_src[0]
    key_name = full_src[1]
    os_dst = dst

    try:
        client_s3.download_file(bucket_name, key_name, os_dst)
        head_response = head_client.head_object(Bucket=bucket_name, Key=key_name)
        file_size_bucket = head_response["ContentLength"]
        file_size_os = os.path.getsize(os_dst)
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == "404":
            print("The object does not exist.")
            return False
        else:
            raise

    if file_size_bucket != file_size_os:
        print("Failed download [%s] from S3 bucket [%s]" % (key_name, bucket_name))
        raise RuntimeError(
            "Failed to download file from S3 because: file_size_bucket != file_size_os [{} != {}]".format(
                file_size_bucket, file_size_os))

    printInfo("Successfully downloaded [%s] from S3 bucket [%s]" % (key_name, bucket_name))
    return True

@retry(tries=3, delay=10, backoff=2)
def manage_app_cname(action, cname, target_name, route53_creds=None, route53_aws_region_name=None, record_type="cname", hosted_zone_name=None):
    logging.debug("manage_app_cname | action=[{}], cname=[{}], target_name=[{}], record_type=[{}], "
                  "hosted_zone_name=[{}]".format(action, cname, target_name, record_type, hosted_zone_name))

    if action == "set" and "_" in cname:
        raise ValueError("manage_app_cname | [{}] is not a valid subdomain ".format(cname))

    dns_record = JFrogAWSRout53(record_type=record_type,
                                domain_name=cname,
                                target=target_name,
                                creds=route53_creds,
                                hosted_zone_name=hosted_zone_name,
                                aws_region_name=route53_aws_region_name)
    if action == "set":
        dns_record.set()
    elif action == "delete":
        dns_record.delete()
    else:
        raise Exception("Cannot [{}] DNS [action not supported]".format(action))

    del dns_record
    return True


def create_bucket_and_iam(region, bucket_name, iam_user):
    """
    Create an Amazon S3 bucket with the specified name and in the specified Region.
    Create an IAM user and policy for this bucket
    """
    s3_client = JFrogAWSS3(region)
    if s3_client.bucket_exists(bucket_name):
        logging.error(f"bucket [{bucket_name}] already exist in region [{region}]")
        return
    bucket = s3_client.create_bucket(bucket_name)
    iam_client = JFrogIAM(user_name=iam_user, s3_bucket=bucket_name, s3_bucket_path="/",
                          policy_template={"FullAccessToBucketUser": "user/policy/FullAccessToBucketUser.json.j2"})
    iam_client.set()
    user = iam_client.get_user()
    return iam_client.aws_user_access_key_list

def get_cluster_oidc_provider(region, cloud_cluster):
    (aws_access_key_id, aws_secret_access_key, sso_profile) = set_aws_secret(creds={}, force_creds=False)
    if sso_profile:
        boto3_session = boto3.session.Session(profile_name=f"{sso_profile}",
                                              region_name=region)
        client_eks = boto3_session.client('eks')
    else:
        client_eks = boto3.client('eks',
                                  aws_access_key_id=aws_access_key_id,
                                  aws_secret_access_key=aws_secret_access_key,
                                  region_name=region)

    logging.debug("Getting OIDC provider from EKS cluster")
    try:
        eks_oidc_provider = client_eks.describe_cluster(name=cloud_cluster)["cluster"]["identity"]["oidc"]["issuer"].split("https://")[1]
        logging.info("OIDC provider of cluster {} fetched successfully - {}".format(cloud_cluster, eks_oidc_provider))
        return eks_oidc_provider
    except Exception as e:
        logging.info(e)

if __name__ == "__main__":
    print("*** Test mode ***")
    customer_name = "testmode_awspy8"
    # CloudFront test
    cloud_id = customer_name
    # Example:  jfrog_narcissus_cli getRegionDetails --region stg-use1 | grep artifactory_bucket_name
    s3_bucket = "jfrog-stg-use1-shared-virginia-main"
    # Example: jfrog_narcissus_cli getRegionDetails --region global | grep cloudfront_logs_bucket_name
    logs_s3_bucket = "stas-cloudfront-logs-use1"
    alias = 'testmode-awspy-cdn.jfrog.info'  # Example: jfrog_narcissus_cli getRegionDetails --region global | grep cdn_cname_endpoint
    # Example: jfrog_narcissus_cli getRegionDetails --region global | grep cdn_certificate_id
    iam_certificate_id = 'ASCA3DI376GHGCZ2Q6EPA'

    # PrivateLink test
    consumer_id = customer_name
    region_name = "eu-central-1"
    # privatelink_consumer_endpoint_id = "vpce-0509ebc545d946806" # Not exist
    privatelink_consumer_endpoint_id = "vpce-0387b5c95a064b4a2"  # Exist
    privatelink_endpoint_service_id = "vpce-svc-0886511649cc7e0b2"

    customer_access_key = 'AKIAIL6ABXAG7U2453PQ'
    region_bucket_name = "jfrog-stg-use1-shared-virginia-main"

    logging.getLogger().setLevel(logging.INFO)
    # logging.getLogger().setLevel(logging.DEBUG)
    logging.debug("customer_name: {}".format(customer_name))
    logging.debug("cloud_id: {}".format(cloud_id))

    sleep_secs = 20

    try:
        #        myiam = JFrogIAM(customer_name, customer_access_key, region_bucket_name)
        #        print("---> INFO AWS IAM user")
        #        print(myiam.info())
        #        print("---> SET AWS IAM user")
        #        myiam.set()
        #        print("---> INFO AWS IAM user")
        #        print(myiam.info())
        #        print("---> DELETE AWS IAM user")
        #        myiam.delete()
        #        print("---> INFO AWS IAM user")
        #        print(myiam.info())

        #        mycdn = JFrogCloudFront(cloud_id, s3_bucket, logs_s3_bucket, alias, iam_certificate_id)
        #        print("---> INFO AWS CDN")
        #        mycdn.info()
        #        print("---> SET AWS CDN")
        #        mycdn.set()
        #        mycdn.info()
        #        logging.info("Sleeping {} seconds before deletion...".format(sleep_secs))
        #        time.sleep(sleep_secs)
        #        print("---> DELETE AWS CDN with ID [{}]".format(mycdn.distribution_id))
        #        mycdn.delete()

        mypl = JFrogPrivateLink(region_name, consumer_id, privatelink_consumer_endpoint_id,
                                privatelink_endpoint_service_id)
        print("---> INFO AWS PL")
        mypl.info()
        print("---> SET AWS PL")
        mypl.set_consumer()
        logging.info("Sleeping {} seconds before deletion...".format(sleep_secs))
        time.sleep(sleep_secs)
        print("---> DELETE AWS PL with ID [{}]".format(mypl.privatelink_consumer_endpoint_id))
        mypl.delete_consumer()

    except Exception:
        print("Oops!")
        traceback.print_exc(file=sys.stdout)
        sys.exit(1)
