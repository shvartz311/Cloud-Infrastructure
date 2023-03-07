import tempfile
from jfrogdevopstools.tools.kubectl import JfrogKubectlCli
from jfrogdevopstools.tools.functions import *
from jfrogdevopstools.tools.alicloud import *
from kubernetes import config, client
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.request import CommonRequest


class JfrogAckKubectlCli(JfrogKubectlCli):
    default_region = "cn-beijing"
    environment = "alistaging"
    cloud_provider_sdm_name = "Ali"

    def __init__(self, environment, region, ali_project, ali_cluster, ali_cluster_id=None,
                 alibabacloud_access_key_id=None, alibabacloud_access_key_secret=None):

        if os.getenv('ALI_KMS_JENKINS_DEPLOYER_ACCESS_KEY_ID') and os.getenv(
                'ALI_KMS_JENKINS_DEPLOYER_SECRET_ACCESS_KEY'):
            self.alibabacloud_access_key_id = os.environ["ALI_KMS_JENKINS_DEPLOYER_ACCESS_KEY_ID"]
            self.alibabacloud_access_key_secret = os.environ["ALI_KMS_JENKINS_DEPLOYER_SECRET_ACCESS_KEY"]
        else:
            self.alibabacloud_access_key_id = alibabacloud_access_key_id
            self.alibabacloud_access_key_secret = alibabacloud_access_key_secret

        super(JfrogAckKubectlCli, self).__init__(region=region,
                                                 project=ali_project,
                                                 cluster=ali_cluster,
                                                 zone=None,
                                                 environment=environment)

        self.client = AcsClient(self.alibabacloud_access_key_id, self.alibabacloud_access_key_secret,
                                self.default_region)
        self.ali_cluster_id = ali_cluster_id

    def get_kubeconfig(self):
        """
        Get the cluster configuration (kubeconfig)
        :return: DICT
        """
        logging.info(f"Getting cluster configuration")
        try:
            request = CommonRequest()
            request.set_accept_format('json')
            request.set_method('GET')
            request.set_protocol_type('https')
            request.set_domain('cs.aliyuncs.com')
            request.set_version('2015-12-15')

            request.add_query_param('RegionId', "cn-beijing")
            request.add_header('Content-Type', 'application/json')
            request.set_uri_pattern(f'/api/v2/k8s/{self.ali_cluster_id}/user_config')

            response = self.client.do_action_with_exception(request)
            response = response.decode("utf-8")
            result = json.loads(response)["config"]

            return result

        except Exception:
            logging.error(f"Could not retrieve cluster configuration!")
            raise

    def save_kubeconfig_in_tempfile(self, result):
        """
        Save the kubeconfig within a pythonic temporary file
        :param: result - the kubeconfig dict to be saved as a file
        :return: file path
        """
        logging.info(f"Saving cluster configuration in a pythonic temporary file")

        temp = tempfile.NamedTemporaryFile(mode='w+t')
        temp.writelines(result)
        temp.seek(0)
        temp.close()

        return temp.name

    def cloud_connect(self):
        """
        Connect to ALI cluster
        :return:
        """

        logging.info("Connecting to ALI cluster [{}]".format(self.cluster))

        os.environ['USE_SDM'] = 'False'

        kubeconfig = self.get_kubeconfig()
        kubeconfig_file = self.save_kubeconfig_in_tempfile(kubeconfig)
        cmd = "export KUBECONFIG={}".format(kubeconfig_file)

        self.exec_system_cmd(cmd)

        self.config = config.load_kube_config()
        self.client_v1 = client.CoreV1Api()

        return True
