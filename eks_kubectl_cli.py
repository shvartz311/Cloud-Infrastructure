import logging
import os

from jfrogdevopstools.tools.kubectl import JfrogKubectlCli
from kubernetes import config, client


class JfrogEksKubectlCli(JfrogKubectlCli):
    cloud_provider = "aws"
    cloud_provider_sdm_name = "AWS"
    aws_iam_role_arn = None
    aws_access_key_id = None
    aws_secret_access_key = None

    def __init__(self, environment, region, aws_project, aws_zone, aws_cluster, aws_access_key_id,
                 aws_secret_access_key, aws_iam_role_arn):

        self.aws_iam_role_arn = aws_iam_role_arn

        if os.getenv('AWS_ACCESS_KEY_ID') and os.getenv('AWS_SECRET_ACCESS_KEY'):
            self.aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
            self.aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']
        else:
            self.aws_access_key_id = aws_access_key_id
            self.aws_secret_access_key = aws_secret_access_key

        super(JfrogEksKubectlCli, self).__init__(region=region,
                                                 project=aws_project,
                                                 cluster=aws_cluster,
                                                 zone=aws_zone,
                                                 environment=environment)

    def cloud_connect(self):
        """
        Connect to AWS cluster
        :return:
        """

        logging.info("Connecting to AWS cluster [{}], zone [{}]".format(self.cluster, self.zone))

        use_aws_arn_role = os.getenv('USE_AWS_ARN_ROLE', None)

        os.environ['AWS_ACCESS_KEY_ID'] = self.aws_access_key_id
        os.environ['AWS_SECRET_ACCESS_KEY'] = self.aws_secret_access_key
        os.environ['AWS_DEFAULT_REGION'] = self.zone

        if use_aws_arn_role == "true":
            logging.info("Configuring aws auth using aws_iam_role_arn = [{}]".format(self.aws_iam_role_arn))
            cmd = "aws eks update-kubeconfig --name {} --role-arn {}".format(self.cluster, self.aws_iam_role_arn)
        else:
            cmd = "aws eks update-kubeconfig --name {}".format(self.cluster)
        self.exec_system_cmd(cmd)

        self.config = config.load_kube_config()
        self.client_v1 = client.CoreV1Api()

        return True