#!/usr/bin/env python3
import jfrogdevopstools.tools.eks_kubectl_cli
import jfrogdevopstools.tools.ack_kubectl_cli
import jfrogdevopstools.tools.gcp as jfrog_gcp_tools
import jfrogdevopstools.tools.aws as jfrog_aws_tools
import jfrogdevopstools.tools.azure as jfrog_azure_tools


def get_kubectl_cli_client(region, region_info, global_info):

    cloud_provider = region_info["cloud_provider"]
    project = region_info["cloud_project"]
    cluster = region_info["cloud_cluster"]
    region_code = region_info["region_code"]
    if "k8s_region_code" in region_info:
        region_code = region_info["k8s_region_code"]
    environment = global_info["environment"]

    # regional credentials take precedence over globals'
    aws_access_key_id = region_info.get('k8s_aws_access_key_id') or global_info.get('k8s_aws_access_key_id')
    aws_secret_access_key = region_info.get('k8s_aws_secret_access_key') or global_info.get('k8s_aws_secret_access_key')

    try:
        if cloud_provider == "gcp":
            kubectl_cli_client = jfrog_gcp_tools.JfrogGkeKubectlCli(environment=environment,
                                                                    region=region,
                                                                    gcloud_cluster=cluster,
                                                                    gcloud_zone=region_info["cloud_zone"],
                                                                    gcloud_project=project,
                                                                    gcloud_key=region_info["gcp_service_account_private_key_json"])
        elif cloud_provider == "aws":
            kubectl_cli_client = jfrogdevopstools.tools.eks_kubectl_cli.JfrogEksKubectlCli(environment=environment,
                                                                                           region=region,
                                                                                           aws_project=project,
                                                                                           aws_zone=region_code,
                                                                                           aws_cluster=cluster,
                                                                                           aws_access_key_id=aws_access_key_id,
                                                                                           aws_secret_access_key=aws_secret_access_key,
                                                                                           aws_iam_role_arn=global_info["aws_iam_role_arn"])
        elif cloud_provider == "ali":
            cluster_id = region_info["cloud_cluster_id"]
            kubectl_cli_client = jfrogdevopstools.tools.ack_kubectl_cli.JfrogAckKubectlCli(environment=environment,
                                                                                           region=region,
                                                                                           ali_project=project,
                                                                                           ali_cluster=cluster,
                                                                                           ali_cluster_id=cluster_id)

        elif cloud_provider == "azure":
            kubectl_cli_client = jfrog_azure_tools.JfrogAksKubectlCli(environment=environment,
                                                                      region=region,
                                                                      azure_cluster=cluster,
                                                                      azure_zone=region_code,
                                                                      azure_project=project,
                                                                      azure_client_id=global_info["azure_client_id"],
                                                                      azure_client_pass=global_info["azure_secret"],
                                                                      azure_tenant_id=global_info["azure_tenant"],
                                                                      azure_subscription_id=global_info["azure_subscription_id"],
                                                                      k8s_resource_group_name=valid_key_from_json(region_info, "k8s_resource_group_name"))
        else:
            raise Exception("Cloud provider {} is not supported!!!".format(cloud_provider))
    except KeyError as e:
        raise KeyError("Trying to use undefined key {} while initiating cloud env of {}".format(e, cloud_provider))
    except Exception:
        raise Exception("Error while initiating cloud env of {}".format(cloud_provider))

    return kubectl_cli_client


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
