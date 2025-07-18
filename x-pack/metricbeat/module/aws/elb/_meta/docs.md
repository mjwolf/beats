Elastic Load Balancing publishes data points to Amazon CloudWatch for your load balancers and your back-end instances. This aws `elb` metricset collects these Cloudwatch metrics for monitoring purposes.


## AWS Permissions [_aws_permissions_6]

Some specific AWS permissions are required for IAM user to collect AWS ELB metrics.

```
ec2:DescribeRegions
cloudwatch:GetMetricData
cloudwatch:ListMetrics
tag:getResources
sts:GetCallerIdentity
iam:ListAccountAliases
```


## Dashboard [_dashboard_7]

The aws elb metricset comes with a predefined dashboard for classic ELB. For example:

![metricbeat aws elb overview](images/metricbeat-aws-elb-overview.png)


## Configuration example [_configuration_example_6]

```yaml
- module: aws
  period: 300s
  metricsets:
    - elb
  access_key_id: '${AWS_ACCESS_KEY_ID:""}'
  secret_access_key: '${AWS_SECRET_ACCESS_KEY:""}'
  session_token: '${AWS_SESSION_TOKEN:""}'
  # This module uses the aws cloudwatch metricset, all
  # the options for this metricset are also available here.
```


## Metrics [_metrics_4]

elb metricset collects Cloudwatch metrics from [classic ELB](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-cloudwatch-metrics.html), [application ELB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-cloudwatch-metrics.html) and [network ELB](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-cloudwatch-metrics.html).


### Metrics for Classic ELB [_metrics_for_classic_elb]

| Metric Name | Statistic Method |
| --- | --- |
| BackendConnectionErrors | Sum |
| HealthyHostCount | Maximum |
| HTTPCode_Backend_2XX | Sum |
| HTTPCode_Backend_3XX | Sum |
| HTTPCode_Backend_4XX | Sum |
| HTTPCode_Backend_5XX | Sum |
| HTTPCode_ELB_4XX | Sum |
| HTTPCode_ELB_5XX | Sum |
| Latency | Average |
| RequestCount | Sum |
| SpilloverCount | Sum |
| SurgeQueueLength | Maximum |
| UnHealthyHostCount | Maximum |
| EstimatedALBActiveConnectionCount | Average |
| EstimatedALBConsumedLCUs | Average |
| EstimatedALBNewConnectionCount | Average |
| EstimatedProcessedBytes | Average |


### Metrics for Application ELB [_metrics_for_application_elb]

| Metric Name | Statistic Method |
| --- | --- |
| ActiveConnectionCount | Sum |
| ClientTLSNegotiationErrorCount | Sum |
| ConsumedLCUs | Average |
| HTTP_Fixed_Response_Count | Sum |
| HTTP_Redirect_Count | Sum |
| HTTP_Redirect_Url_Limit_Exceeded_Count | Sum |
| HTTPCode_ELB_3XX_Count | Sum |
| HTTPCode_ELB_4XX_Count | Sum |
| HTTPCode_ELB_5XX_Count | Sum |
| HTTPCode_ELB_500_Count | Sum |
| HTTPCode_ELB_502_Count | Sum |
| HTTPCode_ELB_503_Count | Sum |
| HTTPCode_ELB_504_Count | Sum |
| IPv6ProcessedBytes | Sum |
| IPv6RequestCount | Sum |
| NewConnectionCount | Sum |
| ProcessedBytes | Sum |
| RejectedConnectionCount | Sum |
| RequestCount | Sum |
| RuleEvaluations | Sum |


### Metrics for Network ELB [_metrics_for_network_elb]

| Metric Name | Statistic Method |
| --- | --- |
| ActiveFlowCount | Average |
| ActiveFlowCount_TLS | Average |
| ActiveFlowCount_TCP | Average |
| ActiveFlowCount_UDP | Average |
| ConsumedLCUs | Average |
| ConsumedLCUs_TCP | Average |
| ConsumedLCUs_TLS | Average |
| ConsumedLCUs_UDP | Average |
| ClientTLSNegotiationErrorCount | Sum |
| NewFlowCount | Sum |
| NewFlowCount_TLS | Sum |
| NewFlowCount_TCP | Sum |
| NewFlowCount_UDP | Sum |
| ProcessedBytes | Sum |
| ProcessedBytes_TCP | Sum |
| ProcessedBytes_TLS | Sum |
| ProcessedBytes_UDP | Sum |
| TargetTLSNegotiationErrorCount | Sum |
| TCP_Client_Reset_Count | Sum |
| TCP_ELB_Reset_Count | Sum |
| TCP_Target_Reset_Count | Sum |
| UnHealthyHostCount | Maximum |
| HealthyHostCount | Maximum |
