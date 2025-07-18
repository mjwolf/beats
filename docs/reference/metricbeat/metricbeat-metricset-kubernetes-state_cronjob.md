---
mapped_pages:
  - https://www.elastic.co/guide/en/beats/metricbeat/current/metricbeat-metricset-kubernetes-state_cronjob.html
---

% This file is generated! See scripts/docs_collector.py

# Kubernetes state_cronjob metricset [metricbeat-metricset-kubernetes-state_cronjob]

This is the `state_cronjob` metricset of the Kubernetes module.

This metricset adds metadata by default only for versions of k8s >= v1.21. For older versions the APIs are not compatible and one need to configure the metricset with `add_metadata: false` and remove the proper `apiGroup` in the `ClusterRole`:

```yaml
- apiGroups: [ "batch" ]
  resources:
  - cronjobs
```

## Fields [_fields]

For a description of each field in the metricset, see the [exported fields](/reference/metricbeat/exported-fields-kubernetes.md) section.

Here is an example document generated by this metricset:

```json
{
    "@timestamp": "2019-03-01T08:05:34.853Z",
    "event": {
        "dataset": "kubernetes.cronjob",
        "duration": 115000,
        "module": "kubernetes"
    },
    "kubernetes": {
        "cronjob": {
            "active": {
                "count": 0
            },
            "created": {
                "sec": 1713862291
            },
            "is_suspended": false,
            "last_schedule": {
                "sec": 1713873360
            },
            "name": "hello",
            "next_schedule": {
                "sec": 1713873420
            }
        },
        "namespace": "default"
    },
    "metricset": {
        "name": "state_cronjob",
        "period": 10000
    },
    "service": {
        "address": "127.0.0.1:55555",
        "type": "kubernetes"
    }
}
```
