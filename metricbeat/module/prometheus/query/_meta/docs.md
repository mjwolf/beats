This is the `query` metricset to query from [querying API of Prometheus](https://prometheus.io/docs/prometheus/latest/querying/api/#expression-queries).


## Configuration [_configuration_3]


### Instant queries [_instant_queries]

The following configuration performs an instant query for `up` metric at a single point in time:

```yaml
- module: prometheus
  period: 10s
  hosts: ["localhost:9090"]
  metricsets: ["query"]
  queries:
  - name: 'up'
    path: '/api/v1/query'
    params:
      query: "up"
```

More complex PromQL expressions can also be used like the following one which calculates the per-second rate of HTTP requests as measured over the last 5 minutes.

```yaml
- module: prometheus
  period: 10s
  hosts: ["localhost:9090"]
  metricsets: ["query"]
  queries:
  - name: "rate_http_requests_total"
    path: "/api/v1/query"
    params:
      query: "rate(prometheus_http_requests_total[5m])"
```


### Range queries [_range_queries]

The following example evaluates the expression `up` over a 30-second range with a query resolution of 15 seconds:

```yaml
- module: prometheus
  period: 10s
  metricsets: ["query"]
  hosts: ["node:9100"]
  queries:
  - name: "up_master"
    path: "/api/v1/query_range"
    params:
      query: "up{node='master01'}"
      start: "2019-12-20T23:30:30.000Z"
      end: "2019-12-21T23:31:00.000Z"
      step: 15s
```
