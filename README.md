# prometheus\_snyk\_exporter

A [prometheus exporter](https://prometheus.io) that scrapes the [snyk.io API](https://snyk.docs.apiary.io), collects aggregate information about your organiation's vulnerabilities, and exposes it as prometheus metrics.

## Motivation

The snyk.io dashboard provides a view of the current state of your project's security vulnerabilities.  Snyk also offers an enterprise product with the ability to track the number of vulnerabilities over time.  For many users, this may be sufficient.

At DNAnexus, we're building a culture of observability and we wanted this information to be available to our internal monitoring system.  This way, we can not only track our security vulnerabilities over time, but also set up our own custom alerts and internal [SLOs](https://landing.google.com/sre/book/chapters/service-level-objectives.html) using Prometheus.

This also allows you to create pretty Grafana dashboards like this:

![snyk_dashboard](https://user-images.githubusercontent.com/1438478/35176929-5ff18dec-fd39-11e7-90f3-fec700ab37a8.jpg)

(Dashboard will be open-sourced soon as well.)   

## Prerequisites

* An account with snyk.io.  It's free for open source projects, and low-frequency scans private projects.
* A snyk API token.  Get it on your [account settings page](https://snyk.io/account/).

## Getting Started

### NodeJS

Note: Requires node > 7.6 for async/await support. 

```bash
git clone git@github.com:dnanexus/prometheus_snyk_exporter.git
cd prometheus_snyk_exporter
npm install
export SNYK_ORG_NAME=CompuGlobalHyperMegaNet
export SNYK_API_TOKEN=xxxxx-yyyyy-zzzzzz
node index.js
```

### Docker

```bash
docker run \
    -d \
    --name prometheus_snyk_exporter \
    --restart=unless-stopped \
    -e SNYK_ORG_NAME=CompuGlobalHyperMegaNet \
    -e SNYK_API_TOKEN=xxxxx-yyyyy-zzzzzz \
    -p 9207:9207 \
    dnanexus/prometheus_snyk_exporter  
```

## Usage

Metrics are exposed on the `/metrics` endpoint, on port `9207`.

### Test it out!

```
curl http://localhost:9207/metrics
```

It may take 5-10 seconds for the API scrape to complete.  After, you should see your metrics similar to the format shown further below.

### Prometheus configuration 

Add something similar to following to your `prometheus.yml` file:

```yml
  - job_name: 'snyk'
    scrape_interval: 600s
    static_configs:
      - targets: ['localhost:9207']
```

Note: Please be nice to the snyk API, and don't configure an aggressive scrape interval.  Scraping every 10 minutes (600s) or even every hour (3600s) should be sufficient.

If you're running the exporter on a different server than your prometheus server, substitute it for `localhost`.

## Metrics Format

This exporter exposes two different metrics.  

Note: The samples below contain dummy generated data and are not taken from an actual security scan.

### snyk\_num\_vulnerabilities\_by\_severity

This metric gives you a breakdown of how many high, medium, and low-severity issues exist per-project.  

```
# HELP snyk_num_vulnerabilities_by_severity Number of Snyk vulnerabilities by severity
# TYPE snyk_num_vulnerabilities_by_severity gauge
snyk_num_vulnerabilities_by_severity{project="burns",severity="high"} 1
snyk_num_vulnerabilities_by_severity{project="burns",severity="medium"} 4
snyk_num_vulnerabilities_by_severity{project="burns",severity="low"} 2
snyk_num_vulnerabilities_by_severity{project="smithers",severity="high"} 24
snyk_num_vulnerabilities_by_severity{project="smithers",severity="medium"} 7
snyk_num_vulnerabilities_by_severity{project="smithers",severity="low"} 14
snyk_num_vulnerabilities_by_severity{project="frink",severity="high"} 0
snyk_num_vulnerabilities_by_severity{project="frink",severity="medium"} 3
snyk_num_vulnerabilities_by_severity{project="frink",severity="low"} 9
```

### snyk\_num\_vulnerabilities\_by\_type

This metric gives you a breakdown of how many issues of each vulnerability type exist per-project.

```
# HELP snyk_num_vulnerabilities_by_type Number of Snyk vulnerabilities by type
# TYPE snyk_num_vulnerabilities_by_type gauge
snyk_num_vulnerabilities_by_type{project="burns",type="Regular Expression Denial of Service (DoS)"} 27
snyk_num_vulnerabilities_by_type{project="smithers",type="Content Injection (XSS)"} 11
snyk_num_vulnerabilities_by_type{project="smithers",type="Improper minification of non-boolean comparisons"} 14
snyk_num_vulnerabilities_by_type{project="frink",type="Uninitialized Memory Exposure"} 8
```
