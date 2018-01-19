const _ = require('lodash');
const express = require('express');
const prometheusClient = require('prom-client');
const axios = require('axios');

const metricsServer = express();

const SNYK_API_TOKEN = process.env.SNYK_API_TOKEN;
const BASE_URL = process.env.SNYK_API_BASE_URL || 'https://snyk.io/api/v1';
const ORG_NAME = process.env.SNYK_ORG_NAME;

if (!ORG_NAME) {
  console.error('Environment variable SNYK_ORG_NAME must be set');
  process.exit(1);
}
if (!SNYK_API_TOKEN) {
  console.error('Environment variable SNYK_API_TOKEN must be set');
  process.exit(1);
}

const QUERY_PROJECTS = `/org/${ORG_NAME}/projects`;

const DEBUG = process.env['SNYK_EXPORTER_DEBUG'] || false;

const httpClient = axios.create({
  baseURL: BASE_URL,
  headers: {
    'Authorization': SNYK_API_TOKEN
  }
});

const POST_DATA = {
  'filters': {
    'severity': [
      'high',
      'medium',
      'low'
    ],
    'types': [
      'vuln',
      'license'
    ],
    'ignored': false,
    'patched': false
  }
};

const up = new prometheusClient.Gauge({name: 'up', help: 'UP Status'});

const vulnerabilitiesBySeverity = new prometheusClient.Gauge({
  name: 'snyk_num_vulnerabilities_by_severity',
  help: 'Number of Snyk vulnerabilities by severity',
  labelNames: ['project', 'severity']
});

const vulnerabilitiesByType = new prometheusClient.Gauge({
  name: 'snyk_num_vulnerabilities_by_type',
  help: 'Number of Snyk vulnerabilities by type',
  labelNames: ['project', 'type']
});

metricsServer.get('/metrics', async (req, res) => {
  res.contentType(prometheusClient.register.contentType);

  try {
    resetStats();
    const response = await getProjects();
    await processProjects(response.data);

    // let connection = await connect();
    // await collect(connection, metrics);
    // connection.close();
    res.send(prometheusClient.register.metrics());
  } catch (error) {
    // error connecting
    up.set(0);
    res.header('X-Error', error.message || error);
    res.send(prometheusClient.register.getSingleMetricAsString(up.name));
  }
});

console.log('Server listening to 9207, metrics exposed on /metrics endpoint');
metricsServer.listen(9207);

function resetStats () {
  up.set(1);
  vulnerabilitiesBySeverity.reset();
  vulnerabilitiesByType.reset();
}

async function getProjects () {
  return httpClient.get(QUERY_PROJECTS);
}

async function processProjects (projectData) {
  let orgId;
  if (projectData.org && projectData.org.id) {
    orgId = projectData.org.id;
  } else {
    throw new Error('Unable to find org id in response data');
  }

  for (let i = 0; i < projectData.projects.length; i++) {
    const project = projectData.projects[i];

    if (DEBUG) {
      console.log(`Project Name: ${project.projectName} Project ID: ${project.projectId}`);
    }

    let issueData = await getIssues(orgId, project);

    if (!issueData.data.issues) {
      throw new Error('Could not find issue object in response data');
    }

    let countsForProject = getVulnerabilityCounts(issueData.data.issues);
    setSeverityGauges(project.name, project.Id, countsForProject.severities);
    setTypeGauges(project.name, project.Id, countsForProject.types);
  }
}

async function getIssues (orgId, project) {
  if (!project) {
    throw new Error('project not provided');
  }

  const issuesQuery = `/org/${orgId}/project/${project.id}/issues`;

  return httpClient.post(
    issuesQuery,
    POST_DATA
  );
}

function getVulnerabilityCounts (issues) {
  const results = {
    severities: {
      high: 0,
      medium: 0,
      low: 0
    },
    types: {}
  };

  for (var k = 0; k < issues.vulnerabilities.length; k++) {
    let thisVuln = issues.vulnerabilities[k];

    const severity = thisVuln.severity;
    if (severity !== 'high' && severity !== 'medium' && severity !== 'low') {
      throw new Error('Invalid severity: ' + severity);
    }

    results.severities[severity]++;

    let thisType = thisVuln.title;
    if (!results.types[thisType]) {
      results.types[thisType] = 1;
    } else {
      results.types[thisType]++;
    }
  }
  return results;
}

function setSeverityGauges (projectName, projectId, severities) {
  _.each(severities, (count, severity) => {
    vulnerabilitiesBySeverity.set({
      project: projectName,
      severity: severity
    }, count);
  });
}

function setTypeGauges (projectName, projectId, types) {
  _.each(types, (count, type) => {
    // console.log(`Type: ${typeName}, Count: ${types[typeName]}`);
    vulnerabilitiesByType.set({
      project: projectName,
      type: type
    }, count);
  });
}
