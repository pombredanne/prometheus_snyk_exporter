const toBeType = require('jest-tobetype').toBeType;
expect.extend({toBeType});

const nock = require('nock');
const fixture = require('./fixtures.json');

var app = require('../index');

describe('getProjects', () => {
  beforeAll(() => {
    app.init({
      SNYK_API_TOKEN: 'abc-123',
      ORG_NAME: 'springfield'
    });
  });

  beforeEach(() => {
    nock(
      'https://snyk.io:443')
      .get('/api/v1/org/springfield/projects')
      .reply(200, fixture);
  });

  it('should get the org information', async () => {
    const response = await app.getProjects('springfield');
    expect(response.data).toBeDefined();
    expect(response.data.org).toBeDefined();
    expect(response.data.org.name).toEqual('springfield');
    expect(response.data.org.id).toEqual('1234567a-123b-456c-def7-890abcdefg01');
  });

  it('should get the project information', async () => {
    const response = await app.getProjects('springfield');
    expect(response.data).toBeDefined();
    expect(response.data.projects).toBeDefined();

    expect(response.data.projects).toBeType('array');
    expect(response.data.projects.length).toBe(3);

    expect(response.data.projects[0].name).toBe('burns');
    expect(response.data.projects[0].id).toBe('2234567a-123b-456c-def7-890abcdefg01');

    expect(response.data.projects[1].name).toBe('smithers');
    expect(response.data.projects[1].id).toBe('3234567a-123b-456c-def7-890abcdefg01');

    expect(response.data.projects[2].name).toBe('frink');
    expect(response.data.projects[2].id).toBe('4234567a-123b-456c-def7-890abcdefg01');
  });
});
