# PitchMe.io

> Our web app welcomes startups to pitch their ideas and show their products to the masses. Those who are passionate about innovative ideas can visit our site, check out popular startup ideas and share ideas of their choices on their social network.

## Team

  - Alison Zhang
  - Craig Rodrigues
  - Edward Chan

## Table of Contents

1. [Usage](#Usage)
1. [Requirements](#requirements)
1. [Development](#development)
    1. [Installing Dependencies](#installing-dependencies)
    1. [Tasks](#tasks)
1. [Roadmap](#roadmap)
1. [Contributing](#contributing)

## Usage
###Set up server & db tables:
With all dependencies installed, please also install Postgres.app (for Mac users) and Postico. The former works with postgres database and the latter allows you to directly check the tables on your Mac. 

The test/db folder contains data that we need for both development and backend tests. With knex installed, you can refer to the commands in this link(http://mherman.org/blog/2016/04/28/test-driven-development-with-node/#.WNqmIHQrJo5) to create the tables and fill in data. (No need to create schema and dummy data again.)

For session to work, session table should be created by hand and a specific schema should be used. To create the table, go to 'SQL Query' in Postico and run the table.sql file in node_modules/connect-pg-simple.

## Requirements

- Node 7.6.0
- Redis 2.6.x
- Postgresql 9.1.x
- React <x.x.x>
- Redux <x.x.x?
- React-Router 4

## Development

### Installing Dependencies

From within the root directory:

```sh
npm install -g bower
npm install
bower install
```

### Roadmap

View the project roadmap [here](LINK_TO_DOC)


## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.
