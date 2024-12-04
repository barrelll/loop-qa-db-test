#!/bin/bash

# Start PostgreSQL service
service postgresql start

# Run the test
npx mocha test_database.js
