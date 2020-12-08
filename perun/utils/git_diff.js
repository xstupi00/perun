const parser = require("gitdiff-parser");
const fs = require('fs');
const diff = JSON.stringify(parser.parse(fs.readFileSync('/dev/stdin').toString()));
console.log(diff)