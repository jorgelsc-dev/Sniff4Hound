// Reuse the frontend's existing ESLint installation; no Electron dependencies
// or running desktop session are needed to check these entry points.
const globals = require("./frontend/node_modules/globals");

module.exports = [
  {
    files: ["**/*.js", "**/*.cjs"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "commonjs",
      globals: globals.node,
    },
    rules: { "no-undef": "error" },
  },
  {
    files: ["**/splash.js"],
    languageOptions: { sourceType: "script", globals: globals.browser },
  },
];
