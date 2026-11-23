// The first thing sagebrush-agent does (#1788): a Node.js too old for it is said, with where to get a current one,
// before any other module loads (one that uses something newer could fail first, saying nothing useful). No imports.
const major = Number(String(process.versions.node).split(".")[0]);
if (!(Number.isInteger(major) && major >= 20)) {
  console.error(`sagebrush-agent needs Node.js 20 or later; this is Node.js ${process.versions.node}. Install a current Node.js from https://nodejs.org, then run the command again.`);
  process.exit(2);
}
