// Minimal Node script — validates dispatcher's Node runtime detection
// (driven by package.json + .js extension) and the local-process executor
// for a non-Python runtime.

function main() {
  console.log(`hello from dispatcher on Node ${process.version}`);
  console.log(`  platform: ${process.platform}/${process.arch}`);
  console.log(`  cwd:      ${process.cwd()}`);

  // Validate .env injection (cmd.Env propagation through the local adapter).
  const name = process.env.GREETING_NAME;
  if (name) {
    console.log(`  greeting: hello, ${name}!`);
  }

  console.log('done');
}

main();
