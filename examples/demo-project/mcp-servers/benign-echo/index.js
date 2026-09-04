// Demo fixture — a deliberately boring, fully local, network-free script
// used to prove the shim's ALLOW path actually execs the real program and
// forwards stdio/exit code, not just that it refuses to run bad things.
console.log("benign-echo: pretend MCP server started fine");
process.exit(0);
