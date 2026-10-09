// Shared test protocol for Node and browser clients. Only the installed public
// API computes cryptographic values; RPCs remain in the Rust test.
export function commands(client) {
  const bytes = (v) => Uint8Array.from(v);
  let start;
  let history;
  let login;
  return async (v) => {
    switch (v.method) {
      case "start":
        start = await client.registrationStart(v.password);
        return start.request;
      case "history":
        history = await client.historyRequest(v.password, bytes(v.ownerDomain));
        if (history === null) throw new Error("test password must be provable");
        return history.blinded;
      case "prove": {
        const proof = await client.prove(v.password, start, {
          context: {
            ...v.context,
            operationId: bytes(v.context.operationId),
            ownerDomain: bytes(v.context.ownerDomain),
            domains: v.context.domains.map((d) => ({
              comparisonDomain: bytes(d.comparisonDomain),
              evaluatorPublicKey: bytes(d.evaluatorPublicKey),
            })),
          },
          history: {
            request: history,
            evaluations: v.evaluations.map((e) => ({
              evaluatedElement: bytes(e.evaluatedElement),
              proof: { challenge: bytes(e.proof.challenge), response: bytes(e.proof.response) },
            })),
          },
        });
        if (proof === null) throw new Error("test password must be provable");
        return proof;
      }
      case "record":
        return client.registrationFinish(v.password, start.state, bytes(v.response));
      case "loginStart":
        login = await client.loginStart(v.password);
        return login.request;
      case "loginFinish":
        // An ordinary sign-in has the empty context; a change sends its own.
        return client.loginFinish(
          v.password,
          login.state,
          bytes(v.response),
          bytes(v.context ?? []),
        );
      default:
        throw new Error("unknown test command");
    }
  };
}
