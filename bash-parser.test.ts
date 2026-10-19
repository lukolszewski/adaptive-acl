import { describe, expect, it, vi } from "vitest";

/**
 * The adapter keeps its init state in module scope, so every test that cares
 * about the un-initialised (or disposed) state needs its own instance of the
 * module rather than an ordering of shared calls. `vi.resetModules()` plus a
 * dynamic import gives that; a re-import also re-bootstraps web-tree-sitter,
 * which costs ~15 ms per fresh copy, so a test that only parses should not take
 * it for no reason.
 */
type Adapter = typeof import("./bash-parser.ts");

async function freshAdapter(): Promise<Adapter> {
  vi.resetModules();
  return (await import("./bash-parser.ts")) as Adapter;
}

/** First node of the given type, depth-first, or null. */
function pick(node: { type: string; children: any[] }, type: string): any | null {
  if (node.type === type) return node;
  for (const child of node.children) {
    const hit = pick(child, type);
    if (hit) return hit;
  }
  return null;
}

describe("bash-parser: lifecycle", () => {
  it("fails closed before init", async () => {
    const mod = await freshAdapter();
    expect(mod.isBashParserReady()).toBe(false);

    const result = mod.parseBash("echo hi");
    expect("tree" in result).toBe(false);
    expect(result).toMatchObject({ error: "not-initialised" });
  });

  it("init is idempotent, including concurrent calls", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();
    const afterFirst = mod.isBashParserReady();
    await mod.initBashParser();
    await Promise.all([mod.initBashParser(), mod.initBashParser()]);

    expect(afterFirst).toBe(true);
    expect(mod.isBashParserReady()).toBe(true);
    expect(mod.bashParserInitError()).toBeNull();

    const result = mod.parseBash("echo hi");
    expect("tree" in result).toBe(true);
    if ("tree" in result) result.tree.delete();
  });

  it("dispose releases the parser and a later init works again", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();
    expect(mod.isBashParserReady()).toBe(true);

    mod.disposeBashParser();
    expect(mod.isBashParserReady()).toBe(false);
    expect(mod.parseBash("echo hi")).toMatchObject({ error: "not-initialised" });
    mod.disposeBashParser(); // disposing twice is not an error

    await mod.initBashParser();
    expect(mod.isBashParserReady()).toBe(true);
    const result = mod.parseBash("echo hi");
    expect("tree" in result).toBe(true);
    if ("tree" in result) expect(result.tree.rootNode.type).toBe("program");
  });
});

describe("bash-parser: parsing", () => {
  // One shared instance for the parse-only tests: they do not touch init state.
  const withParser = async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();
    return mod;
  };

  it("parses a simple command as a program with no error nodes", async () => {
    const mod = await withParser();
    const result = mod.parseBash('git status && ls -la | head -3');
    if (!("tree" in result)) throw new Error(`expected a tree, got ${JSON.stringify(result)}`);

    const root = result.tree.rootNode;
    expect(root.type).toBe("program");
    expect(root.hasError).toBe(false);

    // One `list` child holding both halves of the && chain, with the pipeline
    // nested inside it — i.e. a real tree, not a token soup.
    const list = root.firstChild!;
    expect(list.type).toBe("list");
    expect(list.children.map((c) => c.type)).toEqual(["command", "&&", "pipeline"]);
    result.tree.delete();
  });

  it("treats a malformed command as a tree with errors, not an exception", async () => {
    const mod = await withParser();
    const result = mod.parseBash('echo "unterminated');
    expect("tree" in result).toBe(true);
    if (!("tree" in result)) return;

    expect(result.tree.rootNode.type).toBe("program");
    expect(result.tree.rootNode.hasError).toBe(true);
    result.tree.delete();
  });

  it("reports indices as JS string offsets, not UTF-8 bytes", async () => {
    const mod = await withParser();
    const source = 'echo "héllo wörld" > out.txt';
    // The assertion below only means something if the two encodings differ.
    expect(Buffer.byteLength(source, "utf8")).toBeGreaterThan(source.length);

    const result = mod.parseBash(source);
    if (!("tree" in result)) throw new Error(`expected a tree, got ${JSON.stringify(result)}`);

    expect(result.tree.rootNode.endIndex).toBe(source.length);
    const str = pick(result.tree.rootNode, "string");
    expect(str).not.toBeNull();
    expect(source.slice(str.startIndex, str.endIndex)).toBe('"héllo wörld"');
    const target = pick(result.tree.rootNode, "word");
    expect(source.slice(target.startIndex, target.endIndex)).toBe("echo");
    result.tree.delete();
  });
});

describe("bash-parser: limits", () => {
  const atCap = (mod: Adapter, text: string) => mod.parseBash(text);

  it("refuses a command over the 10 000 character cap without parsing it", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    const tooLong = atCap(mod, "echo " + "a".repeat(mod.MAX_COMMAND_CHARS - 5 + 1));
    expect(tooLong).toMatchObject({ error: "too-large" });
    expect((tooLong as { detail?: string }).detail).toContain(
      String(mod.MAX_COMMAND_CHARS + 1),
    );
  });

  it("still parses a command of exactly the cap", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    const text = "echo " + "x".repeat(mod.MAX_COMMAND_CHARS - 5);
    expect(text.length).toBe(mod.MAX_COMMAND_CHARS);
    // This one used to accept `aborted` — "whether a maximal command survives the time budget under a
    // loaded test runner is not part of the claim". It is part of the claim now, and it can be, because
    // the budget is measured rather than guessed: a 10 000-character command of this shape parses in
    // 0.4 ms (eval/parse-latency.ts, and 0.93 ms was the slowest real command of the whole corpus),
    // against an envelope of PARSE_TIMEOUT_MS. A machine that aborts it is a machine where the abort is
    // the correct answer, and a test that tolerated `aborted` here was the flake in disguise.
    const result = atCap(mod, text);
    if (!("tree" in result)) throw new Error(`a maximal command must parse: ${JSON.stringify(result)}`);
    expect(result.tree.rootNode.type).toBe("program");
    expect(mod.lastParseCost().stop).toBeNull();
    result.tree.delete();

    const overByOne = atCap(mod, text + "y");
    expect(overByOne).toMatchObject({ error: "too-large" });
  });

  // -------------------------------------------------------------------------
  // The two runaway caps, asserted without a stopwatch.
  //
  // `parseBash` enforces its wall-clock budget from inside tree-sitter's progress callback, so the only
  // way to watch it from outside used to be to time a parse and hope the runner was idle. A test that
  // did that parsed 4 000 characters: ~10 ms on an idle box, over the budget when the rest of the suite
  // was running. The cap was not wrong — the parse really did overrun — the *test* was racing it.
  //
  // So the cap is driven, not raced. `Date.now` is the only clock the budget reads, and it is swapped
  // for the duration of one synchronous parse: a stub that jumps past the deadline makes "time ran out"
  // a fact the parser is told about, a frozen stub makes it impossible, and a stub that jumps once and
  // then stops makes "the machine hiccuped" a scenario a test can name. None of them depends on how fast
  // the machine is, which is the whole point.
  //
  // What the three shapes are here to pin, after W53:
  //   - a pause inside a parse must not decide the verdict (the flake: a 322-character golden case
  //     measured 7.6 ms cold, <1 ms warm, 99 ms under 48-way contention, and 99 ms was over the old
  //     50 ms budget);
  //   - the retry is bounded, and the envelope belongs to the call rather than to the attempt, so a
  //     retry can never make the call slower than PARSE_TIMEOUT_MS;
  //   - a retried parse is asserted, not hoped for: the answer we return is the second parse's answer.
  // -------------------------------------------------------------------------

  /**
   * Run `body` with `Date.now` replaced by a clock that moves `msPerRead`
   * milliseconds per consultation, then put the real clock back. `0` freezes time
   * (the deadline can then never be reached, whatever the CPU is doing);
   * `PARSE_TIMEOUT_MS + 1` puts the clock beyond the deadline on the first
   * consultation after the deadline is set. `reads` is how many times the parse
   * looked at the clock — the difference between "the cap fired mid-parse" and
   * "the parser returned nothing for some other reason".
   *
   * `body` must be synchronous: an `await` inside it would leave the stub in place
   * across a macrotask, where anything else in the runtime could read it.
   */
  function withStubbedClock<T>(msPerRead: number, body: () => T): { value: T; reads: number } {
    const realNow = Date.now;
    const origin = realNow();
    let reads = 0;
    Date.now = () => {
      reads += 1;
      return origin + reads * msPerRead;
    };
    try {
      return { value: body(), reads };
    } finally {
      Date.now = realNow;
    }
  }

  /**
   * The same swap, but for a machine that stalls **once**: every consultation from the `stallAtRead`-th
   * onward reports `origin + stallMs` and time never advances again. Read 1 is the call's envelope, read
   * 2 the first attempt's guard, so `stallAtRead: 3` is "the pause happened inside the first parse".
   * This is the shape of the real failure — a scheduling or GC pause inside a sub-millisecond parse —
   * and a test for it cannot be written with a frozen clock or a uniformly fast one.
   */
  function withStutteringClock<T>(
    stallAtRead: number,
    stallMs: number,
    body: () => T,
  ): { value: T; reads: number } {
    const realNow = Date.now;
    const origin = realNow();
    let reads = 0;
    Date.now = () => {
      reads += 1;
      return reads >= stallAtRead ? origin + stallMs : origin;
    };
    try {
      return { value: body(), reads };
    } finally {
      Date.now = realNow;
    }
  }

  /** How the module words a wall-clock abort; spelled once so the tests cannot drift from it. */
  const abortDetail = (mod: Adapter): string => {
    const window = mod.PARSE_TIMEOUT_MS / mod.PARSE_ATTEMPTS;
    return `over ${window} ms per attempt (${mod.PARSE_TIMEOUT_MS} ms over ${mod.PARSE_ATTEMPTS} attempts)`;
  };

  it("counts every node with a cursor and returns cap+1 as soon as the cap is exceeded", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // What parseBash asks is `countTreeNodes(tree, MAX_TREE_NODES) > MAX_TREE_NODES`,
    // and MAX_TREE_NODES is out of reach for any command the size gate accepts (see
    // the maximal-command test), so the cap arithmetic is asserted on the caps this
    // function is actually handed. Both parses below run with time frozen: no test in
    // this block may care how busy the machine is.
    const small = withStubbedClock(0, () => mod.parseBash("git status && ls -la | head -3"));
    if (!("tree" in small.value)) throw new Error(`expected a tree, got ${JSON.stringify(small.value)}`);
    const nodes = mod.countTreeNodes(small.value.tree);
    expect(nodes).toBeGreaterThan(10);
    // Independent check of the JS cursor walk against the native count.
    expect(nodes).toBe(small.value.tree.rootNode.descendantCount);

    // Under the cap: the exact total, no early exit, cap inclusive.
    expect(mod.countTreeNodes(small.value.tree, nodes)).toBe(nodes);
    expect(mod.countTreeNodes(small.value.tree, nodes + 1)).toBe(nodes);
    // Over the cap: cap+1, which is all the caller looks at, and it stops walking.
    for (const cap of [1, 7, Math.floor(nodes / 2), nodes - 1]) {
      expect(mod.countTreeNodes(small.value.tree, cap)).toBe(cap + 1);
    }
    small.value.tree.delete();

    // The same on a tree with real bulk: a 4 000-character `a;` chain is the densest
    // construct we measured (2 nodes/char) and holds 8 001 nodes. Parsed with the
    // clock frozen because a 4 000-character parse is only ~10 ms on an idle machine
    // and that is not a fact a test may depend on.
    const dense = withStubbedClock(0, () => mod.parseBash("a;".repeat(2_000)));
    expect(dense.reads).toBeGreaterThan(1); // the frozen clock was consulted, not bypassed
    if (!("tree" in dense.value)) throw new Error(`expected a tree, got ${JSON.stringify(dense.value)}`);
    expect(mod.countTreeNodes(dense.value.tree)).toBe(8_001);
    expect(mod.countTreeNodes(dense.value.tree)).toBe(dense.value.tree.rootNode.descendantCount);
    expect(mod.countTreeNodes(dense.value.tree, 10)).toBe(11);
    expect(mod.countTreeNodes(dense.value.tree)).toBeLessThan(mod.MAX_TREE_NODES);
    dense.value.tree.delete();
  });

  it("cuts a parse off the moment the clock passes the budget", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // 1 000 characters of `a;`: raises ~50 progress callbacks per parse on this
    // grammar, so the deadline is consulted repeatedly, and small enough that the
    // stub — not the machine — decides what happens.
    const command = "a;".repeat(500);

    const out = withStubbedClock(mod.PARSE_TIMEOUT_MS + 1, () => mod.parseBash(command));
    expect(out.value).toMatchObject({
      error: "aborted",
      detail: abortDetail(mod),
    });
    // Consulted at the deadline's setting and then again during the parse, and cut
    // off on that first consultation — the budget is not checked only at entry.
    expect(out.reads).toBeGreaterThan(1);
    // A machine this slow is uniformly slow: the second attempt would meet the same clock, so the
    // retry is not taken and the call stays a single parse. Bounded, by construction: the envelope
    // belongs to the call, so attempts cannot extend it.
    expect(mod.lastParseCost().attempts).toBe(1);
    expect(mod.lastParseCost().stop).toBe("wall-clock");

    // The control: the very same command with time standing still parses fine. So the
    // abort above came from elapsed time and not from the stub mechanism, the input's
    // size, or its shape. It also shows the parser is usable after a cancellation.
    const idle = withStubbedClock(0, () => mod.parseBash(command));
    if (!("tree" in idle.value)) throw new Error(`expected a tree, got ${JSON.stringify(idle.value)}`);
    expect(idle.value.tree.rootNode.type).toBe("program");
    expect(idle.value.tree.rootNode.hasError).toBe(false);
    idle.value.tree.delete();
    expect(idle.reads).toBeGreaterThan(1);
    expect(mod.lastParseCost()).toMatchObject({ attempts: 1, stop: null });

    // And once more on the real clock, after a cancelled parse left the parser
    // mid-document: parseBash must have reset it.
    const after = mod.parseBash("echo ok");
    if (!("tree" in after)) throw new Error(`expected a tree, got ${JSON.stringify(after)}`);
    expect(after.tree.rootNode.hasError).toBe(false);
    after.tree.delete();
  });

  it("does not let a pause decide the verdict of a command it could read", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();
    const command = "a;".repeat(500);

    // The flake, reproduced without racing anything: one 99 ms pause inside an otherwise idle parse of
    // a 1 000-character command. 99 ms is the slowest parse W47 measured for a 322-character golden case
    // under 48-way contention (7.6 ms cold, <1 ms warm), and under a 50 ms single-window budget that
    // pause was an `aborted` verdict — a command whose answer depended on what else the machine was
    // doing. Here it is inside the attempt window, so nothing happens at all.
    const pause = withStutteringClock(3, 99, () => mod.parseBash(command));
    if (!("tree" in pause.value)) {
      throw new Error(`a 99 ms pause changed the verdict: ${JSON.stringify(pause.value)}`);
    }
    expect(pause.value.tree.rootNode.type).toBe("program");
    expect(mod.lastParseCost()).toMatchObject({ attempts: 1, stop: null });
    pause.value.tree.delete();
  });

  it("answers with the retried verdict when a pause does overrun an attempt", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();
    const command = "a;".repeat(500);

    // A pause larger than one attempt's window: the first parse is cancelled, the call retries inside
    // the same envelope, and the answer the caller gets is the second parse's answer — a real tree,
    // asserted rather than hoped for. This is the production-side replacement for the test-only
    // `parseWithEnvironmentRetry` helper in bash-walker-golden.ts, and the reason that helper's one
    // extra attempt now sits on top of a parser that no longer needs it.
    const stall = mod.PARSE_TIMEOUT_MS / mod.PARSE_ATTEMPTS + 50;
    const retry = withStutteringClock(3, stall, () => mod.parseBash(command));
    if (!("tree" in retry.value)) {
      throw new Error(`expected the retry to answer, got ${JSON.stringify(retry.value)}`);
    }
    expect(retry.value.tree.rootNode.hasError).toBe(false);
    expect(retry.value.tree.rootNode.type).toBe("program");
    const cost = mod.lastParseCost();
    expect(cost.attempts).toBe(2);
    expect(cost.stop).toBeNull();
    retry.value.tree.delete();
  });

  it("gives up after the promised number of attempts and fails closed", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // A clock that creeps 1 ms per consultation against a 10 000-character runaway: every attempt is
    // cancelled by its own window, so this is the case where the retry IS taken — and the case that
    // proves it is bounded. Two attempts, no third one, and the answer is the abort, not a tree.
    const window = withStubbedClock(1, () => mod.parseBash(";a".repeat(mod.MAX_COMMAND_CHARS / 2)));
    expect(window.value).toMatchObject({
      error: "aborted",
      detail: abortDetail(mod),
    });
    const cost = mod.lastParseCost();
    expect(cost.attempts).toBe(mod.PARSE_ATTEMPTS);
    expect(cost.stop).toBe("wall-clock");
    // Clock consultations ≈ one per millisecond of the envelope, for the whole call: the attempts share
    // PARSE_TIMEOUT_MS rather than each getting a fresh one. A `while (!tree)` loop that reset the
    // deadline each time would read like this test passing forever.
    expect(window.reads).toBeGreaterThan(mod.PARSE_TIMEOUT_MS / 2);
    expect(window.reads).toBeLessThan(mod.PARSE_TIMEOUT_MS * 2);
  });

  it("reports too-slow separately from cannot-tell, and only retries the first", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // Nothing parsed yet.
    expect(mod.lastParseCost()).toMatchObject({ attempts: 0 });

    // Over the character ceiling: an input-shaped refusal, decided before the parser is touched, so it
    // is the same on every machine and is never retried.
    const tooLarge = mod.parseBash("echo " + "a".repeat(mod.MAX_COMMAND_CHARS));
    expect(tooLarge).toMatchObject({ error: "too-large" });
    expect(mod.lastParseCost()).toMatchObject({ attempts: 0, steps: 0, stop: "input" });

    // A parse that answers: no stop, one attempt, and the step count is a diagnostic (the progress
    // callback is measured NOT to be a unit of work, so no limit is drawn on it).
    const ok = mod.parseBash("git status");
    if ("tree" in ok) ok.tree.delete();
    expect(mod.lastParseCost()).toMatchObject({ attempts: 1, stop: null });

    // An environment abort: distinct from the above, and the only shape that earns a second attempt.
    withStubbedClock(mod.PARSE_TIMEOUT_MS + 1, () => mod.parseBash("a;".repeat(500)));
    expect(mod.lastParseCost()).toMatchObject({ attempts: 1, stop: "wall-clock" });
  });

  it("gives every parse its own deadline", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // One stubbed window, a clock that creeps 1 ms per consultation. The first
    // command is cut off after PARSE_TIMEOUT_MS consultations, so the second starts
    // with the clock already past the first one's deadline. Were the deadline
    // computed once and reused, that second parse would come back `aborted`.
    const window = withStubbedClock(1, () => ({
      runaway: mod.parseBash("a;".repeat(5_000)), // 10 000 chars, ~500 consultations
      next: mod.parseBash("a;".repeat(100)), // ~11 consultations of its own
    }));
    expect(window.value.runaway).toMatchObject({ error: "aborted" });
    expect(window.reads).toBeGreaterThan(mod.PARSE_TIMEOUT_MS);
    if (!("tree" in window.value.next)) {
      throw new Error(
        `the next parse inherited the previous deadline: ${JSON.stringify(window.value.next)}`,
      );
    }
    window.value.next.tree.delete();
  });

  it("trips neither runaway cap on a maximal command while time stands still", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // The largest command the size gate accepts (10 000 chars) built from the densest
    // construct we measured: 20 001 nodes, ~12 ms of work. With time frozen it parses,
    // which pins the relationship the header describes — a command is refused for
    // taking too long, never for being big, because the node ceiling (50 000) is
    // unreachable inside the character ceiling (~2 nodes/char x 10 000 chars). That is
    // also why no test can drive parseBash into MAX_TREE_NODES from a command string:
    // the cap is a backstop, and it is asserted where it is reachable, in
    // countTreeNodes above.
    const out = withStubbedClock(0, () => mod.parseBash("a;".repeat(mod.MAX_COMMAND_CHARS / 2)));
    if (!("tree" in out.value)) throw new Error(`expected a tree, got ${JSON.stringify(out.value)}`);
    const nodes = mod.countTreeNodes(out.value.tree);
    expect(nodes).toBe(20_001);
    expect(nodes).toBeLessThan(mod.MAX_TREE_NODES);
    out.value.tree.delete();
    expect(out.reads).toBeGreaterThan(100); // budget consulted all the way through, never hit
  });

  it("aborts a runaway command on the real clock (smoke test)", async () => {
    const mod = await freshAdapter();
    await mod.initBashParser();

    // No stub in this one: it is the evidence that the shipped budget cuts a real runaway off in
    // production, not just under a fake clock. `;a` x5000 is 10 000 characters of leading separator —
    // the most expensive parse measured at that length, and the measurement is in the module header:
    // 302 progress callbacks for 700 ms of work, which is also why the callback count is not a budget.
    // The margin here is deliberately enormous: the abort needs the parse still running 150 ms in, on
    // an input that needs 700 ms on an idle machine, and real corpus commands cost 0.03 ms.
    const runaway = mod.parseBash(";a".repeat(mod.MAX_COMMAND_CHARS / 2));
    expect(runaway).toMatchObject({
      error: "aborted",
      detail: abortDetail(mod),
    });
    // Both attempts spent their window on it, and the parser stayed usable afterwards.
    expect(mod.lastParseCost().attempts).toBe(mod.PARSE_ATTEMPTS);

    const after = mod.parseBash("echo ok");
    expect("tree" in after).toBe(true);
    if ("tree" in after) {
      expect(after.tree.rootNode.hasError).toBe(false);
      after.tree.delete();
    }
  });
});
