# configs

| File | What it is |
| --- | --- |
| `prices.json` | the price table the budget guard reads. **Dated**; update it, and the date, before committing a budget |
| `prompts.json` | the task prompts, **frozen before the pilot**. Every sentence must be true of every target. The ledger records each prompt's hash |
| `matrix.fake.json` | the whole pipeline on the fake runner. Run with `--fake`. Costs nothing, and is where every change is tried first |
| `matrix.pilot.json` | stage 2: one target, both conditions, one repeat on the workhorse model |
| `matrix.example.json` | the shape of a measurement matrix. Add targets as their manifests are written |

`tokens_per_run` holds **assumptions** until the pilot has run. Replace them
with the pilot's measured medians (from `runs/pilot/ledger.jsonl`) before
estimating the real matrix. That replacement is what turns `estimate` from a
guess into a forecast.

## The harness side

The harness condition pins every stage to the model under test with
`SUPERVISOR_ROUTE_*` environment variables, and gives each cell an empty
`SUPERVISOR_HOME`, so no configuration here is needed for routing. API keys
come from the environment (`ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`), or from
your trusted `~/.supervisor/config.json`. Never put them in a file in this
repository.

If your `~/.supervisor/config.json` routes a specific lens somewhere else, the
harness runner refuses to start and names the route. That is intended: a cell
whose lens ran on a different model would be mislabelled.
