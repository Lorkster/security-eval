# configs

| File | What it is |
| --- | --- |
| `prices.json` | the price table the budget guard reads. **Dated**; update it, and the date, before committing a budget |
| `prompts.json` | the task prompts, **frozen before the pilot**. Every sentence must be true of every target. The ledger records each prompt's hash |
| `matrix.fake.json` | the whole pipeline on the fake runner. Run with `--fake`. Costs nothing, and is where every change is tried first |
| `matrix.pilot.json` | stage 2: `notes-api`, both conditions, one repeat on the workhorse model at an explicit effort |
| `matrix.example.json` | the shape of a measurement matrix. Add targets as their manifests are written |

`tokens_per_run` holds **assumptions** until the pilot has run. Replace them
with the pilot's measured medians, which `security-eval report runs/pilot`
prints ready to paste, before estimating the real matrix. That replacement is what turns `estimate` from a
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

## Optional matrix fields

| Field | Meaning |
| --- | --- |
| `prompts` | prompt names from `prompts.json` to run, each as its own cells (default `["plain"]`) |
| `prompts_file` | another frozen prompts file |
| `efforts` | effort levels (`low` … `max`) to run, each as its own cells; only models that take one (current Claude models via `anthropic` or `bedrock`) are affected. Set it explicitly: Opus 5.5 and Sonnet 5.5 have different defaults |
