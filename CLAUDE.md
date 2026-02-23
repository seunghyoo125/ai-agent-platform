# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`ai-agent-platform` is a Python-based AI evaluation platform that runs test cases against AI model generators, scores outputs using rubrics, and compares runs for regression detection.

## Commands

**Run Evaluation:**
```bash
python -m src.eval_runner --golden examples/golden_set_sample.jsonl --out output/run_a.json --run-name "baseline"
python -m src.eval_runner --golden examples/golden_set_sample.jsonl --out output/run_b.json --variant noisy
```

**Generate Regression Report:**
```bash
python -m src.regression --a output/run_a.json --b output/run_b.json --out output/regression_report.json
```

**Launch UI:**
```bash
streamlit run app/streamlit_app.py
```

**Install Dependencies:**
```bash
pip install -r requirements.txt
```

## Architecture

The platform follows a pipeline architecture:

1. **Golden Set (JSONL)** → Test cases with prompts, expected outputs, and metadata tags
2. **Evaluation Runner** (`src/eval_runner.py`) → Generates responses via generator stub, scores with rubric
3. **Run Artifact (JSON)** → Stores all results with summary statistics
4. **Regression Analysis** (`src/regression.py`) → Compares two runs, identifies improvements/regressions
5. **Streamlit UI** (`app/streamlit_app.py`) → Interactive visualization and comparison

### Core Modules

- `src/types.py` - Dataclass models: `GoldenCase`, `RubricScores`, `CaseResult`, `Tags`
- `src/rubric.py` - Scoring logic with `score_case()` (yes/partial/no per dimension) and `overall_label()` (pass/mixed/fail)
- `src/generator_stub.py` - Deterministic test generator; `variant="noisy"` degrades outputs for regression testing
- `src/artifacts.py` - JSON I/O and summary statistics helpers
- `src/taxonomy.py` - Tag flattening utilities

### Scoring System

Three rubric dimensions scored as yes/partial/no:
- `answer_correct` - Does generated answer match expected?
- `sources_correct` - Are sources cited appropriately?
- `response_appropriate` - Is response appropriate/safe?

Overall label derivation:
- "pass" - All scores are "yes"
- "fail" - Any score is "no"
- "mixed" - Intermediate result

### Data Formats

Golden set entries have structured tags: `capability` (math/fact/support/safety/summarization), `difficulty` (easy/medium/hard), `test_type` (functional/behavioral), and `behavior` (list of behaviors).

Run artifacts include `summary` with `pass_rate_strict` (all pass) and `pass_rate_lenient` (no fails).
