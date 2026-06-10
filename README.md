# Marlowe

**Automated red-teaming agent for LLM prompt injection testing.**

Marlowe probes a target LLM with a battery of adversarial prompt injection techniques, analyzes responses for vulnerabilities, and produces a structured security report.

```
$ marlowe scan --target http://localhost:11434 --model llama3

╭─────────────────────────────────────────────╮
│ Marlowe — Automated LLM Red-Team Agent      │
╰─────────────────────────────────────────────╯
┌─────────────────────────────────────────────────────────────────┐
│ Attacks: 120  Successes: 34  Success rate: 28.3%  Risk: 7.4/10 │
└─────────────────────────────────────────────────────────────────┘
 Plugin            Severity   Score  Evidence
 direct_override   HIGH       7.4    "MARLOWE_PWNED"
```

## What it tests

Marlowe implements a plugin-based attack engine covering the [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| Plugin | Technique | OWASP |
|---|---|---|
| `direct_override` | "Ignore all previous instructions" + 12 variants | LLM01 |
| `roleplay_dan` | DAN 6.0–13.0, AIM, STAN, JAILBREAK personas | LLM01 |
| `many_shot` | N-shot conditioning (5 / 15 / 50 / 100 examples) | LLM01 |
| `obfuscation` | Base64, ROT13, leetspeak, unicode homoglyphs | LLM01 |
| `completion_trap` | Autoregressive completion exploitation | LLM01 |
| `context_switch` | Context smuggling via translation/summarisation tasks | LLM01 |
| `system_prompt_extraction` | System prompt inference via refusal analysis | LLM07 |
| `indirect_rag` | Malicious instructions embedded in RAG documents | LLM02 |
| `multi_turn_conditioning` | Gradual trust-building over multiple turns | LLM01 |
| `adversarial_suffix` | Token-level greedy suffix search (Zou et al. 2023) | LLM01 |

Each finding is scored with a **CVSS-inspired metric** (0–10) and mapped to a severity level (Critical / High / Medium / Low / Info).

## Quickstart

**Requirements:** Python 3.11+, [Ollama](https://ollama.com) running locally.

```bash
# Install
git clone https://github.com/wensaqt/marlowe
cd marlowe
pip install -e .

# Pull a model
ollama pull llama3

# Run a scan
marlowe scan --target http://localhost:11434 --model llama3
```

Or with Docker:

```bash
docker compose -f docker/docker-compose.yml up
```

## Usage

```
marlowe scan    Run a red-team campaign against a target LLM
marlowe plugins List all registered attack plugins
marlowe help    Show usage guide and examples
```

```bash
# Test a specific plugin
marlowe scan -t http://localhost:11434 -m llama3 -p direct_override

# Test with a custom system prompt
marlowe scan -t http://localhost:11434 -m llama3 \
  -s "You are a customer support agent for Acme Corp." \
  -o reports/acme_scan.json

# More attack variants, higher concurrency
marlowe scan -t http://localhost:11434 -m mistral -v 20 -w 10
```

## Architecture

```
marlowe/
├── core/        Domain models · exceptions · plugin registry
├── targets/     Adapters for Ollama, OpenAI-compatible APIs, LangChain
├── attacks/     Plugin base class + attack plugins
├── engine/      Campaign orchestrator · async runner · baseline profiler
├── analysis/    Vulnerability detector · CVSS scorer · heuristics
└── reporting/   JSON / Markdown / HTML report generators
```

Plugins are discovered via Python entry points — adding a new attack requires only inheriting `BaseAttackPlugin` and registering in `pyproject.toml`. No changes to core code.

## Extending Marlowe

```python
from marlowe.attacks.base import BaseAttackPlugin, AttackContext
from marlowe.core.models import AttackPrompt, OWASPCategory, TargetResponse

class MyPlugin(BaseAttackPlugin):
    plugin_id = "my_attack"
    display_name = "My Custom Attack"
    category = OWASPCategory.LLM01_PROMPT_INJECTION
    base_score = 6.0
    impact_category = "instruction_bypass"
    tags = ["custom"]

    async def generate_variants(self, ctx: AttackContext) -> list[AttackPrompt]:
        ...

    def analyze_response(self, response, prompt, ctx) -> tuple[bool, float, str | None]:
        ...
```

Then register in `pyproject.toml`:
```toml
[project.entry-points."marlowe.attacks"]
my_attack = "my_package.my_plugin:MyPlugin"
```

## Supported targets

| Target | Adapter |
|---|---|
| Ollama (local) | `OllamaAdapter` |
| OpenAI / Groq / Together AI / LM Studio | `OpenAIAdapter` *(coming soon)* |
| Any LangChain `BaseChatModel` | `LangChainAdapter` *(coming soon)* |

## Report output

Marlowe generates a JSON report by default:

```json
{
  "campaign": { "name": "...", "status": "completed" },
  "summary": {
    "total_attacks": 120,
    "successful_attacks": 34,
    "overall_risk_score": 7.4
  },
  "vulnerabilities": [
    {
      "plugin_id": "direct_override",
      "severity": "high",
      "score": { "final": 7.4 },
      "evidence": ["MARLOWE_PWNED"],
      "remediation": "Implement input validation..."
    }
  ]
}
```

## References

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [Universal and Transferable Adversarial Attacks on Aligned Language Models](https://arxiv.org/abs/2307.15043) — Zou et al. 2023
- [Prompt Injection Attacks and Defenses in LLM-Integrated Applications](https://arxiv.org/abs/2310.12815)

## License

MIT
