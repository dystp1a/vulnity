import requests
import os
import json

import rag

OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")
LLM_URL         = f"{OLLAMA_BASE_URL}/api/generate"
MODEL           = os.getenv("OLLAMA_MODEL", "deepseek-coder:1.3b")
TIMEOUT         = int(os.getenv("OLLAMA_TIMEOUT", "700"))

# The judge can reuse the same model, or point at a different one via
# JUDGE_MODEL to reduce self-grading bias (a model is more likely to rubber
# -stamp its own output than a second, independent model would be).
JUDGE_MODEL     = os.getenv("JUDGE_MODEL", MODEL)
JUDGE_TIMEOUT   = int(os.getenv("OLLAMA_JUDGE_TIMEOUT", "300"))

# Set DEBUG=1 (docker-compose.yml or shell env) to log RAG retrieval and
# prompt-size info to stdout on every generate_patch()/judge_patch() call —
# lets you confirm RAG is actually feeding context in, without needing to
# run manual test scripts. Off by default since it's noisy on a full scan.
DEBUG = os.getenv("DEBUG", "0") == "1"


def generate_patch(issue: dict, code_context: str = None,
                   judge_feedback: str = None) -> str:
    """
    Generate a patch suggestion for a vulnerability finding using a local LLM.

    Parameters
    ----------
    issue          : normalized finding dict from cvc.prioritize()
    code_context   : optional source code snippet from load_code_context()
                     If provided, prompt is SAST-style (exact fix requested).
                     If None, prompt is DAST-style (mitigation strategy requested).
    judge_feedback : optional reasoning string from a prior judge_patch() call
                     that rejected an earlier attempt. When provided, it's
                     appended to the prompt so the model can correct course
                     on a retry instead of repeating the same mistake.

    Returns
    -------
    str : markdown-formatted patch suggestion from the LLM
          or an error message string if the call fails.
    """

    # source_tools is a list in the normalized schema from cvc.py
    source_tools = issue.get("source_tools", [])
    tool_info    = (", ".join(source_tools)
                    if source_tools else "Unknown Tool")

    name        = issue.get("name",           "Unknown Vulnerability")
    severity    = issue.get("severity",       "Unknown")
    category    = issue.get("category",       "Uncategorized")
    description = issue.get("description",   "No description provided.")
    cve         = issue.get("cve",            "")
    cwe         = issue.get("cwe",            "")
    score       = issue.get("priority_score", "")

    # Include CVE/CWE identifiers if available
    identifier_parts = []
    if cve: identifier_parts.append(f"CVE: {cve}")
    if cwe: identifier_parts.append(f"CWE: {cwe}")
    identifier_line = " | ".join(identifier_parts) if identifier_parts else ""

    # code_context is now actually inserted into the prompt
    if code_context:
        context_section = f"""
The following source code snippet contains the vulnerability \
(>> marks the vulnerable line):

```
{code_context}
```

Please provide:
1. A brief explanation of exactly why this code is vulnerable
2. The corrected version of this code snippet with the fix applied
3. A one-line summary of what changed and why it prevents the vulnerability
"""
    else:
        context_section = """
This vulnerability was discovered dynamically (black-box testing). \
No specific source code file was identified.

Please provide:
1. A brief explanation of this vulnerability class
2. A concrete Node.js/Express code example showing the vulnerable pattern
3. The corrected version of that code example with the fix applied
4. Any additional HTTP headers or configuration changes required
"""

    # ── RAG: pull in relevant reference material (CWE/OWASP guidance) ──────
    # Fails open — if the index isn't built or Ollama's embedding endpoint
    # is unreachable, retrieved is [] and the prompt is unchanged from
    # before this feature existed.
    retrieved = rag.retrieve_context(issue, k=3)
    print(f"RAG retrieved: {retrieved}") 
    if DEBUG:
        if retrieved:
            print(f"[genai][DEBUG] RAG retrieved {len(retrieved)} chunk(s) "
                  f"for '{issue.get('name', 'unknown')}':")
            for r in retrieved:
                print(f"[genai][DEBUG]   - {r['source']} "
                      f"(score={r['score']:.3f}): {r['text'][:80]}...")
        else:
            print(f"[genai][DEBUG] RAG retrieved 0 chunks for "
                  f"'{issue.get('name', 'unknown')}' — index missing, "
                  f"embedding failed, or no match. Prompt will have no "
                  f"reference material.")

    if retrieved:
        reference_lines = "\n\n".join(
            f"[Reference: {r['source']}]\n{r['text']}" for r in retrieved
        )
        reference_section = f"""
Reference material relevant to this vulnerability class (use this to make \
your explanation and fix accurate — do not contradict it):

{reference_lines}
"""
    else:
        reference_section = ""

    # ── Retry guidance from a previous failed judge_patch() verdict ────────
    if judge_feedback:
        feedback_section = f"""
A previous attempt at fixing this same vulnerability was reviewed and \
rejected for the following reason:

"{judge_feedback}"

Address this specific problem in your new answer.
"""
    else:
        feedback_section = ""

    prompt = f"""You are an expert secure coding assistant specializing in \
web application security and vulnerability remediation.

A vulnerability has been detected with the following details:

Name      : {name}
Severity  : {severity}
Category  : {category}
Tools     : {tool_info}
{f"Identifiers: {identifier_line}" if identifier_line else ""}
{f"Risk Score  : {score}" if score else ""}
Description: {description}

{context_section}
{reference_section}
{feedback_section}

IMPORTANT FORMATTING RULES:
- Format your entire response in Markdown
- Use fenced code blocks with language tags e.g. ```javascript
- Do NOT use raw HTML tags anywhere in your response
- Keep your explanation concise — maximum 3 sentences per section
- Focus on the fix, not a general security lecture
"""

    if DEBUG:
        print(f"[genai][DEBUG] Final prompt for '{issue.get('name', 'unknown')}': "
              f"{len(prompt)} chars | reference_section={'yes' if reference_section else 'no'} "
              f"| judge_feedback={'yes' if feedback_section else 'no'} "
              f"| code_context={'yes' if code_context else 'no'}")

    payload = {
        "model" : MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,   # low temperature = more deterministic code fixes
            "num_predict": 1024,  # max tokens in response
        }
    }

    try:
        r = requests.post(LLM_URL, json=payload, timeout=TIMEOUT)
        r.raise_for_status()
        data = r.json()

        if "response" not in data:
            return (f"⚠️ LLM returned unexpected response format.\n"
                    f"Raw response: `{str(data)[:200]}`")

        return data["response"]

    except requests.exceptions.ConnectionError:
        return (f"⚠️ Could not connect to Ollama at `{LLM_URL}`.\n"
                f"Ensure the Ollama service is running and the model "
                f"`{MODEL}` is pulled.")

    except requests.exceptions.Timeout:
        return (f"⚠️ LLM request timed out after {TIMEOUT}s.\n"
                f"The model may still be loading. Try again in a moment.")

    except requests.exceptions.HTTPError as e:
        return (f"⚠️ Ollama API returned HTTP error: {e}\n"
                f"Check that model `{MODEL}` is available: "
                f"`docker exec ollama ollama list`")

    except (KeyError, ValueError) as e:
        return f"⚠️ Failed to parse LLM response: {e}"

    except Exception as e:
        return f"⚠️ Unexpected error during patch generation: {e}"


def check_llm_connection() -> tuple[bool, str]:
    """
    Verify that Ollama is reachable and that the configured model is available.
    Returns:
        (True, message) when ready
        (False, diagnostic message) when unavailable
    """
    tags_url = f"{OLLAMA_BASE_URL}/api/tags"

    try:
        response = requests.get(tags_url, timeout=10)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.ConnectionError:
        return (
            False,
            f"Could not connect to Ollama at {OLLAMA_BASE_URL}.",
        )
    except requests.exceptions.Timeout:
        return (
            False,
            f"Ollama health check timed out at {OLLAMA_BASE_URL}.",
        )
    except (requests.exceptions.HTTPError, ValueError) as e:
        return (
            False,
            f"Failed to query Ollama models from {tags_url}: {e}",
        )

    models = data.get("models", [])
    installed = {
        model.get("name")
        for model in models
        if isinstance(model, dict) and model.get("name")
    }
    if MODEL not in installed:
        available = ", ".join(sorted(installed)) if installed else "none"
        return (
            False,
            f"Configured model '{MODEL}' is not installed. Available models: {available}.",
        )

    return True, f"Ollama reachable at {OLLAMA_BASE_URL} with model '{MODEL}'."


def load_code_context(file: str, line: int,
                      window: int = 10) -> str | None:
    """
    Load a window of source code around a vulnerable line for SAST findings.

    Parameters
    ----------
    file   : absolute or relative path to the source file
    line   : 1-indexed line number of the vulnerability
    window : number of lines above and below to include (default 10)

    Returns
    -------
    str  : annotated code snippet with line numbers, >> marks vulnerable line
    None : if file cannot be read (logged, not raised)
    """
    if not file:
        return None

    if not os.path.exists(file):
        print(f"[genai] WARNING: source file not found: {file}")
        return None

    try:
        with open(file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        if not lines:
            return None

        # Convert to 0-indexed, clamp to file bounds
        line_0 = max(0, int(line) - 1)
        start  = max(0, line_0 - window)
        end    = min(len(lines), line_0 + window + 1)

        # Annotate with line numbers, mark vulnerable line with >>
        snippet_lines = []
        for i in range(start, end):
            lineno = i + 1
            marker = ">>" if i == line_0 else "  "
            snippet_lines.append(
                f"{marker} {lineno:4d} | {lines[i].rstrip()}"
            )

        return "\n".join(snippet_lines)

    except (OSError, ValueError) as e:
        print(f"[genai] WARNING: could not read {file}: {e}")
        return None


# ---------------------------------------------------------------------------
# LLM-as-judge
# ---------------------------------------------------------------------------

_VALID_VERDICTS = {"pass", "fail"}


def judge_patch(issue: dict, patch: str, code_context: str = None) -> dict:
    """
    Have an LLM critique a previously generated patch before it's trusted
    and shown to the user.

    This is a separate call from generate_patch() on purpose: asking the
    same completion to both produce and grade itself in one pass tends to
    just restate confidence rather than actually check the work. A fresh
    call — optionally against a different JUDGE_MODEL — re-reads the patch
    as new input.

    Parameters
    ----------
    issue        : normalized finding dict from cvc.prioritize()
    patch        : the markdown patch text returned by generate_patch()
    code_context : the same code snippet (if any) passed to generate_patch(),
                   so the judge is grading against the same evidence

    Returns
    -------
    dict : {"verdict": "pass" | "fail" | "unverified", "reasoning": str}
           "unverified" means the judge itself couldn't be reached or its
           output couldn't be parsed — callers should treat this as
           "not confirmed", not as a pass.
    """
    name        = issue.get("name", "Unknown Vulnerability")
    severity    = issue.get("severity", "Unknown")
    category    = issue.get("category", "Uncategorized")
    description = issue.get("description", "No description provided.")

    code_section = (
        f"\nOriginal vulnerable code:\n```\n{code_context}\n```\n"
        if code_context else
        "\nNo specific source file was identified (dynamic/black-box finding).\n"
    )

    prompt = f"""You are a strict, skeptical security code reviewer. Your \
job is to check whether a proposed fix actually resolves a reported \
vulnerability. Do not be lenient — if the fix is incomplete, doesn't \
address the root cause, contains syntax errors, or could introduce a new \
problem, mark it as a fail.

Vulnerability being fixed:
Name       : {name}
Severity   : {severity}
Category   : {category}
Description: {description}
{code_section}
Proposed fix to review:
{patch}

Evaluate the proposed fix against these criteria:
1. Does it correctly address the specific vulnerability described above
   (not just vulnerabilities of this class in general)?
2. Is the code syntactically plausible for the stated language/framework?
3. Does it avoid introducing an obvious new problem (e.g. breaking
   functionality, a different vulnerability class, or a placeholder that
   doesn't actually compile)?

Respond with ONLY a single JSON object and nothing else — no markdown code \
fences, no preamble, no explanation outside the JSON. Use exactly this \
shape:
{{"verdict": "pass", "reasoning": "one or two sentence justification"}}
or
{{"verdict": "fail", "reasoning": "one or two sentence justification"}}
"""

    if DEBUG:
        print(f"[genai][DEBUG] Sending judge request for "
              f"'{issue.get('name', 'unknown')}' to model '{JUDGE_MODEL}' "
              f"({len(prompt)} char prompt)...")

    payload = {
        "model": JUDGE_MODEL,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,   # judging should be as deterministic as possible
            "num_predict": 256,
        },
    }

    try:
        r = requests.post(LLM_URL, json=payload, timeout=JUDGE_TIMEOUT)
        r.raise_for_status()
        data = r.json()
    except requests.exceptions.ConnectionError:
        return {
            "verdict": "unverified",
            "reasoning": f"Could not connect to Ollama at {LLM_URL} to run the judge.",
        }
    except requests.exceptions.Timeout:
        return {
            "verdict": "unverified",
            "reasoning": f"Judge request timed out after {JUDGE_TIMEOUT}s.",
        }
    except Exception as e:
        return {
            "verdict": "unverified",
            "reasoning": f"Unexpected error during judging: {e}",
        }

    raw = data.get("response", "")
    parsed = _parse_judge_response(raw)

    if DEBUG:
        print(f"[genai][DEBUG] Judge verdict for '{issue.get('name', 'unknown')}': "
              f"{parsed['verdict']} — {parsed['reasoning']}")
    print(f"Judge verdict: {parsed}")
    return parsed


def _parse_judge_response(raw: str) -> dict:
    """
    Parse the judge's JSON response defensively — small/local models
    sometimes wrap JSON in code fences or add stray text despite
    instructions, so this strips common wrappers before parsing.
    """
    text = raw.strip()

    # Strip ```json ... ``` or ``` ... ``` fences if the model added them
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()

    # If there's leading/trailing prose, try to isolate the {...} block
    if not text.startswith("{"):
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            text = text[start:end + 1]

    try:
        parsed = json.loads(text)
        verdict = str(parsed.get("verdict", "")).strip().lower()
        reasoning = str(parsed.get("reasoning", "")).strip()

        if verdict not in _VALID_VERDICTS:
            return {
                "verdict": "unverified",
                "reasoning": f"Judge returned an unrecognized verdict: '{verdict}'.",
            }
        return {"verdict": verdict, "reasoning": reasoning or "(no reasoning provided)"}

    except (json.JSONDecodeError, AttributeError) as e:
        return {
            "verdict": "unverified",
            "reasoning": f"Could not parse judge response as JSON: {e}. Raw: {raw[:200]}",
        }