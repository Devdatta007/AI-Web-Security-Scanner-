import os
import time
from openai import OpenAI
from openai import APITimeoutError, APIStatusError
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def generate_ai_report(scan_summary, log_callback=None):
    api_key = os.environ.get("NVIDIA_API_KEY")
    if not api_key:
        print("❌ Error: NVIDIA API key is missing.")
        return {"status": "error", "message": "NVIDIA API key for Mistral/NIM is missing on the server."}
    
    # Configuration
    RETRY_COUNT = 2
    MODELS = [
        "mistralai/mistral-large-3-675b-instruct-2512", # Primary flagship model
        "meta/llama-3.1-70b-instruct" # Fast, reliable fallback
    ]
    
    client = OpenAI(
        base_url="https://integrate.api.nvidia.com/v1",
        api_key=api_key
    )

    # Optimized Prompt
    prompt = f"""You are a Senior Cybersecurity Auditor. Analyze these scan results:
{scan_summary}

Structure your report with these exact sections:

## 🛡️ EXECUTIVE SUMMARY
Brief overview of the target's security posture.

## 📊 VULNERABILITY ANALYSIS TABLE
A markdown table with exactly these 6 columns:
| VULNERABILITY | SEVERITY | CWE | IMPACT | RESOLUTION | CVSS V3.1 |

- VULNERABILITY: name of the finding
- SEVERITY: one of [CRITICAL], [HIGH], [MEDIUM], [LOW]
- CWE: relevant CWE identifier (e.g. CWE-79)
- IMPACT: what an attacker can do if exploited (1-2 sentences)
- RESOLUTION: specific actionable fix for this exact vulnerability (1-2 sentences)
- CVSS V3.1: numeric score (e.g. 9.1)

## 🔍 TECHNICAL DEEP DIVE
Detailed analysis of the most critical findings.

## 🛠️ STRATEGIC RESOLUTION PLAN
Prioritized resolution steps.

Use severity badges: [CRITICAL], [HIGH], [MEDIUM], [LOW].
Limit to 1200 words."""

    for attempt in range(RETRY_COUNT + 1):
        try:
            current_model = MODELS[0] if attempt == 0 else MODELS[1]
            use_thinking = True if "deepseek" in current_model and attempt == 0 else False
            
            print(f"[INFO] Attempt {attempt + 1}: Using {current_model} (Thinking: {use_thinking})...")
            
            # Request
            response = client.chat.completions.create(
                model=current_model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7 if not use_thinking else 1.0,
                top_p=0.9,
                max_tokens=4096,
                extra_body={"chat_template_kwargs": {"thinking": use_thinking}} if use_thinking else {},
                stream=True,
                timeout=300.0 # 5 Minute Timeout
            )

            full_report = ""
            reasoning_text = ""
            chunk_buffer = ""
            
            for chunk in response:
                if not chunk.choices: continue
                delta = chunk.choices[0].delta
                
                # Extract reasoning
                if hasattr(delta, "reasoning_content") and delta.reasoning_content:
                    reasoning_text += delta.reasoning_content
                
                # Extract content
                if delta.content:
                    token = delta.content
                    full_report += token
                    chunk_buffer += token
                    
                    # Stream chunks to terminal (every few words/chars to keep it fluid)
                    if log_callback and (len(chunk_buffer) > 20 or "\n" in chunk_buffer):
                        log_callback(chunk_buffer)
                        chunk_buffer = ""

            # Flush remaining buffer
            if log_callback and chunk_buffer:
                log_callback(chunk_buffer)

            if full_report:
                print(f"\n[SUCCESS] Report generated with {current_model}.")
                result_display = full_report
                if reasoning_text:
                    result_display = f"### 💡 AI Reasoning Process\n\n> {reasoning_text}\n\n---\n\n{full_report}"
                return {"status": "success", "report": result_display}

        except (APITimeoutError, APIStatusError) as e:
            print(f"\n[WARNING] Attempt {attempt + 1} failed: {str(e)}")
            if attempt < RETRY_COUNT:
                print(f"[INFO] Retrying with model switch...")
                time.sleep(2) # Brief pause before retry
                continue
            else:
                return {"status": "error", "message": f"NVIDIA API persistently timed out. Please check your network or try a smaller scan target."}
        except Exception as e:
            print(f"\n[ERROR] Unexpected API Failure: {str(e)}")
            return {"status": "error", "message": f"Security intelligence synthesis failed: {str(e)}"}

    return {"status": "error", "message": "Unknown error during intelligence synthesis."}
