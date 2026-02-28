"""
LLM (Large Language Model) interface module
Handles initialization and interaction with different LLM providers
"""
import json
import time
import os
import anthropic
import outlines
import openai
from google import genai

from .config import LLM_PROVIDER, LLM_MODELS, LLM_API_HOSTS, LLM_TEMPERATURE, LLM_TOP_P, LLM_MAX_TOKENS
from .commons import setup_logger

logger = setup_logger("logsentinelai.llm")

def initialize_llm_model(llm_provider=None, llm_model_name=None):
    """
    Initialize LLM model

    Args:
        llm_provider: Choose from "ollama", "vllm", "openai", "gemini", "anthropic"
                      (default: use global LLM_PROVIDER)
        llm_model_name: Specific model name (default: use model from LLM_MODELS)

    Returns:
        initialized model object
    """
    # Use global configuration if not specified
    if llm_provider is None:
        llm_provider = LLM_PROVIDER
    if llm_model_name is None:
        llm_model_name = LLM_MODELS.get(llm_provider, "unknown")

    logger.info(f"Initializing LLM model: provider={llm_provider}, model={llm_model_name}")

    try:
        if llm_provider == "ollama":
            logger.debug("Creating Ollama client and model.")
            client = openai.OpenAI(
                base_url=LLM_API_HOSTS["ollama"],
                api_key="dummy"
            )
            model = outlines.from_openai(client, llm_model_name)
        elif llm_provider == "vllm":
            logger.debug("Creating vLLM client and model.")
            client = openai.OpenAI(
                base_url=LLM_API_HOSTS["vllm"],
                api_key="dummy"
            )
            model = outlines.from_openai(client, llm_model_name)
        elif llm_provider == "openai":
            logger.debug("Creating OpenAI client and model.")
            client = openai.OpenAI(
                base_url=LLM_API_HOSTS["openai"],
                api_key=os.getenv("OPENAI_API_KEY")
            )
            model = outlines.from_openai(client, llm_model_name)
        elif llm_provider == "gemini":
            logger.debug("Creating Gemini client and model.")
            client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
            model = outlines.from_gemini(client, llm_model_name)
        elif llm_provider == "anthropic":
            logger.debug("Creating Anthropic client.")
            # outlines.from_anthropic() does not support structured output.
            # Return the Anthropic client directly; generate_with_model() handles
            # structured output via tool calling.
            model = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        else:
            logger.error(f"Unsupported LLM provider: {llm_provider}")
            raise ValueError(
                "Unsupported LLM provider. Use 'ollama', 'vllm', 'openai', 'gemini', or 'anthropic'."
            )
        logger.info(f"LLM model initialized: provider={llm_provider}, model={llm_model_name}")
        return model
    except Exception as e:
        logger.exception(f"Failed to initialize LLM model: {e}")
        raise


def _generate_anthropic(client: anthropic.Anthropic, prompt: str, model_class, model_name: str, max_tokens: int) -> str:
    """
    Generate structured JSON output via Anthropic assistant prefill.

    Anthropic does not support outlines structured output natively.
    Tool calling was attempted but causes XML syntax contamination in last fields
    for claude-haiku models. Instead, we use assistant prefill: injecting
    '{"role": "assistant", "content": "{"}' forces the model to continue
    from '{' and output pure JSON without XML markup.

    Args:
        client: Anthropic client instance
        prompt: Input prompt
        model_class: Pydantic model class whose schema defines the output shape
        model_name: Anthropic model ID to use
        max_tokens: Maximum tokens for the response

    Returns:
        JSON string matching model_class schema
    """
    schema = model_class.model_json_schema()

    # Anthropic does not allow temperature and top_p to be set simultaneously.
    # Use temperature only (top_p is ignored for this provider).
    # Assistant prefill with '{' forces the model to output pure JSON from the start,
    # preventing XML tool-call syntax (<parameter>...</parameter>) contamination.
    response = client.messages.create(
        model=model_name,
        max_tokens=max_tokens,
        temperature=LLM_TEMPERATURE,
        system=(
            "You are a log analysis expert. "
            "Output a single valid JSON object that strictly conforms to this schema:\n"
            f"{json.dumps(schema)}\n"
            "Rules: populate every required field, output pure JSON only, "
            "no XML tags, no markdown, no extra text."
        ),
        messages=[
            {"role": "user", "content": prompt},
            {"role": "assistant", "content": "{"},
        ],
    )

    for block in response.content:
        if block.type == "text":
            return "{" + block.text

    raise ValueError("Anthropic response contained no text block")


def generate_with_model(model, prompt, model_class, llm_provider=None):
    """
    Generate response using LLM model with appropriate parameters

    Args:
        model: LLM model object (outlines model or anthropic.Anthropic client)
        prompt: Input prompt
        model_class: Pydantic model class for structured output
        llm_provider: LLM provider name (for parameter handling)

    Returns:
        Generated response as JSON string
    """
    provider = llm_provider or LLM_PROVIDER
    # 파일 로깅만: 콘솔 출력(print)은 그대로 유지
    logger.info(f"Generating response with provider={provider}")
    logger.debug(f"Prompt: {prompt}")

    max_tokens = LLM_MAX_TOKENS.get(provider, 8192)

    # Anthropic uses tool calling (not outlines); handled separately.
    if provider == "anthropic":
        model_name = LLM_MODELS.get(provider, "claude-haiku-4-5-20251001")
        try:
            response = _generate_anthropic(model, prompt, model_class, model_name, max_tokens)
            logger.debug(f"Raw response: {response}")
            logger.info("Response generated and cleaned.")
            return response
        except Exception as e:
            print(f"❌ [LLM ERROR] Error during response generation: {e}")
            logger.exception(f"Error during response generation: {e}")
            raise

    # Each provider has its own max token limit (LLM_MAX_TOKENS is a per-provider dict).
    # Gemini uses max_output_tokens; all other providers use max_tokens.
    if provider == "gemini":
        generate_kwargs: dict = {"temperature": LLM_TEMPERATURE, "top_p": LLM_TOP_P, "max_output_tokens": max_tokens}
    else:
        generate_kwargs = {"temperature": LLM_TEMPERATURE, "top_p": LLM_TOP_P, "max_tokens": max_tokens}

    try:
        response = model(prompt, model_class, **generate_kwargs)
        logger.debug(f"Raw response: {response}")
        cleaned_response = response.strip()
        logger.info("Response generated and cleaned.")
        return cleaned_response
    except Exception as e:
        print(f"❌ [LLM ERROR] Error during response generation: {e}")
        logger.exception(f"Error during response generation: {e}")
        raise


def wait_on_failure(delay_seconds=30):
    """
    Wait for specified seconds when analysis fails to prevent rapid failed requests

    Args:
        delay_seconds: Number of seconds to wait (default: 30)
    """
    print(f"⏳ Waiting {delay_seconds} seconds before processing next chunk...")
    logger.warning(f"Waiting {delay_seconds} seconds before processing next chunk due to failure...")
    time.sleep(delay_seconds)
    print("Wait completed, continuing with next chunk.")
    logger.info("Wait completed, continuing with next chunk.")
