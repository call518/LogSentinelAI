"""
LLM (Large Language Model) interface module
Handles initialization and interaction with different LLM providers
"""
import time
import os
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
        llm_provider: Choose from "ollama", "vllm", "openai", "gemini" (default: use global LLM_PROVIDER)
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
        else:
            logger.error(f"Unsupported LLM provider: {llm_provider}")
            raise ValueError("Unsupported LLM provider. Use 'ollama', 'vllm', 'openai', or 'gemini'.")
        logger.info(f"LLM model initialized: provider={llm_provider}, model={llm_model_name}")
        return model
    except Exception as e:
        logger.exception(f"Failed to initialize LLM model: {e}")
        raise

def generate_with_model(model, prompt, model_class, llm_provider=None):
    """
    Generate response using LLM model with appropriate parameters
    
    Args:
        model: LLM model object
        prompt: Input prompt
        model_class: Pydantic model class for structured output
        llm_provider: LLM provider name (for parameter handling)
    
    Returns:
        Generated response
    """
    provider = llm_provider or LLM_PROVIDER
    # 파일 로깅만: 콘솔 출력(print)은 그대로 유지
    logger.info(f"Generating response with provider={provider}")
    logger.debug(f"Prompt: {prompt}")
    
    # Each provider has its own max token limit (LLM_MAX_TOKENS is a per-provider dict).
    # Gemini uses max_output_tokens; all other providers use max_tokens.
    max_tokens = LLM_MAX_TOKENS.get(provider, 8192)
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
