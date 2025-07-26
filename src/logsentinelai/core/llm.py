"""
LLM (Large Language Model) interface module
Handles initialization and interaction with different LLM providers
"""
import time
import outlines
import ollama
import openai
from .config import LLM_PROVIDER, LLM_MODELS, LLM_TEMPERATURE, LLM_TOP_P

def initialize_llm_model(llm_provider=None, llm_model_name=None):
    """
    Initialize LLM model
    
    Args:
        llm_provider: Choose from "ollama", "vllm", "openai" (default: use global LLM_PROVIDER)
        llm_model_name: Specific model name (default: use model from LLM_MODELS)
    
    Returns:
        initialized model object
    """
    # Use global configuration if not specified
    if llm_provider is None:
        llm_provider = LLM_PROVIDER
    if llm_model_name is None:
        llm_model_name = LLM_MODELS.get(llm_provider, "unknown")
    
    if llm_provider == "ollama":
        client = ollama.Client()
        model = outlines.from_ollama(client, llm_model_name)
    elif llm_provider == "vllm":
        client = openai.OpenAI(
            base_url="http://127.0.0.1:5000/v1",
            api_key="dummy"
        )
        model = outlines.from_openai(client, llm_model_name)
    elif llm_provider == "openai":
        import os
        client = openai.OpenAI(
            base_url="https://api.openai.com/v1",
            api_key=os.getenv("OPENAI_API_KEY")
        )
        model = outlines.from_openai(client, llm_model_name)
    else:
        raise ValueError("Unsupported LLM provider. Use 'ollama', 'vllm', or 'openai'.")
    
    return model

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
    
    if provider == "ollama":
        # Ollama doesn't support temperature and top_p in outlines
        return model(prompt, model_class)
    else:
        # OpenAI and vLLM support temperature and top_p
        return model(prompt, model_class, temperature=LLM_TEMPERATURE, top_p=LLM_TOP_P)

def wait_on_failure(delay_seconds=30):
    """
    Wait for specified seconds when analysis fails to prevent rapid failed requests
    
    Args:
        delay_seconds: Number of seconds to wait (default: 30)
    """
    print(f"⏳ Waiting {delay_seconds} seconds before processing next chunk...")
    time.sleep(delay_seconds)
    print("Wait completed, continuing with next chunk.")
