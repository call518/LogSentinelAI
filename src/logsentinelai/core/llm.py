"""
LLM (Large Language Model) interface module
Handles initialization and interaction with different LLM providers
"""
import time
import os
import outlines
import ollama
import openai
from google import genai
from .config import LLM_PROVIDER, LLM_MODELS, LLM_API_HOSTS, LLM_TEMPERATURE, LLM_TOP_P

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
    
    if llm_provider == "ollama":
        client = ollama.Client(
            host=LLM_API_HOSTS["ollama"],
        )
        model = outlines.from_ollama(client, llm_model_name)
    elif llm_provider == "vllm":
        client = openai.OpenAI(
            base_url=LLM_API_HOSTS["vllm"],
            api_key="dummy"
        )
        model = outlines.from_openai(client, llm_model_name)
    elif llm_provider == "openai":
        client = openai.OpenAI(
            base_url=LLM_API_HOSTS["openai"],
            api_key=os.getenv("OPENAI_API_KEY")
        )
        model = outlines.from_openai(client, llm_model_name)
    elif llm_provider == "gemini":
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise ValueError("GEMINI_API_KEY not found in environment variables. Please set it in your config file.")
        client = genai.Client(api_key=api_key)
        model = outlines.from_gemini(client, llm_model_name)
    else:
        raise ValueError("Unsupported LLM provider. Use 'ollama', 'vllm', 'openai', or 'gemini'.")
    
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
    elif provider == "gemini":
        response = model(prompt, max_output_tokens=2048, temperature=LLM_TEMPERATURE)
        
        # Clean up response - remove markdown code blocks if present
        cleaned_response = response.strip()
        
        # Remove markdown code blocks
        if cleaned_response.startswith('```json'):
            cleaned_response = cleaned_response[7:]  # Remove ```json
        elif cleaned_response.startswith('```'):
            cleaned_response = cleaned_response[3:]   # Remove ```
            
        if cleaned_response.endswith('```'):
            cleaned_response = cleaned_response[:-3]  # Remove trailing ```
            
        cleaned_response = cleaned_response.strip()
        
        return cleaned_response
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
