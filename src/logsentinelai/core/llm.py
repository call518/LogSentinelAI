"""
LLM (Large Language Model) interface module
Handles initialization and interaction with different LLM providers
"""
import time
import os
import outlines
import ollama
import openai
import json
from pydantic import ValidationError
from google import genai

from .config import LLM_PROVIDER, LLM_MODELS, LLM_API_HOSTS, LLM_TEMPERATURE, LLM_TOP_P, LLM_MAX_TOKENS
from .commons import setup_logger
import logging

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
            client = openai.OpenAI(
                base_url=LLM_API_HOSTS["gemini"],
                api_key=os.getenv("GEMINI_API_KEY")
            )
            model = outlines.from_openai(client, llm_model_name)
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
    
    if provider == "gemini":
        # Gemini API에서 additionalProperties is not supported 오류가 발생하는 이유는 outlines 라이브러리의 Gemini 구현에서 Pydantic 모델의 스키마 변환 과정에서 문제가 있기 때문.
        # outlines 문서에서는 Gemini가 구조화된 출력을 지원한다고 하지만, 실제로는 다음과 같은 제한사항이 있음:
        # - Gemini API 제한: Google의 Gemini API는 OpenAI처럼 완전한 JSON Schema를 지원하지 않음.
        # - outlines 라이브러리 구현: Gemini용 outlines 구현이 아직 완전하지 않을 수 있음.
        # - 스키마 변환 문제: Pydantic 모델을 Gemini가 이해할 수 있는 형태로 변환하는 과정에서 additionalProperties 같은 속성이 지원되지 않음.
        # 현재 코드에서 Gemini는 model_class 없이 raw 텍스트를 반환하고, 프롬프트 엔지니어링을 통해 JSON 형태로 응답을 받고, 이를 Pydantic 모델로 검증하는 방식으로 동작함. (아래 try문 참조)
        try:
            response = model(prompt, temperature=LLM_TEMPERATURE, top_p=LLM_TOP_P, max_tokens=LLM_MAX_TOKENS)
            logger.debug(f"Raw Gemini response: {response}")
            cleaned_response = response.strip()
            # Remove markdown code blocks
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            elif cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()
            logger.debug(f"Cleaned Gemini response: {cleaned_response}")
            # Validate Gemini response with Pydantic model (Using model_class)
            parsed_json = json.loads(cleaned_response)
            validated_data = model_class.model_validate(parsed_json)
            logger.info("Gemini response validated successfully.")
            return validated_data.model_dump_json()
        except json.JSONDecodeError as e:
            print(f"\n❌ [GEMINI JSON ERROR] Invalid JSON format in response")
            print(f"Error: {e}")
            print(f"Raw response:\n{cleaned_response}")
            logger.error(f"[GEMINI JSON ERROR] Invalid JSON format in response: {e}")
            logger.debug(f"Raw response: {cleaned_response}")
            raise ValueError(f"❌ [GEMINI JSON ERROR] Invalid JSON format in response: {e}")
        except ValidationError as e:
            print(f"\n❌ [GEMINI SCHEMA ERROR] Response doesn't match required schema")
            print(f"Error: {e}")
            print(f"Raw response:\n{cleaned_response}")
            logger.error(f"[GEMINI SCHEMA ERROR] Response doesn't match required schema: {e}")
            logger.debug(f"Raw response: {cleaned_response}")
            raise ValueError(f"❌ [GEMINI SCHEMA ERROR] Response doesn't match required schema: {e}")
    else:
        # For Ollama, vLLM, OpenAI
        try:
            response = model(prompt, model_class, temperature=LLM_TEMPERATURE, top_p=LLM_TOP_P, max_tokens=LLM_MAX_TOKENS)
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
