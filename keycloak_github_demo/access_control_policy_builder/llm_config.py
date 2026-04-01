"""
LLM Configuration Module

This module provides a global LLM instance configured for the document generation system.
The LLM is initialized once and can be imported by other modules.

Configuration is read from llm_config.yaml.
RITS_API_KEY is read from environment variables (.env file).
"""

import os
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

import yaml
from dotenv import load_dotenv
from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI
from pydantic import SecretStr


@dataclass
class LLMConfig:
    """Configuration for LLM."""
    model: str
    endpoint: str
    temperature: float
    max_tokens: int
    timeout: int
    retries: int


def load_llm_config(
    config_path: Optional[Path] = None,
    section: str = "llm",
    legacy_section: Optional[str] = None
) -> LLMConfig:
    """
    Load LLM configuration from YAML file.
    
    Config file path can be specified via LLM_CONFIG_FILE environment variable.
    
    Args:
        config_path: Path to configuration YAML file (optional, reads from LLM_CONFIG_FILE env var if not provided)
        section: Primary section to read from (e.g., "docgen.llm")
        legacy_section: Fallback section if primary not found
    
    Returns:
        LLMConfig: Configuration object
        
    Raises:
        FileNotFoundError: If configuration file doesn't exist
        ValueError: If required configuration is missing
    """
    # Get config path from environment variable if not provided
    if config_path is None:
        load_dotenv(override=True)
        config_file_env = os.getenv("LLM_CONFIG_FILE", "llm_config.yaml")
        config_path = Path(config_file_env)
    
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_path, 'r') as f:
        config_data = yaml.safe_load(f)
    
    # Try to get config from nested section (e.g., "docgen.llm")
    llm_config_data = config_data
    if '.' in section:
        for key in section.split('.'):
            llm_config_data = llm_config_data.get(key, {})
    else:
        llm_config_data = config_data.get(section, {})
    
    # Fallback to legacy section if primary section is empty
    if not llm_config_data and legacy_section:
        llm_config_data = config_data.get(legacy_section, {})
    
    if not llm_config_data:
        raise ValueError(f"No LLM configuration found in {config_path} under section '{section}'")
    
    # Extract configuration values with defaults matching llm_config.yaml
    return LLMConfig(
        model=llm_config_data.get('model', 'openai/gpt-oss-120b'),
        endpoint=llm_config_data.get('endpoint', 'https://inference-3scale-apicast-production.apps.rits.fmaas.res.ibm.com/gpt-oss-120b/v1'),
        temperature=llm_config_data.get('temperature', 0.0),
        max_tokens=llm_config_data.get('max_tokens', 8192),
        timeout=llm_config_data.get('timeout', 360),
        retries=llm_config_data.get('max_retries', 2)
    )

def create_llm(config_path: Optional[Path] = None) -> BaseChatModel:
    """
    Create and configure a LangChain LLM instance from configuration file.
    
    Reads LLM configuration from YAML file under llm section.
    RITS_API_KEY is read from environment variables.
    Config file path can be specified via LLM_CONFIG_FILE environment variable.
    
    Args:
        config_path: Path to configuration YAML file (optional, overrides env var)
    
    Returns:
        BaseChatModel: Configured LangChain LLM instance
        
    Raises:
        ValueError: If required configuration or API key is missing
        FileNotFoundError: If configuration file doesn't exist
    """
    # Load environment variables for API key and config path
    load_dotenv(override=True)
    
    # Get config path from environment variable if not provided
    if config_path is None:
        config_file_env = os.getenv("LLM_CONFIG_FILE", "llm_config.yaml")
        config_path = Path(config_file_env)
    
    # Get API key from environment
    api_key = os.getenv("RITS_API_KEY")
    if api_key is None:
        raise ValueError("RITS_API_KEY environment variable is not set")
    
    # Load LLM configuration from YAML
    llm_config = load_llm_config(
        config_path=config_path,
        section="docgen.llm",
        legacy_section="llm"  # Fallback to legacy section
    )
    
    print(f"🤖 Initializing LLM")
    print(f"   Model: {llm_config.model}")
    print(f"   Endpoint: {llm_config.endpoint}")
    print(f"   Temperature: {llm_config.temperature}")
    print(f"   Max Tokens: {llm_config.max_tokens}")
    print(f"   Timeout: {llm_config.timeout}s")
    print(f"   Max Retries: {llm_config.retries}")
    
    # Create ChatOpenAI instance with RITS configuration
    llm = ChatOpenAI(
        model=llm_config.model,
        temperature=llm_config.temperature,
        max_retries=llm_config.retries,
        timeout=llm_config.timeout,
        api_key=SecretStr("none"),  # Not used, RITS uses header
        base_url=llm_config.endpoint,
        default_headers={'RITS_API_KEY': api_key},
        model_kwargs={"max_tokens": llm_config.max_tokens},
    )
    
    print(f"✅ LLM initialized successfully")
    return llm


# Create global LLM instance
llm = create_llm()

# Made with Bob
