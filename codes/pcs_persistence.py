"""Data persistence layer for PCS.

This module handles saving and loading data to/from JSON files,
ensuring that users, blockchain, and profiles persist across restarts.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Dict


BASE_DIR = pathlib.Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent
DATA_DIR = PROJECT_ROOT / "data"


def ensure_data_directory() -> pathlib.Path:
    """Create the data directory if it doesn't exist."""
    DATA_DIR.mkdir(exist_ok=True)
    return DATA_DIR


def save_json(filename: str, data: Any) -> None:
    """Save data to a JSON file in the data directory.
    
    Parameters
    ----------
    filename : str
        Name of the file (without path).
    data : Any
        Data to serialize to JSON.
    """
    ensure_data_directory()
    filepath = DATA_DIR / filename
    
    # Write to a temporary file first, then rename (atomic operation)
    temp_filepath = filepath.with_suffix('.tmp')
    with temp_filepath.open('w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    
    # Atomic rename
    temp_filepath.replace(filepath)


def load_json(filename: str, default: Any = None) -> Any:
    """Load data from a JSON file in the data directory.
    
    Parameters
    ----------
    filename : str
        Name of the file (without path).
    default : Any
        Default value to return if file doesn't exist.
    
    Returns
    -------
    Any
        Loaded data or default value.
    """
    filepath = DATA_DIR / filename
    
    if not filepath.exists():
        return default
    
    try:
        with filepath.open('r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError):
        # If file is corrupted, return default
        return default


def save_users(users_dict: Dict[str, Any], username_index: Dict[str, str]) -> None:
    """Save user data to disk."""
    data = {
        'users': users_dict,
        'username_index': username_index,
    }
    save_json('users.json', data)


def load_users() -> tuple[Dict[str, Any], Dict[str, str]]:
    """Load user data from disk."""
    data = load_json('users.json', {'users': {}, 'username_index': {}})
    return data.get('users', {}), data.get('username_index', {})


def save_blockchain(blockchain_data: list) -> None:
    """Save blockchain data to disk."""
    save_json('blockchain.json', blockchain_data)


def load_blockchain() -> list:
    """Load blockchain data from disk."""
    return load_json('blockchain.json', [])


def save_profiles(profiles_dict: Dict[str, Any]) -> None:
    """Save profiles data to disk."""
    save_json('profiles.json', profiles_dict)


def load_profiles() -> Dict[str, Any]:
    """Load profiles data from disk."""
    return load_json('profiles.json', {})
