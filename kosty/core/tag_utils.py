"""Tag utilities for resource filtering"""

from typing import List, Dict, Any, Optional


def should_exclude_resource_by_tags(resource: Dict[str, Any], config_manager) -> bool:
    """Check if resource should be excluded based on tags
    
    Args:
        resource: Resource dict that may contain 'Tags' or 'tags' field
        config_manager: ConfigManager instance
    
    Returns:
        True if resource should be excluded, False otherwise
    """
    if not config_manager:
        return False
    
    tags = resource.get('Tags') or resource.get('tags') or []
    
    if not tags:
        return False
    
    return config_manager.should_exclude_by_tags(tags)


def get_resource_tags(resource: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract tags from resource in various formats"""
    return resource.get('Tags') or resource.get('tags') or resource.get('TagList') or []
